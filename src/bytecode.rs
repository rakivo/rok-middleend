use crate::{Function, Value, Block, Inst, Opcode as IrOpcode};
use hashbrown::HashMap;

//-////////////////////////////////////////////////////////////////////
// Bytecode Data Structures
//

/// Opcodes for the VM.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    // Constants
    IConst8, IConst16, IConst32, IConst64,

    // Arithmetic
    Add, Sub, Mul, Lt,

    // Control Flow
    Jump16, Jump32,
    BranchIf16, BranchIf32,

    // Functions
    Call, Return,

    // Memory
    Load8, Load16, Load32, Load64,
    Store8, Store16, Store32, Store64,

    // Stack
    Mov, // Move value from one stack slot to another
}

/// A chunk of bytecode for a single function.
#[derive(Debug, Clone, Default)]
pub struct BytecodeChunk {
    pub code: Vec<u8>,
    pub constants: Vec<u64>,
}

/// Represents a function that has been lowered to bytecode.
pub struct LoweredFunction<'a> {
    pub context: LoweringContext<'a>,
    pub chunk: BytecodeChunk,
}

//-////////////////////////////////////////////////////////////////////
// Lowering from SSA to Bytecode
//

/// The context for lowering a single function.
pub struct LoweringContext<'a> {
    func: &'a Function,
    ssa_to_slot: HashMap<Value, u32>,
    pub block_offsets: HashMap<Block, u32>,
    /// For patching jumps.
    jump_placeholders: Vec<(usize, Block)>,
}

impl<'a> LoweringContext<'a> {
    pub fn new(func: &'a Function) -> Self {
        Self {
            func,
            ssa_to_slot: Default::default(),
            block_offsets: Default::default(),
            jump_placeholders: Default::default(),
        }
    }

    /// Lower the function to a bytecode chunk.
    pub fn lower(mut self) -> LoweredFunction<'a> {
        let mut chunk = BytecodeChunk::default();
        // 1. Assign stack slots to all SSA values.
        self.assign_ssa_slots();

        // 2. Emit bytecode for each block.
        self.emit_blocks(&mut chunk);

        // 3. Patch jump instructions with correct offsets.
        self.patch_jumps(&mut chunk);

        LoweredFunction { context: self, chunk }
    }

    fn assign_ssa_slots(&mut self) {
        for i in 0..self.func.dfg.values.len() {
            let value = Value::new(i);
            self.ssa_to_slot.insert(value, i as u32);
        }
    }

    fn emit_blocks(&mut self, chunk: &mut BytecodeChunk) {
        let mut worklist = vec![self.func.layout.block_entry.unwrap()];
        let mut visited = std::collections::HashSet::new();

        while let Some(block_id) = worklist.pop() {
            if !visited.insert(block_id) {
                continue;
            }

            self.block_offsets.insert(block_id, chunk.code.len() as u32);

            let block_data = &self.func.cfg.blocks[block_id.index()];
            for &inst_id in &block_data.insts {
                self.emit_inst(inst_id, chunk);
            }

            if let Some(last_inst_id) = block_data.insts.last() {
                let inst_data = &self.func.dfg.insts[last_inst_id.index()];
                match &inst_data.opcode {
                    IrOpcode::Jump(dest) => worklist.push(*dest),
                    IrOpcode::BranchIf(_, t, f) => {
                        worklist.push(*f);
                        worklist.push(*t);
                    }
                    _ => {}
                }
            }
        }
    }

    fn emit_inst(&mut self, inst_id: Inst, chunk: &mut BytecodeChunk) {
        let inst = &self.func.dfg.insts[inst_id.index()];
        let results = self.func.dfg.inst_results.get(&inst_id);

        match &inst.opcode {
            IrOpcode::IConst(val) => {
                let dst = self.ssa_to_slot[&results.unwrap()[0]];
                // Simplified: using IConst64 for all constants
                chunk.code.push(Opcode::IConst64 as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&(*val as u64).to_le_bytes());
            }
            IrOpcode::IAdd => {
                let dst = self.ssa_to_slot[&results.unwrap()[0]];
                let a = self.ssa_to_slot[&inst.args[0]];
                let b = self.ssa_to_slot[&inst.args[1]];
                chunk.code.push(Opcode::Add as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&a.to_le_bytes());
                chunk.code.extend_from_slice(&b.to_le_bytes());
            }
            IrOpcode::ISub => {
                let dst = self.ssa_to_slot[&results.unwrap()[0]];
                let a = self.ssa_to_slot[&inst.args[0]];
                let b = self.ssa_to_slot[&inst.args[1]];
                chunk.code.push(Opcode::Sub as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&a.to_le_bytes());
                chunk.code.extend_from_slice(&b.to_le_bytes());
            }
            IrOpcode::ILt => {
                let dst = self.ssa_to_slot[&results.unwrap()[0]];
                let a = self.ssa_to_slot[&inst.args[0]];
                let b = self.ssa_to_slot[&inst.args[1]];
                chunk.code.push(Opcode::Lt as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&a.to_le_bytes());
                chunk.code.extend_from_slice(&b.to_le_bytes());
            }
            IrOpcode::Jump(dest) => {
                chunk.code.push(Opcode::Jump16 as u8);
                let pos = chunk.code.len();
                chunk.code.extend_from_slice(&[0, 0]); // Placeholder
                self.jump_placeholders.push((pos, *dest));
            }
            IrOpcode::BranchIf(cond, true_dest, false_dest) => {
                let cond_slot = self.ssa_to_slot[cond];
                chunk.code.push(Opcode::BranchIf16 as u8);
                chunk.code.extend_from_slice(&cond_slot.to_le_bytes());
                let pos = chunk.code.len();
                chunk.code.extend_from_slice(&[0, 0]); // Placeholder for true branch
                self.jump_placeholders.push((pos, *true_dest));

                // Unconditional jump for the false branch
                chunk.code.push(Opcode::Jump16 as u8);
                let pos = chunk.code.len();
                chunk.code.extend_from_slice(&[0, 0]); // Placeholder for false branch
                self.jump_placeholders.push((pos, *false_dest));
            }
            IrOpcode::Call(_func_ref, _args) => {
                // For now, assume the function ID is 0
                let func_id = 0u32;
                chunk.code.push(Opcode::Call as u8);
                chunk.code.extend_from_slice(&func_id.to_le_bytes());

                // In a real implementation, we would also handle arguments here
            }
            IrOpcode::Return(vals) => {
                if !vals.is_empty() {
                    let return_val_slot = self.ssa_to_slot[&vals[0]];
                    if return_val_slot != 0 {
                        // Move the return value to the first slot (v0)
                        chunk.code.push(Opcode::Mov as u8);
                        chunk.code.extend_from_slice(&0u32.to_le_bytes()); // dst = v0
                        chunk.code.extend_from_slice(&return_val_slot.to_le_bytes()); // src
                    }
                }
                chunk.code.push(Opcode::Return as u8);
            }
            _ => { /* Unimplemented */ }
        }
    }

    fn patch_jumps(&mut self, chunk: &mut BytecodeChunk) {
        for (pos, target_block) in &self.jump_placeholders {
            let target_offset = self.block_offsets[target_block];
            // The jump offset is relative to the position *after* the jump instruction.
            let jump_offset = target_offset as i16 - (*pos as i16 + 2);
            let bytes = jump_offset.to_le_bytes();
            chunk.code[*pos] = bytes[0];
            chunk.code[*pos + 1] = bytes[1];
        }
    }
}

//-////////////////////////////////////////////////////////////////////
// Bytecode Disassembler
//

pub fn disassemble_chunk(lowered_func: &LoweredFunction, name: &str) {
    println!("== {} ==", name);

    let mut offset = 0;
    while offset < lowered_func.chunk.code.len() {
        offset = disassemble_instruction(lowered_func, offset);
    }
}

pub fn disassemble_instruction(lowered_func: &LoweredFunction, offset: usize) -> usize {
    print!("{:04} ", offset);

    let opcode = lowered_func.chunk.code[offset];
    match unsafe { std::mem::transmute::<u8, Opcode>(opcode) } {
        Opcode::IConst64 => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = u64::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 13].try_into().unwrap());
            println!("ICONST64  v{}, #{}", dst, val);
            offset + 13
        }
        Opcode::Add => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("ADD       v{}, v{}, v{}", dst, a, b);
            offset + 13
        }
        Opcode::Sub => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("SUB       v{}, v{}, v{}", dst, a, b);
            offset + 13
        }
        Opcode::Lt => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("LT        v{}, v{}, v{}", dst, a, b);
            offset + 13
        }
        Opcode::Jump16 => {
            let jmp = i16::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 3].try_into().unwrap());
            let target_addr = offset as i16 + 3 + jmp;
            println!("JUMP      {:04} ({})", target_addr, jmp);
            offset + 3
        }
        Opcode::BranchIf16 => {
            let cond = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let jmp = i16::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 7].try_into().unwrap());
            let target_addr = offset as i16 + 7 + jmp;
            println!("BRANCH_IF v{}, {:04} ({})", cond, target_addr, jmp);
            offset + 7
        }
        Opcode::Call => {
            let func_id = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("CALL      fib #{}", func_id);
            offset + 5
        }
        Opcode::Mov => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("MOV       v{}, v{}", dst, src);
            offset + 9
        }
        Opcode::Return => {
            println!("RETURN");
            offset + 1
        }
        _ => {
            println!("Unknown opcode: {}", opcode);
            offset + 1
        }
    }
}
