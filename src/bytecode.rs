use crate::{Block, Function, Inst, InstructionData, Value};
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
    FConst32, FConst64,

    // Arithmetic
    Add, Sub, Mul, Lt,
    FAdd, FSub, FMul, FDiv,

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
    StackAddr,
    StackLoad,
    StackStore,
}

fn convert_opcode(opcode: crate::Opcode) -> Opcode {
    match opcode {
        crate::Opcode::IAdd => Opcode::Add,
        crate::Opcode::ISub => Opcode::Sub,
        crate::Opcode::IMul => Opcode::Mul,
        crate::Opcode::ILt => Opcode::Lt,
        crate::Opcode::FAdd => Opcode::FAdd,
        crate::Opcode::FSub => Opcode::FSub,
        crate::Opcode::FMul => Opcode::FMul,
        crate::Opcode::FDiv => Opcode::FDiv,
        _ => panic!("Unsupported opcode {:?}", opcode),
    }
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
                match inst_data {
                    InstructionData::Jump { destination, .. } => worklist.push(*destination),
                    InstructionData::Branch { destinations, .. } => {
                        worklist.push(destinations[1]);
                        worklist.push(destinations[0]);
                    },
                    _ => {}
                }
            }
        }
    }

    fn emit_inst(&mut self, inst_id: Inst, chunk: &mut BytecodeChunk) {
        let inst = &self.func.dfg.insts[inst_id.index()];
        let results = self.func.dfg.inst_results.get(&inst_id);

        match inst {
            InstructionData::Const { value, .. } => {
                let dst = self.ssa_to_slot[&results.unwrap()[0]];
                // Simplified: using IConst64 for all constants
                chunk.code.push(Opcode::IConst64 as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&(*value as u64).to_le_bytes());
            }
            InstructionData::FConst { value, .. } => {
                let dst = self.ssa_to_slot[&results.unwrap()[0]];
                // Simplified: using FConst64 for all constants
                chunk.code.push(Opcode::FConst64 as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&value.to_le_bytes());
            }
            InstructionData::Binary { opcode, args } => {
                chunk.code.push(convert_opcode(*opcode) as u8);
                let dst = self.ssa_to_slot[&results.unwrap()[0]];
                let a = self.ssa_to_slot[&args[0]];
                let b = self.ssa_to_slot[&args[1]];
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&a.to_le_bytes());
                chunk.code.extend_from_slice(&b.to_le_bytes());
            }
            InstructionData::Jump { destination, .. } => {
                chunk.code.push(Opcode::Jump16 as u8);
                let pos = chunk.code.len();
                chunk.code.extend_from_slice(&[0, 0]); // Placeholder
                self.jump_placeholders.push((pos, *destination));
            }
            InstructionData::Branch { arg, destinations, .. } => {
                let cond_slot = self.ssa_to_slot[arg];
                chunk.code.push(Opcode::BranchIf16 as u8);
                chunk.code.extend_from_slice(&cond_slot.to_le_bytes());
                let pos = chunk.code.len();
                chunk.code.extend_from_slice(&[0, 0]); // Placeholder for true branch
                self.jump_placeholders.push((pos, destinations[0]));

                // Unconditional jump for the false branch
                chunk.code.push(Opcode::Jump16 as u8);
                let pos = chunk.code.len();
                chunk.code.extend_from_slice(&[0, 0]); // Placeholder for false branch
                self.jump_placeholders.push((pos, destinations[1]));
            }
            InstructionData::Call { func_id, args, .. } => {
                chunk.code.push(Opcode::Call as u8);
                chunk.code.extend_from_slice(&(func_id.index() as u32).to_le_bytes());
                chunk.code.push(args.len() as u8);

                for &arg in args.iter() {
                    let arg_slot = self.ssa_to_slot[&arg];
                    chunk.code.extend_from_slice(&arg_slot.to_le_bytes());
                }
            }
            InstructionData::Return { args, .. } => {
                if !args.is_empty() {
                    let return_val_slot = self.ssa_to_slot[&args[0]];
                    if return_val_slot != 0 {
                        // Move the return value to the first slot (v0)
                        chunk.code.push(Opcode::Mov as u8);
                        chunk.code.extend_from_slice(&0u32.to_le_bytes()); // dst = v0
                        chunk.code.extend_from_slice(&return_val_slot.to_le_bytes()); // src
                    }
                }
                chunk.code.push(Opcode::Return as u8);
            }
            InstructionData::StackLoad { slot, .. } => {
                let dst = self.ssa_to_slot[&results.unwrap()[0]];
                chunk.code.push(Opcode::StackLoad as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&(slot.index() as u32).to_le_bytes());
            }
            InstructionData::StackStore { slot, arg, .. } => {
                let src = self.ssa_to_slot[arg];
                chunk.code.push(Opcode::StackStore as u8);
                chunk.code.extend_from_slice(&(slot.index() as u32).to_le_bytes());
                chunk.code.extend_from_slice(&src.to_le_bytes());
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

    let opcode_byte = lowered_func.chunk.code[offset];
    let opcode: Opcode = unsafe { std::mem::transmute(opcode_byte) };

    match opcode {
        Opcode::IConst64 => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = u64::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 13].try_into().unwrap());
            println!("ICONST64  v{}, #{}", dst, val);
            offset + 13
        }
        Opcode::FConst64 => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = f64::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 13].try_into().unwrap());
            println!("FCONST64  v{}, #{}", dst, val);
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
        Opcode::Mul => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("MUL       v{}, v{}, v{}", dst, a, b);
            offset + 13
        }
        Opcode::Lt => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("LT        v{}, v{}, v{}", dst, a, b);
            offset + 13
        }
        Opcode::FAdd => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("FADD      v{}, v{}, v{}", dst, a, b);
            offset + 13
        }
        Opcode::FSub => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("FSUB      v{}, v{}, v{}", dst, a, b);
            offset + 13
        }
        Opcode::FMul => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("FMUL      v{}, v{}, v{}", dst, a, b);
            offset + 13
        }
        Opcode::FDiv => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("FDIV      v{}, v{}, v{}", dst, a, b);
            offset + 13
        }
        Opcode::Load64 => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let addr = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("LOAD64    v{}, v{}", dst, addr);
            offset + 9
        }
        Opcode::Store64 => {
            let addr = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("STORE64   v{}, v{}", addr, val);
            offset + 9
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
            let num_args = lowered_func.chunk.code[offset + 5] as usize;
            print!("CALL      F{}, {} args", func_id, num_args);
            let mut new_offset = offset + 6;
            for _ in 0..num_args {
                let arg = u32::from_le_bytes(lowered_func.chunk.code[new_offset..new_offset + 4].try_into().unwrap());
                print!(", v{}", arg);
                new_offset += 4;
            }
            println!();
            new_offset
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
        Opcode::StackAddr => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let slot = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("STACK_ADDR v{}, s{}", dst, slot);
            offset + 9
        }
        Opcode::StackLoad => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let slot = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("STACK_LOAD v{}, s{}", dst, slot);
            offset + 9
        }
        Opcode::StackStore => {
            let slot = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("STACK_STORE s{}, v{}", slot, src);
            offset + 9
        }
        _ => {
            println!("Unknown opcode: {}", opcode_byte);
            offset + 1
        }
    }
}