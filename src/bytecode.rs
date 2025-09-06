use crate::{Block, Function, Inst, InstructionData, StackSlot, Type, Value};
use hashbrown::HashMap;

fn get_type_alignment(ty: Type) -> i32 {
    match ty {
        Type::I32 | Type::F32 => 4,
        Type::I64 | Type::F64 | Type::Ptr => 8,
    }
}

fn get_type_size(ty: Type) -> u32 {
    match ty {
        Type::I32 | Type::F32 => 4,
        Type::I64 | Type::F64 | Type::Ptr => 8,
    }
}

fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

fn align_down(value: i32, alignment: i32) -> i32 {
    value & !(alignment - 1)
}

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

    // Low-level stack operations
    Mov, // Move value from one stack slot to another

    // Stack frame management
    FrameSetup,      // Set up stack frame: FrameSetup <frame_size>
    FrameTeardown,   // Tear down stack frame

    // Direct stack pointer operations
    SpAdd,           // Add to stack pointer: SpAdd <offset>
    SpSub,           // Subtract from stack pointer: SpSub <offset>

    // Frame pointer relative operations
    FpLoad8, FpLoad16, FpLoad32, FpLoad64,   // Load from [FP + offset]
    FpStore8, FpStore16, FpStore32, FpStore64, // Store to [FP + offset]

    // Stack pointer relative operations
    SpLoad8, SpLoad16, SpLoad32, SpLoad64,   // Load from [SP + offset]
    SpStore8, SpStore16, SpStore32, SpStore64, // Store to [SP + offset]

    // Address calculation
    FpAddr,          // Calculate FP + offset address: FpAddr <dst>, <offset>
    SpAddr,          // Calculate SP + offset address: SpAddr <dst>, <offset>
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

/// Stack slot allocation information
#[derive(Debug, Clone)]
pub struct StackSlotAllocation {
    pub offset: i32,    // Offset from frame pointer (negative for locals)
    pub size: u32,      // Size in bytes
    pub ty: Type,       // Type of the slot
}

/// Stack frame layout information
#[derive(Debug, Clone, Default)]
pub struct StackFrameInfo {
    pub total_size: u32,
    pub slot_allocations: HashMap<StackSlot, StackSlotAllocation>,
}

impl StackFrameInfo {
    /// Calculate stack frame layout for the given function
    pub fn calculate_layout(func: &Function) -> Self {
        let mut frame_info = StackFrameInfo::default();
        let mut current_offset = 0i32;

        // Allocate stack slots (growing downward from frame pointer)
        for (slot_idx, slot_data) in func.stack_slots.iter().enumerate() {
            let slot = StackSlot::new(slot_idx);
            let size = slot_data.size;

            // Align to natural alignment of the type
            let alignment = get_type_alignment(slot_data.ty);
            current_offset = align_down(current_offset - size as i32, alignment);

            frame_info.slot_allocations.insert(slot, StackSlotAllocation {
                offset: current_offset,
                size,
                ty: slot_data.ty,
            });
        }

        // Total frame size (make it 16-byte aligned for calling convention)
        frame_info.total_size = align_up((-current_offset) as u32, 16);

        frame_info
    }
}

/// A chunk of bytecode for a single function.
#[derive(Debug, Clone, Default)]
pub struct BytecodeChunk {
    pub code: Vec<u8>,
    pub constants: Vec<u64>,
    pub frame_info: StackFrameInfo,
}

/// Represents a function that has been lowered to bytecode.
pub struct LoweredFunction<'a> {
    pub context: LoweringContext<'a>,
    pub chunk: BytecodeChunk,
}

//-////////////////////////////////////////////////////////////////////
// Lowering from SSA to Bytecode
//
pub struct LoweringContext<'a> {
    func: &'a mut Function,
    ssa_to_slot: HashMap<Value, u32>,
    pub block_offsets: HashMap<Block, u32>,
    /// For patching jumps.
    jump_placeholders: Vec<(usize, Block)>,
    /// Stack frame information
    frame_info: StackFrameInfo,
}

/// The context for lowering a single function.
impl<'a> LoweringContext<'a> {
    pub fn new(func: &'a mut Function) -> Self {
        let frame_info = StackFrameInfo::calculate_layout(func);

        Self {
            func,
            ssa_to_slot: Default::default(),
            block_offsets: Default::default(),
            jump_placeholders: Default::default(),
            frame_info,
        }
    }

    /// Lower the function to a bytecode chunk.
    pub fn lower(mut self) -> LoweredFunction<'a> {
        let mut chunk = BytecodeChunk::default();

        // Copy frame info to chunk
        chunk.frame_info = self.frame_info.clone();

        // 1. Assign stack slots to all SSA values.
        self.assign_ssa_slots();

        // 2. Emit frame setup at the beginning
        self.emit_frame_setup(&mut chunk);

        // 3. Emit bytecode for each block.
        self.emit_blocks(&mut chunk);

        // 4. Patch jump instructions with correct offsets.
        self.patch_jumps(&mut chunk);

        LoweredFunction { context: self, chunk }
    }

    fn assign_ssa_slots(&mut self) {
        for i in 0..self.func.dfg.values.len() {
            let value = Value::new(i);
            self.ssa_to_slot.insert(value, i as u32);
        }
    }

    fn emit_frame_setup(&mut self, chunk: &mut BytecodeChunk) {
        if self.frame_info.total_size > 0 {
            chunk.code.push(Opcode::FrameSetup as u8);
            chunk.code.extend_from_slice(&self.frame_info.total_size.to_le_bytes());
        }
    }

    fn emit_frame_teardown(&mut self, chunk: &mut BytecodeChunk) {
        if self.frame_info.total_size > 0 {
            chunk.code.push(Opcode::FrameTeardown as u8);
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

            let block_data = unsafe { &(&*(self as *const Self)).func.cfg.blocks[block_id.index()] };
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
                chunk.code.push(Opcode::IConst64 as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&(*value as u64).to_le_bytes());
            }
            InstructionData::FConst { value, .. } => {
                let dst = self.ssa_to_slot[&results.unwrap()[0]];
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
                // Emit frame teardown before return
                self.emit_frame_teardown(chunk);
                chunk.code.push(Opcode::Return as u8);
            }

            // Replace high-level stack operations with low-level ones
            InstructionData::StackLoad { slot, .. } => {
                let dst = self.ssa_to_slot[&results.unwrap()[0]];
                let allocation = &self.frame_info.slot_allocations[slot];

                // Choose appropriate load instruction based on type
                let opcode = match allocation.ty {
                    Type::I32 | Type::F32 => Opcode::FpLoad32,
                    Type::I64 | Type::F64 | Type::Ptr => Opcode::FpLoad64,
                };

                chunk.code.push(opcode as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&allocation.offset.to_le_bytes());
            }

            InstructionData::StackStore { slot, arg, .. } => {
                let src = self.ssa_to_slot[arg];
                let allocation = &self.frame_info.slot_allocations[slot];

                // Choose appropriate store instruction based on type
                let opcode = match allocation.ty {
                    Type::I32 | Type::F32 => Opcode::FpStore32,
                    Type::I64 | Type::F64 | Type::Ptr => Opcode::FpStore64,
                };

                chunk.code.push(opcode as u8);
                chunk.code.extend_from_slice(&allocation.offset.to_le_bytes());
                chunk.code.extend_from_slice(&src.to_le_bytes());
            }

            InstructionData::StackAddr { slot, .. } => {
                let dst = self.ssa_to_slot[&results.unwrap()[0]];
                let allocation = &self.frame_info.slot_allocations[slot];

                chunk.code.push(Opcode::FpAddr as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&allocation.offset.to_le_bytes());
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
    println!("Frame size: {} bytes", lowered_func.chunk.frame_info.total_size);

    // Print stack slot allocations
    for (slot, allocation) in &lowered_func.chunk.frame_info.slot_allocations {
        println!("  s{}: {:?} at FP{:+} (size: {})",
                slot.index(), allocation.ty, allocation.offset, allocation.size);
    }
    println!();

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
        Opcode::FAdd | Opcode::FSub | Opcode::FMul | Opcode::FDiv => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            let op_name = match opcode {
                Opcode::FAdd => "FADD",
                Opcode::FSub => "FSUB",
                Opcode::FMul => "FMUL",
                Opcode::FDiv => "FDIV",
                _ => unreachable!(),
            };
            println!("{}      v{}, v{}, v{}", op_name, dst, a, b);
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

        // New stack frame operations
        Opcode::FrameSetup => {
            let size = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("FRAME_SETUP {}", size);
            offset + 5
        }
        Opcode::FrameTeardown => {
            println!("FRAME_TEARDOWN");
            offset + 1
        }

        // Frame pointer relative operations
        Opcode::FpLoad32 => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset = i32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_LOAD32 v{}, FP{:+}", dst, fp_offset);
            offset + 9
        }
        Opcode::FpLoad64 => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset = i32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_LOAD64 v{}, FP{:+}", dst, fp_offset);
            offset + 9
        }
        Opcode::FpStore32 => {
            let fp_offset = i32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_STORE32 FP{:+}, v{}", fp_offset, src);
            offset + 9
        }
        Opcode::FpStore64 => {
            let fp_offset = i32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_STORE64 FP{:+}, v{}", fp_offset, src);
            offset + 9
        }
        Opcode::FpAddr => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset = i32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_ADDR   v{}, FP{:+}", dst, fp_offset);
            offset + 9
        }

        // Stack pointer operations
        Opcode::SpAdd => {
            let sp_offset = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("SP_ADD    {}", sp_offset);
            offset + 5
        }
        Opcode::SpSub => {
            let sp_offset = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("SP_SUB    {}", sp_offset);
            offset + 5
        }
        Opcode::SpAddr => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let sp_offset = i32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("SP_ADDR   v{}, SP{:+}", dst, sp_offset);
            offset + 9
        }

        _ => {
            println!("Unknown opcode: {}", opcode_byte);
            offset + 1
        }
    }
}
