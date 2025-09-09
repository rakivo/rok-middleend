use crate::{ssa::{
    Block, DataFlowGraph, Inst, InstructionData as IData, SsaFunc, SsaOp, StackSlot, Type, Value
}, util::IntoBytes};

use std::{ptr, mem};

use hashbrown::{HashMap, HashSet};

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
    IConst8       = 0,
    IConst16      = 1,
    IConst32      = 2,
    IConst64      = 3,
    FConst32      = 4,
    FConst64      = 5,

    // Arithmetic
    Add           = 10,
    Sub           = 11,
    Mul           = 12,
    Lt            = 13,
    FAdd          = 14,
    FSub          = 15,
    FMul          = 16,
    FDiv          = 17,

    // Control Flow
    Jump16        = 20,
    Jump32        = 21,
    BranchIf16    = 22,
    BranchIf32    = 23,
    Return        = 24,
    Call          = 25,

    // Memory
    Load8         = 40,
    Load16        = 41,
    Load32        = 42,
    Load64        = 43,
    Store8        = 44,
    Store16       = 45,
    Store32       = 46,
    Store64       = 47,

    // Stack operations
    Mov           = 50,

    // Stack frame management
    FrameSetup    = 60,
    FrameTeardown = 61,

    // Direct stack pointer operations
    SpAdd         = 62,
    SpSub         = 63,

    // Frame pointer relative operations
    FpLoad8       = 70,
    FpLoad16      = 71,
    FpLoad32      = 72,
    FpLoad64      = 73,
    FpStore8      = 74,
    FpStore16     = 75,
    FpStore32     = 76,
    FpStore64     = 77,

    // Stack pointer relative operations
    SpLoad8       = 80,
    SpLoad16      = 81,
    SpLoad32      = 82,
    SpLoad64      = 83,
    SpStore8      = 84,
    SpStore16     = 85,
    SpStore32     = 86,
    SpStore64     = 87,

    // Address calculation
    FpAddr        = 90,
    SpAddr        = 91,

    // VM control
    Halt          = 255,
}

const OPCODE_LOOKUP: [Option<Opcode>; 256] = {
    let mut table: [Option<Opcode>; 256] = [None; 256];
    table[Opcode::IConst8 as usize] = Some(Opcode::IConst8);
    table[Opcode::IConst16 as usize] = Some(Opcode::IConst16);
    table[Opcode::IConst32 as usize] = Some(Opcode::IConst32);
    table[Opcode::IConst64 as usize] = Some(Opcode::IConst64);
    table[Opcode::FConst32 as usize] = Some(Opcode::FConst32);
    table[Opcode::FConst64 as usize] = Some(Opcode::FConst64);
    table[Opcode::Add as usize] = Some(Opcode::Add);
    table[Opcode::Sub as usize] = Some(Opcode::Sub);
    table[Opcode::Mul as usize] = Some(Opcode::Mul);
    table[Opcode::Lt as usize] = Some(Opcode::Lt);
    table[Opcode::FAdd as usize] = Some(Opcode::FAdd);
    table[Opcode::FSub as usize] = Some(Opcode::FSub);
    table[Opcode::FMul as usize] = Some(Opcode::FMul);
    table[Opcode::FDiv as usize] = Some(Opcode::FDiv);
    table[Opcode::Jump16 as usize] = Some(Opcode::Jump16);
    table[Opcode::Jump32 as usize] = Some(Opcode::Jump32);
    table[Opcode::BranchIf16 as usize] = Some(Opcode::BranchIf16);
    table[Opcode::BranchIf32 as usize] = Some(Opcode::BranchIf32);
    table[Opcode::Call as usize] = Some(Opcode::Call);
    table[Opcode::Return as usize] = Some(Opcode::Return);
    table[Opcode::Load8 as usize] = Some(Opcode::Load8);
    table[Opcode::Load16 as usize] = Some(Opcode::Load16);
    table[Opcode::Load32 as usize] = Some(Opcode::Load32);
    table[Opcode::Load64 as usize] = Some(Opcode::Load64);
    table[Opcode::Store8 as usize] = Some(Opcode::Store8);
    table[Opcode::Store16 as usize] = Some(Opcode::Store16);
    table[Opcode::Store32 as usize] = Some(Opcode::Store32);
    table[Opcode::Store64 as usize] = Some(Opcode::Store64);
    table[Opcode::Mov as usize] = Some(Opcode::Mov);
    table[Opcode::FrameSetup as usize] = Some(Opcode::FrameSetup);
    table[Opcode::FrameTeardown as usize] = Some(Opcode::FrameTeardown);
    table[Opcode::SpAdd as usize] = Some(Opcode::SpAdd);
    table[Opcode::SpSub as usize] = Some(Opcode::SpSub);
    table[Opcode::FpLoad8 as usize] = Some(Opcode::FpLoad8);
    table[Opcode::FpLoad16 as usize] = Some(Opcode::FpLoad16);
    table[Opcode::FpLoad32 as usize] = Some(Opcode::FpLoad32);
    table[Opcode::FpLoad64 as usize] = Some(Opcode::FpLoad64);
    table[Opcode::FpStore8 as usize] = Some(Opcode::FpStore8);
    table[Opcode::FpStore16 as usize] = Some(Opcode::FpStore16);
    table[Opcode::FpStore32 as usize] = Some(Opcode::FpStore32);
    table[Opcode::FpStore64 as usize] = Some(Opcode::FpStore64);
    table[Opcode::SpLoad8 as usize] = Some(Opcode::SpLoad8);
    table[Opcode::SpLoad16 as usize] = Some(Opcode::SpLoad16);
    table[Opcode::SpLoad32 as usize] = Some(Opcode::SpLoad32);
    table[Opcode::SpLoad64 as usize] = Some(Opcode::SpLoad64);
    table[Opcode::SpStore8 as usize] = Some(Opcode::SpStore8);
    table[Opcode::SpStore16 as usize] = Some(Opcode::SpStore16);
    table[Opcode::SpStore32 as usize] = Some(Opcode::SpStore32);
    table[Opcode::SpStore64 as usize] = Some(Opcode::SpStore64);
    table[Opcode::FpAddr as usize] = Some(Opcode::FpAddr);
    table[Opcode::SpAddr as usize] = Some(Opcode::SpAddr);
    table[Opcode::Halt as usize] = Some(Opcode::Halt);
    table
};

impl Opcode {
    #[must_use]
    pub const fn from_u8(val: u8) -> Option<Self> {
        OPCODE_LOOKUP[val as usize]
    }

    #[must_use]
    pub const fn fp_load(bits: u32) -> Option<Self> {
        Some(match bits {
             8 => Opcode::FpLoad8,
            16 => Opcode::FpLoad16,
            32 => Opcode::FpLoad32,
            64 => Opcode::FpLoad64,
            _ => return None
        })
    }

    #[must_use]
    pub const fn fp_store(bits: u32) -> Option<Self> {
        Some(match bits {
             8 => Opcode::FpStore8,
            16 => Opcode::FpStore16,
            32 => Opcode::FpStore32,
            64 => Opcode::FpStore64,
            _ => return None
        })
    }
}

fn convert_opcode(opcode: SsaOp) -> Opcode {
    match opcode {
        SsaOp::IAdd => Opcode::Add,
        SsaOp::ISub => Opcode::Sub,
        SsaOp::IMul => Opcode::Mul,
        SsaOp::ILt  => Opcode::Lt,
        SsaOp::FAdd => Opcode::FAdd,
        SsaOp::FSub => Opcode::FSub,
        SsaOp::FMul => Opcode::FMul,
        SsaOp::FDiv => Opcode::FDiv,
        _ => panic!("Unsupported opcode {opcode:?}"),
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
    #[must_use]
    pub fn calculate_layout(func: &SsaFunc) -> Self {
        let mut frame_info = StackFrameInfo::default();
        let mut current_offset = 0i32;

        // Allocate stack slots (growing downward from frame pointer)
        for (slot_idx, slot_data) in func.stack_slots.iter().enumerate() {
            let slot = StackSlot::new(slot_idx);
            let size = slot_data.size;

            let align = slot_data.ty.align_bytes() as i32;
            current_offset = align_down(current_offset - size as i32, align);

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
    pub frame_info: StackFrameInfo,
}

impl BytecodeChunk {
    pub fn append<'a>(&mut self, x: impl IntoBytes<'a>) {
        self.code.extend_from_slice(&x.into_bytes());
    }

    pub fn append_placeholder<T: Sized>(&mut self, _: T) {
        let len = self.code.len();
        self.code.resize(len + mem::size_of::<T>(), 0);
    }
}

/// Represents a function that has been lowered to bytecode.
pub struct LoweredSsaFunc<'a> {
    pub context: LoweringContext<'a>,
    pub chunk: BytecodeChunk,
}

//////////////////////////////////////////////////////////////////////
// Lowering from SSA to Bytecode
//
pub struct LoweringContext<'a> {
    func: &'a mut SsaFunc,
    ssa_to_reg: HashMap<Value, u32>,

    block_offsets: HashMap<Block, u32>,

    /// For patching jumps.
    jump_placeholders: Vec<(usize, Block)>,

    /// Stack frame information
    frame_info: StackFrameInfo,

    /// Computed liveness (populated in `lower`)
    liveness: Option<Liveness>,

    /// Map from Value -> spill `StackSlot` (allocated in `frame_info`)
    spill_slots: HashMap<Value, StackSlot>,
}

/// The context for lowering a single function.
impl<'a> LoweringContext<'a> {
    pub const RETURN_VALUES_REGISTERS_COUNT: u32 = 8;

    pub fn new(func: &'a mut SsaFunc) -> Self {
        Self {
            frame_info: StackFrameInfo::calculate_layout(func),
            func,
            ssa_to_reg: HashMap::default(),
            block_offsets: HashMap::default(),
            jump_placeholders: Vec::default(),
            liveness: None,
            spill_slots: HashMap::default(),
        }
    }

    /// Lower the function to a bytecode chunk.
    #[must_use]
    pub fn lower(mut self) -> LoweredSsaFunc<'a> {
        // 1. Assign stack slots (register numbers) to all SSA values.
        self.assign_ssa_slots();

        let liv = self.compute_liveness();
        self.liveness = Some(liv);
        self.preallocate_spill_slots();

        // After possibly growing the frame with spill slots, copy frame info to chunk
        let mut chunk = BytecodeChunk {
            frame_info: self.frame_info.clone(),
            ..Default::default()
        };

        // 4. Emit frame setup at the beginning
        self.emit_frame_setup(&mut chunk);

        // 5. Emit bytecode for each block.
        self.emit_blocks(&mut chunk);

        // 6. Patch jump instructions with correct offsets.
        self.patch_jumps(&mut chunk);

        LoweredSsaFunc { context: self, chunk }
    }

    fn preallocate_spill_slots(&mut self) {
        let liv = unsafe { (*ptr::from_ref(self)).liveness() };

        for values in liv.live_across_call.values() {
            for &v in values {
                if self.spill_slots.contains_key(&v) {
                    continue
                }

                // If the IR explicitly stores this value to a stack slot somewhere -> reuse it.
                if let Some(existing_slot) = self.find_stack_slot_for_value(v) {
                    self.spill_slots.insert(v, existing_slot);
                    continue
                }

                let ty = self.func.dfg.values[v.index()].ty;
                let slot = self.allocate_spill_slot(ty);
                self.spill_slots.insert(v, slot);
            }
        }
    }

    fn liveness(&self) -> &Liveness {
        self.liveness.as_ref().expect("set .liveness first")
    }

    fn append_placeholder(
        &mut self,
        chunk: &mut BytecodeChunk,
        x: impl Sized,
        dst: Block
    ) {
        let pos = chunk.code.len();
        chunk.append_placeholder(mem::size_of_val(&x));
        self.jump_placeholders.push((pos, dst));
    }

    /// If the IR contains `StackStore { slot, arg }` that stores value `v` into `slot`,
    /// return that `StackSlot`. This lets us reuse slot instead of allocating a new spill slot.
    fn find_stack_slot_for_value(&self, v: Value) -> Option<StackSlot> {
        // iterate blocks & instructions looking for StackStore that stores `v`
        for block in 0..self.func.cfg.blocks.len() {
            let block_id = Block::new(block);
            let block_data = unsafe {
                &(*ptr::from_ref::<Self>(self)).func.cfg.blocks[block_id.index()]
            };
            for &inst_id in &block_data.insts {
                match &self.func.dfg.insts[inst_id.index()] {
                    IData::StackStore { slot, arg } if *arg == v => {
                        return Some(*slot)
                    }
                    _ => {}
                }
            }
        }
        None
    }

    /// Allocate a new FP-relative stack slot for a spill and register it in `frame_info`.
    /// Returns the `StackSlot` handle.
    fn allocate_spill_slot(&mut self, ty: Type) -> StackSlot {
        let size = ty.bytes();
        let align = ty.align_bytes() as i32;

        // compute new offset below existing frame (frame grows downward)
        // existing total is number of bytes currently reserved (positive)
        let existing_total = self.frame_info.total_size as i32;

        let offset = align_down(
            -existing_total - (size as i32),
            align
        );

        let slot = self.func.create_stack_slot(ty, size);

        self.frame_info.slot_allocations.insert(slot, StackSlotAllocation {
            offset,
            size,
            ty,
        });

        // update total_size (positive)
        self.frame_info.total_size = align_up((-offset) as u32, 16);

        slot
    }

    fn assign_ssa_slots(&mut self) {
        for i in 0..self.func.dfg.values.len() {
            let value = Value::new(i);
            self.ssa_to_reg.insert(
                value,
                i as u32 + Self::RETURN_VALUES_REGISTERS_COUNT
            );
        }
    }

    fn emit_frame_setup(&mut self, chunk: &mut BytecodeChunk) {
        if self.frame_info.total_size > 0 {
            chunk.append(Opcode::FrameSetup);
            chunk.append(self.frame_info.total_size);
        }
    }

    fn emit_frame_teardown(&mut self, chunk: &mut BytecodeChunk) {
        if self.frame_info.total_size > 0 {
            chunk.append(Opcode::FrameTeardown);
        }
    }

    #[must_use]
    pub fn num_regs(&self) -> usize {
        self.ssa_to_reg.len()
    }

    fn emit_blocks(&mut self, chunk: &mut BytecodeChunk) {
        let mut worklist = vec![self.func.layout.block_entry.unwrap()];
        let mut visited = HashSet::new();

        while let Some(block_id) = worklist.pop() {
            if !visited.insert(block_id) {
                continue
            }

            self.block_offsets.insert(block_id, chunk.code.len() as u32);

            let block_data = unsafe { &(*ptr::from_ref::<Self>(self)).func.cfg.blocks[block_id.index()] };
            for &inst_id in &block_data.insts {
                self.emit_inst(inst_id, chunk);
            }

            if let Some(last_inst_id) = block_data.insts.last() {
                let inst_data = &self.func.dfg.insts[last_inst_id.index()];
                match inst_data {
                    IData::Jump { destination, .. } => worklist.push(*destination),
                    IData::Branch { destinations, .. } => {
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
            IData::Const { value, .. } => {
                let dst = self.ssa_to_reg[&results.unwrap()[0]];
                chunk.code.push(Opcode::IConst64 as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&(*value as u64).to_le_bytes());
            }
            IData::FConst { value, .. } => {
                let dst = self.ssa_to_reg[&results.unwrap()[0]];
                chunk.code.push(Opcode::FConst64 as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&value.to_le_bytes());
            }
            IData::Binary { opcode, args } => {
                chunk.code.push(convert_opcode(*opcode) as u8);
                let dst = self.ssa_to_reg[&results.unwrap()[0]];
                let a = self.ssa_to_reg[&args[0]];
                let b = self.ssa_to_reg[&args[1]];
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&a.to_le_bytes());
                chunk.code.extend_from_slice(&b.to_le_bytes());
            }
            IData::Jump { destination, .. } => {
                chunk.code.push(Opcode::Jump16 as u8);
                let pos = chunk.code.len();
                chunk.code.extend_from_slice(&[0, 0]); // Placeholder
                self.jump_placeholders.push((pos, *destination));
            }
            IData::Branch { arg, destinations, .. } => {
                let cond_slot = self.ssa_to_reg[arg];
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
            IData::Call { func_id, args, .. } => {
                // 0) Emit stores for spilled values live across this call
                let l = self.liveness();
                if let Some(vals) = l.live_across_call.get(&inst_id) {
                    for &v in vals {
                        if let Some(&spill_slot) = self.spill_slots.get(&v) {
                            let allocation = &self.frame_info.slot_allocations[&spill_slot];
                            let src_reg = self.ssa_to_reg[&v];
                            let opcode = Opcode::fp_store(allocation.ty.bits()).unwrap();
                            chunk.append(opcode);
                            chunk.append(allocation.offset as u32);
                            chunk.append(src_reg);
                        }
                    }
                }

                // 1) Move arguments to registers starting from r8.
                for (i, &arg) in args.iter().enumerate() {
                    let arg_slot = self.ssa_to_reg[&arg];
                    chunk.append(Opcode::Mov);
                    chunk.append((i + 8) as u32); // dst
                    chunk.append(arg_slot);         // src
                }

                // 2) Emit call
                chunk.append(Opcode::Call);
                chunk.append(func_id.index() as u32);

                // 3) Move result(s) from r0 to destination register(s) BEFORE reloading spills.
                let mut result_vals: Vec<Value> = Vec::new();
                if let Some(results) = results {
                    if !results.is_empty() {
                        result_vals.push(results[0]);
                        let result_slot = self.ssa_to_reg[&results[0]];
                        if result_slot != 0 {
                            chunk.append(Opcode::Mov);
                            chunk.append(result_slot); // dst
                            chunk.append(0u32);       // src (r0)
                        }
                    }
                }

                // 4) Reload spilled values, but skip values that are call results (we just wrote them).
                let l = self.liveness();
                if let Some(vals) = l.live_across_call.get(&inst_id) {
                    for &v in vals {
                        if result_vals.contains(&v) { continue; }
                        if let Some(&spill_slot) = self.spill_slots.get(&v) {
                            let allocation = &self.frame_info.slot_allocations[&spill_slot];
                            let dst_reg = self.ssa_to_reg[&v];
                            let opcode = Opcode::fp_load(allocation.ty.bits()).unwrap();
                            chunk.append(opcode);
                            chunk.append(dst_reg);
                            chunk.append(allocation.offset as u32);
                        }
                    }
                }
            }
            IData::Return { args, .. } => {
                // Move return values to the first N registers (r0, r1, ...).
                for (i, &arg) in args.iter().enumerate() {
                    let arg_slot = self.ssa_to_reg[&arg];
                    if arg_slot != i as u32 {
                        chunk.append(Opcode::Mov);
                        chunk.append(i as u32); // dst
                        chunk.append(arg_slot);      // src
                    }
                }

                // Emit frame teardown before return
                self.emit_frame_teardown(chunk);
                chunk.append(Opcode::Return);
            }
            IData::StackLoad { slot, .. } => {
                let dst = self.ssa_to_reg[&results.unwrap()[0]];
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
            IData::StackStore { slot, arg, .. } => {
                let src = self.ssa_to_reg[arg];
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
            IData::StackAddr { slot, .. } => {
                let dst = self.ssa_to_reg[&results.unwrap()[0]];
                let allocation = &self.frame_info.slot_allocations[slot];

                chunk.code.push(Opcode::FpAddr as u8);
                chunk.code.extend_from_slice(&dst.to_le_bytes());
                chunk.code.extend_from_slice(&allocation.offset.to_le_bytes());
            }
            IData::Nop => {}
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

pub fn disassemble_chunk(lowered_func: &LoweredSsaFunc, name: &str) {
    println!("== {name} ==");
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

#[must_use]
pub fn disassemble_instruction(lowered_func: &LoweredSsaFunc, offset: usize) -> usize {
    const IMM_PREFIX: &str = "@";

    print!("{offset:05X} ");

    let opcode_byte = lowered_func.chunk.code[offset];
    let opcode: Opcode = unsafe { std::mem::transmute(opcode_byte) };

    match opcode {
        Opcode::IConst64 => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = u64::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 13].try_into().unwrap());
            println!("ICONST64   v{dst}, {IMM_PREFIX}{val}");
            offset + 13
        }
        Opcode::FConst64 => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = f64::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 13].try_into().unwrap());
            println!("FCONST64   v{dst}, {IMM_PREFIX}{val}");
            offset + 13
        }
        Opcode::Add => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("ADD        v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Sub => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("SUB        v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Mul => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("MUL        v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Lt => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered_func.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("LT         v{dst}, v{a}, v{b}");
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
            println!("{op_name}       v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Load64 => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let addr = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("LOAD64     v{dst}, v{addr}");
            offset + 9
        }
        Opcode::Store64 => {
            let addr = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("STORE64    v{addr}, v{val}");
            offset + 9
        }
        Opcode::Jump16 => {
            let jmp = i16::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 3].try_into().unwrap());
            let target_addr = offset as i16 + 3 + jmp;
            println!("JUMP16      {target_addr:04X} block({jmp})");
            offset + 3
        }
        Opcode::BranchIf16 => {
            let cond = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let jmp = i16::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 7].try_into().unwrap());
            let target_addr = offset as i16 + 7 + jmp;
            println!("BRANCH_IF16 v{cond}, {target_addr:04X} block({jmp})");
            offset + 7
        }
        Opcode::Call => {
            let func_id = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("CALL       F{func_id}");
            offset + 5
        }
        Opcode::Mov => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("MOV        v{dst}, v{src}");
            offset + 9
        }
        Opcode::Return => {
            println!("RETURN");
            offset + 1
        }

        // New stack frame operations
        Opcode::FrameSetup => {
            let size = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("FRAME_SETUP {size}");
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
            println!("FP_LOAD32  v{dst}, FP{fp_offset:+}");
            offset + 9
        }
        Opcode::FpLoad64 => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset = i32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_LOAD64  v{dst}, FP{fp_offset:+}");
            offset + 9
        }
        Opcode::FpStore32 => {
            let fp_offset = i32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_STORE32 FP{fp_offset:+}, v{src}");
            offset + 9
        }
        Opcode::FpStore64 => {
            let fp_offset = i32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_STORE64 FP{fp_offset:+}, v{src}");
            offset + 9
        }
        Opcode::FpAddr => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset = i32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_ADDR    v{dst}, FP{fp_offset:+}");
            offset + 9
        }

        // Stack pointer operations
        Opcode::SpAdd => {
            let sp_offset = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("SP_ADD     {sp_offset}");
            offset + 5
        }
        Opcode::SpSub => {
            let sp_offset = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("SP_SUB     {sp_offset}");
            offset + 5
        }
        Opcode::SpAddr => {
            let dst = u32::from_le_bytes(lowered_func.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let sp_offset = i32::from_le_bytes(lowered_func.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("SP_ADDR    v{dst}, SP{sp_offset:+}");
            offset + 9
        }

        _ => {
            println!("Unknown opcode: {opcode_byte}");
            offset + 1
        }
    }
}

type ValueSet = HashSet<Value>;

/// Liveness results for the function
#[derive(Debug, Default)]
pub struct Liveness {
    pub uses: HashMap<Block, ValueSet>,
    pub defs: HashMap<Block, ValueSet>,
    pub live_in: HashMap<Block, ValueSet>,
    pub live_out: HashMap<Block, ValueSet>,
    /// per-value interval: (`start_pos`, `end_pos`) where positions are instruction-order indices
    pub intervals: HashMap<Value, (usize, usize)>,
    /// for each Call instruction, which values are live *across* the call
    pub live_across_call: HashMap<Inst, Vec<Value>>,
}

impl LoweringContext<'_> {
    /// Compute uses/defs per block and then live-in/live-out via standard backward dataflow.
    /// After that compute per-value intervals (start..end) and detect values live across call insts.
    pub fn compute_liveness(&mut self) -> Liveness {
        let mut out = Liveness::default();

        // collect all blocks by index
        let all_blocks: Vec<Block> = (0..self.func.cfg.blocks.len()).map(Block::new).collect();

        // 1) compute uses/defs per block
        for &bb in &all_blocks {
            let mut uses = ValueSet::default();
            let mut defs = ValueSet::default();

            let block_data = unsafe { &(*ptr::from_ref::<Self>(self)).func.cfg.blocks[bb.index()] };
            for &inst_id in &block_data.insts {
                let (srcs, dsts) = Self::inst_uses_defs(inst_id, &self.func.dfg, &self.func.dfg.insts[inst_id.index()]);
                for v in srcs {
                    if !defs.contains(&v) {
                        uses.insert(v);
                    }
                }
                for v in dsts {
                    defs.insert(v);
                }
            }

            out.uses.insert(bb, uses);
            out.defs.insert(bb, defs);
        }

        // 2) block-level dataflow fixpoint (live_in / live_out)
        for &bb in &all_blocks {
            out.live_in.insert(bb, ValueSet::default());
            out.live_out.insert(bb, ValueSet::default());
        }

        let mut changed = true;
        while changed {
            changed = false;
            for &bb in all_blocks.iter().rev() {
                // compute liveOut by looking at successors via terminator
                let mut live_out = HashSet::<Value>::default();
                let block_data = unsafe { &(*ptr::from_ref::<Self>(self)).func.cfg.blocks[bb.index()] };
                if let Some(&last_inst) = block_data.insts.last() {
                    match &self.func.dfg.insts[last_inst.index()] {
                        IData::Jump { destination } => {
                            if let Some(s_in) = out.live_in.get(destination) {
                                live_out.extend(s_in.iter().copied());
                            }
                        }
                        IData::Branch { destinations, .. } => {
                            for &succ in destinations {
                                if let Some(s_in) = out.live_in.get(&succ) {
                                    live_out.extend(s_in.iter().copied());
                                }
                            }
                        }
                        _ => {}
                    }
                }

                // liveIn = uses U (liveOut - defs)
                let mut live_in = out.uses.get(&bb).cloned().unwrap_or_default();
                let defs = out.defs.get(&bb).cloned().unwrap_or_default();
                for v in &live_out {
                    if !defs.contains(v) {
                        live_in.insert(*v);
                    }
                }

                if &live_in != out.live_in.get(&bb).unwrap() {
                    out.live_in.insert(bb, live_in.clone());
                    changed = true;
                }
                if &live_out != out.live_out.get(&bb).unwrap() {
                    out.live_out.insert(bb, live_out.clone());
                    changed = true;
                }
            }
        }

        // 3) Instruction-level backward scan per block: compute live-after per instruction
        // and record live_across_call = live_after for Call instructions.
        for &bb in &all_blocks {
            // start from live_out[bb]
            let mut live_after: ValueSet = out.live_out.get(&bb).cloned().unwrap_or_default();

            // iterate instructions in reverse
            let block_data = unsafe { &(*ptr::from_ref::<Self>(self)).func.cfg.blocks[bb.index()] };
            for &inst_id in block_data.insts.iter().rev() {
                // if this inst is a Call, the values live AFTER the call are exactly those that
                // must be preserved across the call (they are needed later).
                if let IData::Call { .. } = &self.func.dfg.insts[inst_id.index()] {
                    out.live_across_call.insert(inst_id, live_after.iter().copied().collect());
                }

                // compute live_before = uses(inst) U (live_after - defs(inst))
                let (srcs, dsts) = Self::inst_uses_defs(inst_id, &self.func.dfg, &self.func.dfg.insts[inst_id.index()]);

                // live_after - defs
                for d in &dsts {
                    live_after.remove(d);
                }
                // add uses
                for s in &srcs {
                    live_after.insert(*s);
                }

                // continue: live_after now represents the liveness before the previous instruction
            }
        }

        out
    }

    /// Helper: return (sources, dests) for an instruction.
    /// This version needs inst id because results are stored in `dfg.inst_results`.
    fn inst_uses_defs(inst_id: Inst, dfg: &DataFlowGraph, inst: &IData) -> (Vec<Value>, Vec<Value>) {
        match inst {
            IData::Binary { args, .. } => {
                let srcs: Vec<Value> = args.to_vec();
                let dsts: Vec<Value> = dfg.inst_results.get(&inst_id)
                    .map(|sv| sv.iter().copied().collect()).unwrap_or_default();
                (srcs, dsts)
            }
            IData::Const { .. } | IData::FConst { .. } => {
                let dsts: Vec<Value> = dfg.inst_results.get(&inst_id)
                    .map(|sv| sv.iter().copied().collect()).unwrap_or_default();
                (vec![], dsts)
            }
            IData::Jump { .. } => (vec![], vec![]),
            IData::Branch { arg, .. } => (vec![*arg], vec![]),
            IData::Call { args, .. } => {
                let srcs: Vec<Value> = args.iter().copied().collect();
                let dsts: Vec<Value> = dfg.inst_results.get(&inst_id)
                    .map(|sv| sv.iter().copied().collect()).unwrap_or_default();
                (srcs, dsts)
            }
            IData::Return { args } => {
                let srcs: Vec<Value> = args.iter().copied().collect();
                (srcs, vec![])
            }
            IData::StackLoad { .. } | IData::StackAddr { .. } => {
                let dsts: Vec<Value> = dfg.inst_results.get(&inst_id)
                    .map(|sv| sv.iter().copied().collect()).unwrap_or_default();
                (vec![], dsts)
            }
            IData::StackStore { arg, .. } => (vec![*arg], vec![]),
            IData::Nop => (vec![], vec![]),
        }
    }
}
