use crate::util::{self, reborrow};
use crate::bytecode::{
    StackFrameInfo,
    StackSlotAllocation,
    Opcode,
    BytecodeChunk
};
use crate::ssa::{
    Block,
    DataFlowGraph,
    Inst,
    InstructionData as IData,
    SsaFunc,
    StackSlot,
    Type,
    Value
};

use std::collections::{HashMap, HashSet};

type ValueSet = HashSet<Value>;

/// Represents a function that has been lowered to bytecode.
pub struct LoweredSsaFunc<'a> {
    pub context: LoweringContext<'a>,
    pub chunk: BytecodeChunk,
}

#[cfg(debug_assertions)]
#[derive(Clone, Debug)]
pub struct InstMeta {
    pub inst: Inst,             // SSA inst id
    pub pc: usize,                // start pc
    pub size: u8,              // byte size
}

//////////////////////////////////////////////////////////////////////
// Lowering from SSA to Bytecode
//
pub struct LoweringContext<'a> {
    pub func: &'a mut SsaFunc,
    pub ssa_to_reg: HashMap<Value, u32>,

    block_offsets: HashMap<Block, u32>,

    /// For patching jumps.
    jump_placeholders: Vec<(usize, Block)>,

    /// Stack frame information
    pub frame_info: StackFrameInfo,

    /// Computed liveness (populated in `lower`)
    liveness: Option<Liveness>,

    /// Map from Value -> spill `StackSlot` (allocated in `frame_info`)
    pub spill_slots: HashMap<Value, StackSlot>,

    #[cfg(debug_assertions)]
    pc_to_inst_meta: HashMap<usize, InstMeta>,  // index == inst index in lowered list
}

/// The context for lowering a single function.
#[cfg_attr(not(debug_assertions), allow(unused, dead_code))]
impl<'a> LoweringContext<'a> {
    pub const RETURN_VALUES_REGISTERS_COUNT: u32 = 8;

    pub fn new(func: &'a mut SsaFunc) -> Self {
        Self {
            #[cfg(debug_assertions)]
            pc_to_inst_meta: HashMap::new(),
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

    #[inline(always)]
    pub fn liveness(&self) -> &Liveness {
        self.liveness.as_ref().expect("set .liveness first")
    }

    fn preallocate_spill_slots(&mut self) {
        // SAFETY: we don't mutate self.liveness here
        let liv = unsafe { reborrow(self.liveness()) };

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

    #[inline(always)]
    pub fn append_jump_placeholder<T>(
        &mut self,
        chunk: &mut BytecodeChunk,
        dst: Block
    ) {
        let pos = chunk.code.len();
        chunk.append_placeholder::<T>();
        self.jump_placeholders.push((pos, dst));
    }

    /// If the IR contains `StackStore { slot, arg }` that stores value `v` into `slot`,
    /// return that `StackSlot`. This lets us reuse slot instead of allocating a new spill slot.
    fn find_stack_slot_for_value(&self, v: Value) -> Option<StackSlot> {
        // iterate blocks & instructions looking for StackStore that stores `v`
        for block in 0..self.func.cfg.blocks.len() {
            let block_id = Block::new(block);
            let block_data = &self.func.cfg.blocks[block_id.index()];
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

        let offset = util::align_down(
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
        self.frame_info.total_size = util::align_up((-offset) as u32, 16);

        slot
    }

    #[inline(always)]
    fn assign_ssa_slots(&mut self) {
        for i in 0..self.func.dfg.values.len() {
            let value = Value::new(i);
            self.ssa_to_reg.insert(
                value,
                i as u32 + Self::RETURN_VALUES_REGISTERS_COUNT
            );
        }
    }

    #[inline(always)]
    pub fn emit_frame_setup(&mut self, chunk: &mut BytecodeChunk) {
        if self.frame_info.total_size > 0 {
            chunk.append(Opcode::FrameSetup);
            chunk.append(self.frame_info.total_size);
        }
    }

    #[inline(always)]
    pub fn emit_frame_teardown(&mut self, chunk: &mut BytecodeChunk) {
        if self.frame_info.total_size > 0 {
            chunk.append(Opcode::FrameTeardown);
        }
    }

    #[must_use]
    #[inline(always)]
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

            let n = self.func.cfg.blocks[block_id.index()].insts.len();
            #[cfg(debug_assertions)]
            self.pc_to_inst_meta.reserve(n);
            for i in 0..n {
                let pc = chunk.code.len();

                let inst_id = self.func.cfg.blocks[block_id.index()].insts[i];
                self.generated_emit_inst(inst_id, chunk);

                #[cfg(debug_assertions)]
                self.pc_to_inst_meta.insert(
                    pc,
                    InstMeta {
                        inst: inst_id,
                        pc,
                        size: (chunk.code.len() - pc) as u8
                    }
                );
            }

            let block_data = &self.func.cfg.blocks[block_id.index()];
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

            let block_data = &self.func.cfg.blocks[bb.index()];
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
                let block_data = &self.func.cfg.blocks[bb.index()];
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
            let block_data = &self.func.cfg.blocks[bb.index()];
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
            IData::IConst { .. } | IData::FConst { .. } => {
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
    let mut curr_block: Option<Block> = None;
    while offset < lowered_func.chunk.code.len() {
        offset = disassemble_instruction(lowered_func, offset, &mut curr_block);
    }
}

#[must_use]
#[cfg_attr(not(debug_assertions), allow(unused, dead_code))]
pub fn disassemble_instruction(
    lowered: &LoweredSsaFunc,
    offset: usize,
    current_block: &mut Option<Block>,
) -> usize {
    let offset_str = format!("{offset:05X} ");

    #[cfg(debug_assertions)]
    {
        if let Some(InstMeta {
            pc, inst, size
        }) = lowered.context.pc_to_inst_meta.get(&offset) {
            // Look up the block this instruction belongs to
            if let Some(&block) = lowered.context.func.layout.inst_blocks.get(inst) {
                if Some(block) != *current_block {
                    *current_block = Some(block);
                    println!();
                    println!("{offset_str} ; block({})", block.index());
                }
            }

            println!();
            println!("{offset_str};");
            print!("{offset_str};");
            println!("{}", lowered.context.func.pretty_print_inst(*inst));
            println!("{offset_str};");
            print!("{offset_str};");
            println!("  pc={pc:?} inst_id={inst:?}, size={size}");
            println!("{offset_str};");
        }
    }

    print!("{offset_str}");

    let opcode_byte = lowered.chunk.code[offset];
    let opcode: Opcode = unsafe { std::mem::transmute(opcode_byte) };

    match opcode {
        Opcode::IConst64 => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = u64::from_le_bytes(lowered.chunk.code[offset + 5..offset + 13].try_into().unwrap());
            println!("ICONST64    v{dst}, {val}_i64");
            offset + 13
        }
        Opcode::FConst64 => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = f64::from_le_bytes(lowered.chunk.code[offset + 5..offset + 13].try_into().unwrap());
            println!("FCONST64    v{dst}, {val}_f64");
            offset + 13
        }
        Opcode::Add => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("ADD         v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Sub => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("SUB         v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Mul => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("MUL         v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Lt => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("LT          v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::FAdd | Opcode::FSub | Opcode::FMul | Opcode::FDiv => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            let op_name = match opcode {
                Opcode::FAdd => "FADD",
                Opcode::FSub => "FSUB",
                Opcode::FMul => "FMUL",
                Opcode::FDiv => "FDIV",
                _ => unreachable!(),
            };
            println!("{op_name}        v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Load64 => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let addr = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("LOAD64      v{dst}, v{addr}");
            offset + 9
        }
        Opcode::Store64 => {
            let addr = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("STORE64     v{addr}, v{val}");
            offset + 9
        }
        Opcode::Jump16 => {
            let jmp = i16::from_le_bytes(lowered.chunk.code[offset + 1..offset + 3].try_into().unwrap());
            let sign = if jmp < 0 { "-" } else { "+" };
            let target_addr = offset as i16 + 3 + jmp;
            println!("JUMP16      {target_addr:04X} ({sign}0x{jmp:X})");
            offset + 3
        }
        Opcode::BranchIf16 => {
            let cond = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let jmp = i16::from_le_bytes(lowered.chunk.code[offset + 5..offset + 7].try_into().unwrap());
            let target_addr = offset as i16 + 7 + jmp;
            let sign = if jmp < 0 { "-" } else { "+" };
            println!("BRANCH_IF16 v{cond}, {target_addr:04X} ({sign}0x{jmp:X})");
            offset + 7
        }
        Opcode::Call => {
            let func_id = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("CALL        F{func_id}");
            offset + 5
        }
        Opcode::Mov => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("MOV         v{dst}, v{src}");
            offset + 9
        }
        Opcode::Return => {
            println!("RETURN");
            offset + 1
        }

        // New stack frame operations
        Opcode::FrameSetup => {
            let size = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("FRAME_SETUP {size}");
            offset + 5
        }
        Opcode::FrameTeardown => {
            println!("FRAME_TEARDOWN");
            offset + 1
        }

        // Frame pointer relative operations
        Opcode::FpLoad32 => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_LOAD32   v{dst}, FP{fp_offset:+}");
            offset + 9
        }
        Opcode::FpLoad64 => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_LOAD64   v{dst}, FP{fp_offset:+}");
            offset + 9
        }
        Opcode::FpStore32 => {
            let fp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_STORE32  FP{fp_offset:+}, v{src}");
            offset + 9
        }
        Opcode::FpStore64 => {
            let fp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_STORE64  FP{fp_offset:+}, v{src}");
            offset + 9
        }
        Opcode::FpAddr => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_ADDR     v{dst}, FP{fp_offset:+}");
            offset + 9
        }

        // Stack pointer operations
        Opcode::SpAdd => {
            let sp_offset = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("SP_ADD      {sp_offset}");
            offset + 5
        }
        Opcode::SpSub => {
            let sp_offset = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("SP_SUB      {sp_offset}");
            offset + 5
        }
        Opcode::SpAddr => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let sp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("SP_ADDR     v{dst}, SP{sp_offset:+}");
            offset + 9
        }

        _ => {
            println!("Unknown opcode: {opcode_byte}");
            offset + 1
        }
    }
}

