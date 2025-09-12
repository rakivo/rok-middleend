use crate::entity::EntityRef;
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

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, BTreeMap};

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
    pub pc_to_inst_meta: HashMap<usize, InstMeta>,  // index == inst index in lowered list
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
        let liv = self.compute_liveness();
        self.liveness = Some(liv);

        let config = RegAllocConfig::new(
            self.func.signature.params.len() as _
        );
        self.assign_ssa_slots_smart(config);

        // 1. Assign stack slots (register numbers) to all SSA values.
        // self.assign_ssa_slots_naive();
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
        let size = ty.bytes() as i32;
        let align = ty.align_bytes() as u32;

        // compute new offset above existing frame
        let mut offset = self.frame_info.total_size;
        offset = util::align_up(offset, align);

        let slot = self.func.create_stack_slot(ty, size as u32);

        self.frame_info.slot_allocations.insert(slot, StackSlotAllocation {
            offset,
            size: size as u32,
            ty,
        });

        // update total_size
        self.frame_info.total_size = util::align_up(offset as u32 + size as u32, 16);

        slot
    }

    #[allow(unused)]
    #[inline(always)]
    fn assign_ssa_slots_naive(&mut self) {
        for i in 0..self.func.dfg.values.len() {
            let value = Value::new(i);
            self.ssa_to_reg.insert(
                value,
                i as u32 + Self::RETURN_VALUES_REGISTERS_COUNT
            );
        }
    }

    #[allow(unused)]
    fn assign_ssa_slots_smart(&mut self, config: RegAllocConfig) {
        // Clear any existing assignments
        self.ssa_to_reg.clear();

        // First, assign function arguments to their fixed registers
        // Arguments are typically the first N values that are used but never defined
        let mut all_defined: HashSet<Value> = HashSet::new();
        let mut all_used: HashSet<Value> = HashSet::new();

        // Collect all defined and used values
        for block_idx in 0..self.func.cfg.blocks.len() {
            let block_id = Block::new(block_idx);
            let block_data = &self.func.cfg.blocks[block_id.index()];

            for &inst_id in &block_data.insts {
                let inst_data = &self.func.dfg.insts[inst_id.index()];
                let (uses, defs) = Self::inst_uses_defs(inst_id, &self.func.dfg, inst_data);

                for val in uses {
                    all_used.insert(val);
                }
                for val in defs {
                    all_defined.insert(val);
                }
            }
        }

        // Function arguments are values that are used but never defined
        let mut function_args: Vec<Value> = all_used.difference(&all_defined).copied().collect();
        function_args.sort_by_key(|v| v.index()); // Sort by value index for deterministic assignment

        // Pre-assign function arguments to r8, r9, r10, etc.
        for (i, &arg_val) in function_args.iter().enumerate() {
            let reg = config.return_registers + i as u32;
            self.ssa_to_reg.insert(arg_val, reg);
        }

        #[cfg(debug_assertions)]
        println!("Pre-assigned {} function arguments: {:?}",
            function_args.len(),
            function_args.iter().enumerate().map(|(i, v)| (v.index(), config.return_registers + i as u32)).collect::<Vec<_>>()
        );

        // Update config with actual argument count
        let mut updated_config = config;
        updated_config.argument_count = function_args.len() as u32;

        let mut allocator = SmartRegisterAllocator::new(updated_config);
        allocator.allocate(self.func);

        // Apply register assignments for non-argument values
        for (&value, &reg) in &allocator.assignments {
            self.ssa_to_reg.insert(value, reg);
        }

        // Handle spilled values by ensuring they have spill slots
        for spilled_value in &allocator.spilled_values {
            if !self.spill_slots.contains_key(spilled_value) {
                let ty = self.func.dfg.values[spilled_value.index()].ty;
                let slot = self.allocate_spill_slot(ty);
                self.spill_slots.insert(*spilled_value, slot);
            }
        }

        let stats = allocator.stats();
        #[cfg(debug_assertions)]
        println!("Register allocation stats: {:?}", stats);
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
            IData::Unary { arg, .. } => {
                let srcs: Vec<Value> = vec![*arg];
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
            IData::CallExt { args, .. } => {
                let srcs: Vec<Value> = args.iter().copied().collect();
                let dsts: Vec<Value> = dfg.inst_results.get(&inst_id)
                    .map(|sv| sv.iter().copied().collect()).unwrap_or_default();
                (srcs, dsts)
            }
            IData::Return { args } => {
                let srcs: Vec<Value> = args.iter().copied().collect();
                (srcs, vec![])
            }
            IData::DataAddr { .. } |
            IData::StackLoad { .. } |
            IData::StackAddr { .. } => {
                let dsts: Vec<Value> = dfg.inst_results.get(&inst_id)
                    .map(|sv| sv.iter().copied().collect()).unwrap_or_default();
                (vec![], dsts)
            }
            IData::StackStore { arg, .. } => (vec![*arg], vec![]),
            IData::LoadNoOffset { addr, .. } => (vec![*addr], dfg.inst_results.get(&inst_id).map(|sv| sv.iter().copied().collect()).unwrap_or_default()),
            IData::StoreNoOffset { args, .. } => (vec![args[0], args[1]], vec![]),
            IData::Nop => (vec![], vec![]),
        }
    }
}

/// Configuration for register allocation
#[derive(Clone, Debug)]
pub struct RegAllocConfig {
    /// Total number of registers available
    pub total_registers: u32,
    /// Number of registers reserved for return values (r0-r7)
    pub return_registers: u32,
    /// Number of function arguments (reserves r8..r8+arg_count)
    pub argument_count: u32,
    /// Enable/disable register coalescing optimizations
    pub enable_coalescing: bool,
    /// Spill cost threshold - higher values prefer registers over spilling
    pub spill_cost_threshold: f32,
}

#[allow(unused)]
impl RegAllocConfig {
    fn new(argument_count: u32) -> Self {
        Self {
            argument_count,
            total_registers: 256,
            return_registers: 8,
            enable_coalescing: true,
            spill_cost_threshold: 10.0,
        }
    }
}

/// Represents a live interval for a value
#[derive(Clone, Debug)]
pub struct LiveInterval {
    pub value: Value,
    pub start: u32,
    pub end: u32,
    pub spill_cost: f32,
    pub reg: Option<u32>,
    pub spilled: bool,
    /// Positions where this value is used (for spill code placement)
    pub use_positions: Vec<u32>,
    /// Positions where this value is defined
    pub def_positions: Vec<u32>,
}

impl LiveInterval {
    fn new(value: Value, start: u32, end: u32) -> Self {
        Self {
            value,
            start,
            end,
            spill_cost: 0.0,
            reg: None,
            spilled: false,
            use_positions: Vec::new(),
            def_positions: Vec::new(),
        }
    }

    fn overlaps(&self, other: &LiveInterval) -> bool {
        self.start < other.end && other.start < self.end
    }

    fn length(&self) -> u32 {
        self.end - self.start
    }
}

#[derive(Clone, Debug)]
pub enum SpillOp {
    /// Load value from spill slot before use
    Load { value: Value, before_pos: u32 },
    /// Store value to spill slot after def
    Store { value: Value, after_pos: u32 },
}

/// Smart register allocator using linear scan with improvements
pub struct SmartRegisterAllocator {
    pub config: RegAllocConfig,
    intervals: Vec<LiveInterval>,
    position_counter: u32,

    /// Final register assignments
    pub assignments: HashMap<Value, u32>,
    /// Values that need to be spilled
    pub spilled_values: HashSet<Value>,
    /// Spill code insertions: (position, spill_ops)
    pub spill_insertions: BTreeMap<u32, Vec<SpillOp>>,
    /// Pre-assigned registers (e.g., function arguments)
    pub pre_assigned: HashMap<Value, u32>,
}

impl SmartRegisterAllocator {
    pub fn new(config: RegAllocConfig) -> Self {
        Self {
            config,
            intervals: Vec::new(),
            position_counter: 0,
            assignments: HashMap::new(),
            spilled_values: HashSet::new(),
            spill_insertions: BTreeMap::new(),
            pre_assigned: HashMap::new(),
        }
    }

    /// Main entry point: allocate registers for the given liveness information
    pub fn allocate(&mut self, func: &SsaFunc) {
        #[cfg(debug_assertions)]
        println!("Starting register allocation with {} blocks", func.cfg.blocks.len());

        for param in 0..func.signature.params.len() {
            let value = func.cfg.blocks[0].params[param];
            self.pre_assigned.insert(value, param as u32 + self.config.return_registers);
        }

        // 1. Build live intervals from liveness analysis
        self.build_intervals(func);

        #[cfg(debug_assertions)]
        println!("Built {} intervals", self.intervals.len());

        // 2. Calculate spill costs
        self.calculate_spill_costs();

        // 3. Optional: coalesce intervals for move elimination
        if self.config.enable_coalescing {
            self.coalesce_intervals(func);
        }

        println!("PRE ASSIGNED: {:#?}", self.pre_assigned);

        // 4. Sort intervals by start position
        self.intervals.sort_by_key(|i| i.start);

        #[cfg(debug_assertions)]
        {
            println!("Live intervals:");
            for (i, interval) in self.intervals.iter().enumerate() {
                println!("  {}: v{} [{}, {}) cost={:.2}",
                    i, interval.value.index(), interval.start, interval.end, interval.spill_cost);
            }
        }

        // 5. Linear scan register allocation
        self.linear_scan();

        #[cfg(debug_assertions)]
        {
            println!("Register assignments:");
            for (value, reg) in &self.assignments {
                println!("  v{} -> r{}", value.index(), reg);
            }
            println!("Spilled values: {:?}", self.spilled_values.iter().map(|v| v.index()).collect::<Vec<_>>());
        }

        // 6. Insert spill code where needed
        self.generate_spill_code();
    }

    fn build_intervals(&mut self, func: &SsaFunc) {
        let mut value_ranges: HashMap<Value, (u32, u32)> = HashMap::new();
        let mut value_uses: HashMap<Value, Vec<u32>> = HashMap::new();
        let mut value_defs: HashMap<Value, Vec<u32>> = HashMap::new();

        self.position_counter = 0;

        // Walk through all blocks in a consistent order
        for block_idx in 0..func.cfg.blocks.len() {
            let block_id = Block::new(block_idx);
            let block_data = &func.cfg.blocks[block_id.index()];

            for &inst_id in &block_data.insts {
                let inst_data = &func.dfg.insts[inst_id.index()];
                let (uses, defs) = LoweringContext::inst_uses_defs(inst_id, &func.dfg, inst_data);

                // Record uses
                for &val in &uses {
                    let entry = value_ranges.entry(val).or_insert((u32::MAX, 0));
                    entry.0 = entry.0.min(self.position_counter);
                    entry.1 = entry.1.max(self.position_counter);
                    value_uses.entry(val).or_default().push(self.position_counter);
                }

                // Record defs
                for &val in &defs {
                    let entry = value_ranges.entry(val).or_insert((u32::MAX, 0));
                    entry.0 = entry.0.min(self.position_counter);
                    entry.1 = entry.1.max(self.position_counter);
                    value_defs.entry(val).or_default().push(self.position_counter);
                }

                self.position_counter += 1;
            }
        }

        // Create intervals
        for (value, (start, end)) in value_ranges {
            if start == u32::MAX { continue; } // unused value

            let mut interval = LiveInterval::new(value, start, end + 1);
            interval.use_positions = value_uses.get(&value).cloned().unwrap_or_default();
            interval.def_positions = value_defs.get(&value).cloned().unwrap_or_default();

            self.intervals.push(interval);
        }
    }

    fn calculate_spill_costs(&mut self) {
        for interval in &mut self.intervals {
            // Pre-assigned values should never be spilled
            if self.pre_assigned.contains_key(&interval.value) {
                interval.spill_cost = f32::INFINITY;
                continue;
            }

            let mut cost = 0.0;

            // Base cost: number of uses + defs
            cost += (interval.use_positions.len() + interval.def_positions.len()) as f32;

            // Length penalty: longer intervals are cheaper to spill
            cost /= (interval.length() as f32).max(1.0);

            // Loop depth bonus (simplified: assume all instructions have same weight)
            // In a real implementation, you'd analyze loop nesting

            // Call crossing penalty: values live across calls are more expensive to keep in registers
            // since they need to be preserved anyway
            cost *= 0.8; // slight preference for spilling call-crossing values

            interval.spill_cost = cost;
        }
    }

    fn coalesce_intervals(&mut self, func: &SsaFunc) {
        fn is_move(inst_id: Inst, func: &SsaFunc) -> Option<(Value, Value)> {
            let inst_data = &func.dfg.insts[inst_id.index()];
            match inst_data {
                IData::Binary { args, .. } => {
                    if let Some(results) = func.dfg.inst_results.get(&inst_id) {
                        if results.len() == 1 {
                            return Some((args[0], results[0]));
                        }
                    }
                }
                _ => {}
            }
            None
        }

        // Look for move-like operations that can be coalesced
        // This is a simplified version - real coalescing is more complex
        let mut coalesce_candidates = Vec::new();

        for block_idx in 0..func.cfg.blocks.len() {
            let block_id = Block::new(block_idx);
            let block_data = &func.cfg.blocks[block_id.index()];

            for &inst_id in &block_data.insts {
                if let Some((src, dst)) = is_move(inst_id, func) {
                    // Don't coalesce with pre-assigned values
                    if !self.pre_assigned.contains_key(&src) && !self.pre_assigned.contains_key(&dst) {
                        coalesce_candidates.push((src, dst));
                    }
                }
            }
        }

        // Apply coalescing (simplified)
        for (src, dst) in coalesce_candidates {
            if let (Some(src_idx), Some(dst_idx)) = (
                self.intervals.iter().position(|i| i.value == src),
                self.intervals.iter().position(|i| i.value == dst)
            ) {
                if src_idx != dst_idx && !self.intervals[src_idx].overlaps(&self.intervals[dst_idx]) {
                    // Merge intervals
                    let src_interval = self.intervals.remove(src_idx.max(dst_idx));
                    let dst_idx = if src_idx > dst_idx { dst_idx } else { dst_idx - 1 };

                    self.intervals[dst_idx].start = self.intervals[dst_idx].start.min(src_interval.start);
                    self.intervals[dst_idx].end = self.intervals[dst_idx].end.max(src_interval.end);
                    self.intervals[dst_idx].use_positions.extend(src_interval.use_positions);
                    self.intervals[dst_idx].def_positions.extend(src_interval.def_positions);
                    self.intervals[dst_idx].spill_cost += src_interval.spill_cost;
                }
            }
        }
    }

    fn linear_scan(&mut self) {
        let mut active = Vec::new(); // indices into self.intervals

        // Track which registers are in use
        let mut used_regs = HashSet::new();

        // Mark pre-assigned registers as used
        for &reg in self.pre_assigned.values() {
            used_regs.insert(reg);
        }

        // Calculate available register range
        // Skip return registers (r0-r7) and argument registers (r8..r8+arg_count)
        let first_available = self.config.return_registers + self.config.argument_count;

        // Build free register pool
        let mut free_regs = Vec::new();
        for reg in first_available..self.config.total_registers {
            if !used_regs.contains(&reg) {
                free_regs.push(reg);
            }
        }
        free_regs.reverse(); // Use lower register numbers first

        // Process pre-assigned intervals first
        for i in 0..self.intervals.len() {
            if let Some(&pre_reg) = self.pre_assigned.get(&self.intervals[i].value) {
                self.intervals[i].reg = Some(pre_reg);
                active.push(i);
            }
        }

        // Process remaining intervals
        for i in 0..self.intervals.len() {
            // Skip if already pre-assigned
            if self.pre_assigned.contains_key(&self.intervals[i].value) {
                continue;
            }

            let current_start = self.intervals[i].start;

            // Expire old intervals (but not pre-assigned ones)
            active.retain(|&idx| {
                if self.intervals[idx].end <= current_start {
                    // Only return the register to the pool if it's not pre-assigned
                    if !self.pre_assigned.contains_key(&self.intervals[idx].value) {
                        if let Some(reg) = self.intervals[idx].reg {
                            // Only add back if it's in the allocatable range
                            if reg >= first_available {
                                free_regs.push(reg);
                                free_regs.sort_unstable();
                                free_regs.reverse();
                            }
                        }
                    }
                    false
                } else {
                    true
                }
            });

            // Try to assign a register
            if let Some(reg) = free_regs.pop() {
                self.intervals[i].reg = Some(reg);
                active.push(i);
            } else {
                // Need to spill
                self.spill_at_interval(i, &mut active);
            }
        }

        // Build final assignments
        for interval in &self.intervals {
            if let Some(reg) = interval.reg {
                self.assignments.insert(interval.value, reg);
            } else {
                self.spilled_values.insert(interval.value);
            }
        }
    }

    fn spill_at_interval(&mut self, current: usize, active: &mut Vec<usize>) {
        // Find the active interval with the highest spill cost (lowest priority)
        // BUT never spill pre-assigned values
        let spill_candidate = active.iter()
            .filter(|&&idx| !self.pre_assigned.contains_key(&self.intervals[idx].value))
            .max_by(|&&a, &&b| {
                // Compare by end position first (spill the one that ends latest)
                let end_cmp = self.intervals[a].end.cmp(&self.intervals[b].end);
                if end_cmp != Ordering::Equal {
                    return end_cmp;
                }
                // Then by spill cost (spill the cheapest)
                self.intervals[a].spill_cost.partial_cmp(&self.intervals[b].spill_cost)
                    .unwrap_or(Ordering::Equal)
            }).copied();

        if let Some(spill_idx) = spill_candidate {
            // Check if it's better to spill the current interval instead
            if self.intervals[spill_idx].end > self.intervals[current].end &&
               self.intervals[current].spill_cost < self.config.spill_cost_threshold {

                // Spill the candidate
                let reg = self.intervals[spill_idx].reg.take().unwrap();
                self.intervals[spill_idx].spilled = true;
                self.intervals[current].reg = Some(reg);

                // Replace spilled interval with current in active list
                let pos = active.iter().position(|&x| x == spill_idx).unwrap();
                active[pos] = current;
            } else {
                // Spill current interval
                self.intervals[current].spilled = true;
            }
        } else {
            // No active intervals to spill, current must be spilled
            self.intervals[current].spilled = true;
        }
    }

    fn generate_spill_code(&mut self) {
        for interval in &self.intervals {
            if interval.spilled {
                // Generate loads before uses
                for &use_pos in &interval.use_positions {
                    self.spill_insertions.entry(use_pos)
                        .or_default()
                        .push(SpillOp::Load {
                            value: interval.value,
                            before_pos: use_pos
                        });
                }

                // Generate stores after defs
                for &def_pos in &interval.def_positions {
                    self.spill_insertions.entry(def_pos)
                        .or_default()
                        .push(SpillOp::Store {
                            value: interval.value,
                            after_pos: def_pos
                        });
                }
            }
        }
    }

    /// Get the register assigned to a value, if any
    pub fn get_register(&self, value: Value) -> Option<u32> {
        self.assignments.get(&value).copied()
    }

    /// Check if a value was spilled
    pub fn is_spilled(&self, value: Value) -> bool {
        self.spilled_values.contains(&value)
    }

    /// Get statistics about the allocation
    pub fn stats(&self) -> RegAllocStats {
        RegAllocStats {
            total_intervals: self.intervals.len(),
            allocated_registers: self.assignments.len(),
            spilled_values: self.spilled_values.len(),
            spill_operations: self.spill_insertions.values().map(|v| v.len()).sum(),
        }
    }
}

#[derive(Debug)]
pub struct RegAllocStats {
    pub total_intervals: usize,
    pub allocated_registers: usize,
    pub spilled_values: usize,
    pub spill_operations: usize,
}

