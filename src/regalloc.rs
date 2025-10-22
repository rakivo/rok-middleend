use crate::util;
use crate::entity::EntityRef;
use crate::ssa::{self, Value, SsaFunc, InstructionData, Block as SsaBlock};

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use rustc_hash::{FxHashSet, FxHashMap};

// Simplified register allocator with caller/callee-saved conventions
//
// Register convention (similar to x86-64 System V ABI):
// - r0-r7:   argument/return registers (caller-saved)
// - r8-r31:  general purpose caller-saved
// - r32-r62: callee-saved (preserved across calls)
// - r63:     scratch register

pub const REG_COUNT: u8 = 63;
pub const SCRATCH_REG: u8 = REG_COUNT + 1;

// Sentinel value for entry parameter definitions
const ENTRY_PARAM_DEF: usize = usize::MAX;

#[inline(always)]
const fn int_preg(index: u8) -> PReg {
    PReg { index }
}

#[derive(Hash, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PReg {
    index: u8,
}

impl EntityRef for PReg {
    #[inline(always)]
    fn new(index: usize) -> Self {
        Self { index: index as _ }
    }

    #[inline(always)]
    fn index(self) -> usize { self.index as _ }
}

#[inline(always)]
pub fn is_caller_saved(reg: u8) -> bool {
    reg < 32  // r0-r31
}

#[inline(always)]
pub fn is_callee_saved(reg: u8) -> bool {
    reg >= 32 && reg < REG_COUNT  // r32-r62
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SpillSlot {
    pub index: usize,
}

pub struct MachineEnv {
    /// r32-r62: callee-saved (preserved across calls)
    callee_saved_regs: Vec<PReg>,
    /// r8-r31: caller-saved general purpose
    caller_saved_general: Vec<PReg>,
    /// r0-r7: argument/return registers (also caller-saved)
    arg_regs: Vec<PReg>,
}

impl Default for MachineEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl MachineEnv {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            callee_saved_regs: (32..REG_COUNT).map(int_preg).collect(),
            caller_saved_general: (8..32).map(int_preg).collect(),
            arg_regs: (0..8).map(int_preg).collect(),
        }
    }
}

pub struct CustomAllocAdapter<'a> {
    func: &'a ssa::SsaFunc,
    block_order: Vec<ssa::Block>,
    entry_param_pregs: FxHashMap<Value, PReg>,
    value_defs: FxHashMap<Value, usize>,
    value_uses: FxHashMap<Value, Vec<usize>>,
    inst_positions: FxHashMap<usize, u32>,
    block_positions: FxHashMap<usize, u32>,
    /// Program positions where calls occur
    call_positions: Vec<u32>,
}

impl<'a> CustomAllocAdapter<'a> {
    #[must_use]
    pub fn new(func: &'a ssa::SsaFunc) -> Self {
        let mut adapter = Self {
            func,
            block_order: Vec::new(),
            entry_param_pregs: FxHashMap::default(),
            value_defs: FxHashMap::default(),
            value_uses: FxHashMap::default(),
            inst_positions: FxHashMap::default(),
            block_positions: FxHashMap::default(),
            call_positions: Vec::new(),
        };

        adapter.compute_block_order();
        adapter.compute_entry_params();
        adapter.compute_defs_uses_and_positions();
        adapter
    }

    fn compute_block_order(&mut self) {
        if let Some(entry) = self.func.layout.block_entry {
            let mut visited = FxHashSet::default();
            let mut stack = vec![entry];

            while let Some(block) = stack.pop() {
                if visited.contains(&block) { continue; }
                visited.insert(block);
                self.block_order.push(block);

                let block_data = &self.func.cfg.blocks[block.index()];

                if let Some(&last_inst) = block_data.insts.last() {
                    match &self.func.dfg.insts[last_inst.index()] {
                        InstructionData::Jump { destination, .. } => {
                            if !visited.contains(destination) {
                                stack.push(*destination);
                            }
                        }
                        InstructionData::Branch { destinations, .. } => {
                            for dest in destinations.iter().rev() {
                                if !visited.contains(dest) {
                                    stack.push(*dest);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn compute_entry_params(&mut self) {
        if let Some(entry) = self.func.layout.block_entry {
            let block_data = &self.func.cfg.blocks[entry.index()];
            let mut used_regs = FxHashSet::default();
            for (i, &param) in block_data.params.iter().enumerate().take(8) {
                let preg = int_preg(i as _);
                assert!(used_regs.insert(preg), "Duplicate fixed register r{i} for entry param");
                self.entry_param_pregs.insert(param, preg);
            }
            if block_data.params.len() > 8 {
                unimplemented!("Parameters beyond 8 not supported")
            }
        }
    }

    fn compute_defs_uses_and_positions(&mut self) {
        let mut current_pos: u32 = 0;
        let block_order = unsafe { util::reborrow(&self.block_order) };

        for &block in block_order {
            let block_idx = block.index();
            self.block_positions.insert(block_idx, current_pos);

            let block_data = &self.func.cfg.blocks[block_idx];
            for &param in &block_data.params {
                if self.entry_param_pregs.contains_key(&param) {
                    self.value_defs.insert(param, ENTRY_PARAM_DEF);
                } else {
                    self.value_defs.insert(param, block_idx);
                }
            }
            current_pos += 1;

            for &inst in &block_data.insts {
                let inst_idx = inst.index();
                self.inst_positions.insert(inst_idx, current_pos);

                let inst_data = &self.func.dfg.insts[inst_idx];

                // Track call positions
                if matches!(inst_data,
                    InstructionData::Call { .. } |
                    InstructionData::CallExt { .. } |
                    InstructionData::CallHook { .. }
                ) {
                    self.call_positions.push(current_pos);
                }

                current_pos += 2;

                match inst_data {
                    InstructionData::Binary { args, .. } => {
                        self.add_use(args[0], inst_idx);
                        self.add_use(args[1], inst_idx);
                    }
                    InstructionData::Icmp { args, .. } => {
                        self.add_use(args[0], inst_idx);
                        self.add_use(args[1], inst_idx);
                    }
                    InstructionData::Unary { arg, .. } => {
                        self.add_use(*arg, inst_idx);
                    }
                    InstructionData::Call { args, .. } |
                    InstructionData::CallExt { args, .. } |
                    InstructionData::CallHook { args, .. } => {
                        for &arg in args.iter().take(8) {
                            self.add_use(arg, inst_idx);
                        }
                    }
                    InstructionData::Return { args, .. } => {
                        for &arg in args.iter().take(8) {
                            self.add_use(arg, inst_idx);
                        }
                    }
                    InstructionData::Jump { args, .. } => {
                        for &arg in args {
                            self.add_use(arg, inst_idx);
                        }
                    }
                    InstructionData::Branch { arg, args, .. } => {
                        self.add_use(*arg, inst_idx);
                        for &a in args {
                            self.add_use(a, inst_idx);
                        }
                    }
                    InstructionData::StackStore { arg, .. } => {
                        self.add_use(*arg, inst_idx);
                    }
                    InstructionData::LoadNoOffset { addr, .. } => {
                        self.add_use(*addr, inst_idx);
                    }
                    InstructionData::StoreNoOffset { args, .. } => {
                        self.add_use(args[0], inst_idx);
                        self.add_use(args[1], inst_idx);
                    }
                    _ => {}
                }

                if let Some(results) = self.func.dfg.inst_results.get(&inst) {
                    for &result in results {
                        self.value_defs.insert(result, inst_idx);
                    }
                }
            }
        }
    }

    fn add_use(&mut self, value: Value, inst_idx: usize) {
        self.value_uses.entry(value).or_default().push(inst_idx);
    }
}

#[derive(Debug, Clone)]
struct Interval {
    value: Value,
    start: u32,
    end: u32,
    fixed_reg: Option<PReg>,
    use_count: usize,
    crosses_call: bool,
}

#[derive(Debug)]
pub struct RegAllocOutput {
    pub allocs: FxHashMap<Value, PReg>,
    pub spills: Vec<(Value, SpillSlot)>,
    pub entry_param_pregs: FxHashMap<Value, PReg>,
}

type RegAllocResult = Result<(Vec<SsaBlock>, RegAllocOutput), String>;

pub fn allocate_registers_custom(func: &SsaFunc) -> RegAllocResult {
    let adapter = CustomAllocAdapter::new(func);
    let machine_env = MachineEnv::new();

    let mut intervals = Vec::new();
    let mut spill_slot_index = 0;

    for (value, def_loc) in &adapter.value_defs {
        if adapter.entry_param_pregs.contains_key(value) {
            continue;
        }

        let uses = adapter.value_uses.get(value).cloned().unwrap_or_default();

        let start = if *def_loc == ENTRY_PARAM_DEF {
            0
        } else if adapter.inst_positions.contains_key(def_loc) {
            adapter.inst_positions[def_loc] + 1
        } else if adapter.block_positions.contains_key(def_loc) {
            adapter.block_positions[def_loc]
        } else {
            panic!("Value {value:?} has unknown def_loc {def_loc}");
        };

        let end = if uses.is_empty() {
            start
        } else {
            uses.iter().map(|&u| adapter.inst_positions[&u]).max().unwrap() + 1
        };

        // Check if this interval crosses any calls
        let crosses = adapter.call_positions.iter()
            .any(|&call_pos| call_pos > start && call_pos < end);

        let fixed_reg = adapter.entry_param_pregs.get(value).copied();

        intervals.push(Interval {
            value: *value,
            start,
            end,
            fixed_reg,
            use_count: uses.len(),
            crosses_call: crosses,
        });
    }

    intervals.sort_by_key(|i| (i.start, Reverse(i.use_count)));

    let mut active = BinaryHeap::new();
    let mut free_callee_saved = machine_env.callee_saved_regs.iter()
        .copied()
        .collect::<FxHashSet<_>>();
    let mut free_caller_saved = machine_env.caller_saved_general.iter()
        .copied()
        .collect::<FxHashSet<_>>();
    let mut free_arg_regs = machine_env.arg_regs.iter()
        .copied()
        .collect::<FxHashSet<_>>();

    let mut allocs = FxHashMap::default();
    let mut spills = Vec::new();

    for interval in intervals {
        // Expire old intervals
        while let Some(Reverse((end, _))) = active.peek() {
            if *end > interval.start {
                break;
            }
            let Reverse((_, reg)) = active.pop().unwrap();
            if machine_env.callee_saved_regs.contains(&reg) {
                free_callee_saved.insert(reg);
            } else if machine_env.caller_saved_general.contains(&reg) {
                free_caller_saved.insert(reg);
            } else {
                free_arg_regs.insert(reg);
            }
        }

        let assigned = if let Some(fixed) = interval.fixed_reg {
            // Entry parameters stay in r0-r7
            Some(fixed)
        } else if interval.crosses_call {
            // Prefer callee-saved registers (no save/restore needed)
            if let Some(&reg) = free_callee_saved.iter().next() {
                free_callee_saved.remove(&reg);
                Some(reg)
            } else if let Some(&reg) = free_caller_saved.iter().next() {
                free_caller_saved.remove(&reg);
                Some(reg)
            } else if let Some(&reg) = free_arg_regs.iter().next() {
                free_arg_regs.remove(&reg);
                Some(reg)
            } else {
                None
            }
        } else {
            // Doesn't cross calls - prefer caller-saved (more available)
            if let Some(&reg) = free_caller_saved.iter().next() {
                free_caller_saved.remove(&reg);
                Some(reg)
            } else if let Some(&reg) = free_arg_regs.iter().next() {
                free_arg_regs.remove(&reg);
                Some(reg)
            } else if let Some(&reg) = free_callee_saved.iter().next() {
                free_callee_saved.remove(&reg);
                Some(reg)
            } else {
                None
            }
        };

        if let Some(reg) = assigned {
            allocs.insert(interval.value, reg);
            active.push(Reverse((interval.end, reg)));
        } else {
            let slot = SpillSlot { index: spill_slot_index };
            spill_slot_index += 1;
            spills.push((interval.value, slot));
        }
    }

    let output = RegAllocOutput {
        allocs,
        spills,
        entry_param_pregs: adapter.entry_param_pregs,
    };

    Ok((adapter.block_order, output))
}
