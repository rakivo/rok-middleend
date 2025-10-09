use crate::util;
use crate::entity::EntityRef;
use crate::ssa::{self, Value, SsaFunc, InstructionData, Block as SsaBlock};

use rustc_hash::{FxHashSet, FxHashMap};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

pub const REG_COUNT   : u8 = 63;
pub const SCRATCH_REG : u8 = REG_COUNT + 1;

#[inline(always)]
const fn int_preg(index: u8) -> PReg {
    PReg { index }
}

// PReg with required derives for BinaryHeap
#[derive(Hash, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PReg {
    index: u8,
}

impl EntityRef for PReg {
    fn new(index: usize) -> Self {
        Self { index: index as _ }
    }

    fn index(self) -> usize {
        self.index as _
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SpillSlot {
    index: usize,
}

// Machine environment
pub struct MachineEnv {
    preferred_regs: Vec<PReg>,
    non_preferred_regs: Vec<PReg>,
}

impl MachineEnv {
    pub fn new() -> Self {
        Self {
            preferred_regs: (8..REG_COUNT).map(int_preg).collect(),
            non_preferred_regs: (0..8).map(int_preg).collect(),
        }
    }
}

// Adapter for linear scan
pub struct CustomAllocAdapter<'a> {
    func: &'a ssa::SsaFunc,
    block_order: Vec<ssa::Block>,
    entry_param_pregs: FxHashMap<Value, PReg>,
    value_defs: FxHashMap<Value, usize>, // inst index or block index for params
    value_uses: FxHashMap<Value, Vec<usize>>, // inst indices where used
    inst_positions: FxHashMap<usize, u32>, // inst index -> position
    block_positions: FxHashMap<usize, u32>, // block index -> start position
    is_call: FxHashMap<usize, bool>, // inst index -> is call
}

impl<'a> CustomAllocAdapter<'a> {
    pub fn new(func: &'a ssa::SsaFunc) -> Self {
        let mut adapter = Self {
            func,
            block_order: Vec::new(),
            entry_param_pregs: FxHashMap::default(),
            value_defs: FxHashMap::default(),
            value_uses: FxHashMap::default(),
            inst_positions: FxHashMap::default(),
            block_positions: FxHashMap::default(),
            is_call: FxHashMap::default(),
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
                if !block_data.insts.is_empty() || self.func.layout.block_entry == Some(block) {
                    self.block_order.push(block);
                }

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
                if !used_regs.insert(preg) {
                    panic!("Duplicate fixed register r{i} for entry param")
                }
                self.entry_param_pregs.insert(param, preg);
                self.value_defs.insert(param, entry.index());
            }
            if block_data.params.len() > 8 {
                unimplemented!("Parameters beyond 8 not supported")
            }
        }
    }

    fn compute_defs_uses_and_positions(&mut self) {
        let mut current_pos: u32 = 0;
        // SAFETY: self.block_order is not modified in this function
        let block_order = unsafe { util::reborrow(&self.block_order) };

        for &block in block_order {
            let block_idx = block.index();
            self.block_positions.insert(block_idx, current_pos);

            let block_data = &self.func.cfg.blocks[block_idx];
            for &param in &block_data.params {
                if !self.entry_param_pregs.contains_key(&param) {
                    self.value_defs.insert(param, block_idx);
                }
            }
            current_pos += 1;

            for &inst in &block_data.insts {
                let inst_idx = inst.index();
                self.inst_positions.insert(inst_idx, current_pos);
                current_pos += 2;

                let inst_data = &self.func.dfg.insts[inst_idx];

                if matches!{
                    inst_data,
                    InstructionData::Call { .. } |
                    InstructionData::CallExt { .. } |
                    InstructionData::CallIntrin { .. }
                } {
                    self.is_call.insert(inst_idx, true);
                }

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
                    InstructionData::CallIntrin { args, .. } => {
                        for (i, &arg) in args.iter().enumerate().take(8) {
                            self.add_use(arg, inst_idx);
                            self.value_defs.insert(arg, inst_idx);
                            self.entry_param_pregs.insert(arg, int_preg(i as u8));
                        }
                    }
                    InstructionData::Return { args, .. } => {
                        for (i, &arg) in args.iter().enumerate().take(8) {
                            self.add_use(arg, inst_idx);
                            self.value_defs.insert(arg, inst_idx);
                            self.entry_param_pregs.insert(arg, int_preg(i as u8));
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

        let start = if adapter.block_positions.contains_key(def_loc) {
            adapter.block_positions[def_loc]
        } else {
            adapter.inst_positions[def_loc] + 1
        };

        let end = if uses.is_empty() {
            start
        } else {
            uses.iter().map(|&u| adapter.inst_positions[&u]).max().unwrap() + 1
        };

        intervals.push(Interval {
            value: *value,
            start,
            end,
            fixed_reg: None,
            use_count: uses.len()
        });
    }

    intervals.sort_by_key(|i| (i.start, Reverse(i.use_count)));

    let mut active = BinaryHeap::new();
    let mut free_preferred = machine_env.preferred_regs.iter().cloned().collect::<FxHashSet<_>>();
    let mut free_non_preferred = machine_env.non_preferred_regs.iter().cloned().collect::<FxHashSet<_>>();
    let mut allocs = FxHashMap::default();
    let mut spills = Vec::new();

    for interval in intervals {
        while let Some(Reverse((end, _))) = active.peek() {
            if *end > interval.start {
                break;
            }
            let Reverse((_, reg)) = active.pop().unwrap();
            if machine_env.preferred_regs.contains(&reg) {
                free_preferred.insert(reg);
            } else {
                free_non_preferred.insert(reg);
            }
        }

        let assigned = if let Some(fixed) = interval.fixed_reg {
            Some(fixed)
        } else if !free_preferred.is_empty() {
            let reg = free_preferred.iter().next().cloned().unwrap();
            free_preferred.remove(&reg);
            Some(reg)
        } else if !free_non_preferred.is_empty() {
            let reg = free_non_preferred.iter().next().cloned().unwrap();
            free_non_preferred.remove(&reg);
            Some(reg)
        } else {
            None
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

    for (value, preg) in &adapter.entry_param_pregs {
        allocs.insert(*value, *preg);
    }

    let output = RegAllocOutput {
        allocs,
        spills,
        entry_param_pregs: adapter.entry_param_pregs,
    };

    Ok((adapter.block_order, output))
}
