use crate::util;
use crate::entity::EntityRef;
use crate::ssa::{self, Value, SsaFunc, InstructionData, Block as SsaBlock, FuncId};

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use smallvec::SmallVec;
use rustc_hash::{FxHashSet, FxHashMap};

pub const REG_COUNT   : u8 = 63;
pub const SCRATCH_REG : u8 = REG_COUNT + 1;

// Sentinel value for entry parameter definitions
const ENTRY_PARAM_DEF: usize = usize::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct RegMask(pub u128);

pub type RegMaskMap = FxHashMap<FuncId, RegMask>;

impl RegMask {
    #[inline(always)]
    pub const fn empty() -> Self { Self(0) }

    #[inline(always)]
    pub const fn full() -> Self { Self(u128::MAX) }

    #[inline(always)]
    pub fn set(&mut self, reg_index: u8) {
        debug_assert!(reg_index < 128);
        self.0 |= 1u128 << reg_index;
    }

    #[inline(always)]
    pub fn contains(&self, reg_index: u8) -> bool {
        debug_assert!(reg_index < 128);
        (self.0 & (1u128 << reg_index)) != 0
    }

    #[inline(always)]
    pub fn union(self, other: Self) -> Self { Self(self.0 | other.0) }

    #[inline(always)]
    pub fn subtract(self, other: Self) -> Self { Self(self.0 & !other.0) }

    /// Convenience: r0-r7 set (args/returns clobbered)
    #[inline(always)]
    pub const fn args_and_returns() -> Self {
        Self(0xFF)
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SpillSlot {
    pub index: usize,
}

pub struct MachineEnv {
    preferred_regs: Vec<PReg>,
    non_preferred_regs: Vec<PReg>,
}

impl MachineEnv {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            preferred_regs: (8..REG_COUNT).map(int_preg).collect(),
            non_preferred_regs: (0..8).map(int_preg).collect(),
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
    is_call: FxHashMap<usize, bool>,
    call_masks: Vec<(u32, RegMask)>,
    func_clobber_masks: &'a RegMaskMap,
    call_arg_map: Vec<(u32, SmallVec<[(Value, u8); 8]>)>,
}

impl<'a> CustomAllocAdapter<'a> {
    pub fn new(func: &'a ssa::SsaFunc, regmask_map: &'a RegMaskMap) -> Self {
        let mut adapter = Self {
            func,
            block_order: Vec::new(),
            entry_param_pregs: FxHashMap::default(),
            value_defs: FxHashMap::default(),
            value_uses: FxHashMap::default(),
            inst_positions: FxHashMap::default(),
            block_positions: FxHashMap::default(),
            is_call: FxHashMap::default(),
            call_masks: Vec::new(),
            func_clobber_masks: regmask_map,
            call_arg_map: Vec::new(),
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
                if !used_regs.insert(preg) {
                    panic!("Duplicate fixed register r{i} for entry param")
                }
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
                if !self.entry_param_pregs.contains_key(&param) {
                    self.value_defs.insert(param, block_idx);
                } else {
                    self.value_defs.insert(param, ENTRY_PARAM_DEF);
                }
            }
            current_pos += 1;

            for &inst in &block_data.insts {
                let inst_idx = inst.index();
                self.inst_positions.insert(inst_idx, current_pos);
                current_pos += 2;

                let inst_data = &self.func.dfg.insts[inst_idx];

                if matches!(inst_data,
                    InstructionData::Call { .. } |
                    InstructionData::CallExt { .. } |
                    InstructionData::CallHook { .. }
                ) {
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
                    InstructionData::CallHook { args, .. } => {
                        for &arg in args.iter().take(8) {
                            self.add_use(arg, inst_idx);
                        }

                        let pos = self.inst_positions[&inst_idx];
                        let mask = match inst_data {
                            InstructionData::Call { func_id, .. } => {
                                let callee = self.func_clobber_masks.get(func_id).unwrap();
                                callee.union(RegMask::args_and_returns())
                            }
                            InstructionData::CallExt { .. } => {
                                // External calls in VM don't clobber beyond arg registers
                                RegMask::args_and_returns()
                            }
                            InstructionData::CallHook { .. } => {
                                RegMask::args_and_returns()
                            }
                            _ => unreachable!()
                        };
                        self.call_masks.push((pos, mask));

                        let mut vec: SmallVec<[(Value, u8); 8]> = SmallVec::new();
                        for (i, &arg) in args.iter().enumerate().take(8) {
                            vec.push((arg, i as u8));
                        }
                        self.call_arg_map.push((pos, vec));
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
        self.call_masks.sort_by_key(|(p, _)| *p);
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
    clobber_union: RegMask,
    arg_conflict_mask: RegMask,
}

#[derive(Debug)]
pub struct RegAllocOutput {
    pub allocs: FxHashMap<Value, PReg>,
    pub spills: Vec<(Value, SpillSlot)>,
    pub entry_param_pregs: FxHashMap<Value, PReg>,
}

type RegAllocResult = Result<(Vec<SsaBlock>, RegAllocOutput), String>;

pub fn allocate_registers_custom(func: &SsaFunc, regmask_map: &RegMaskMap) -> RegAllocResult {
    let adapter = CustomAllocAdapter::new(func, regmask_map);
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
            panic!("Value {:?} has unknown def_loc {}", value, def_loc);
        };

        let end = if uses.is_empty() {
            start
        } else {
            uses.iter().map(|&u| adapter.inst_positions[&u]).max().unwrap() + 1
        };

        let mut crosses = false;
        let mut clobber_union = RegMask::empty();
        let mut arg_conflict_mask = RegMask::empty();

        for &(p, m) in &adapter.call_masks {
            if p > start && p < end {
                if let Some(last_use) = uses.iter().map(|&u| adapter.inst_positions[&u]).max() {
                    if last_use > p {
                        crosses = true;
                        clobber_union = clobber_union.union(m);
                    }
                }
            }
        }

        for &(p, ref vec) in &adapter.call_arg_map {
            if p > start && p < end {
                for &(arg_val, reg_idx) in vec {
                    if arg_val == *value {
                        arg_conflict_mask.set(reg_idx);
                    }
                }
            }
        }

        let fixed_reg = adapter.entry_param_pregs.get(value).cloned();

        intervals.push(Interval {
            value: *value,
            start,
            end,
            fixed_reg,
            use_count: uses.len(),
            crosses_call: crosses,
            clobber_union,
            arg_conflict_mask,
        });
    }

    intervals.sort_by_key(|i| (i.start, Reverse(i.use_count)));

    let mut active = BinaryHeap::new();
    let mut free_preferred = machine_env.preferred_regs.iter()
        .cloned()
        .collect::<FxHashSet<_>>();

    let mut free_non_preferred = machine_env.non_preferred_regs.iter()
        .cloned()
        .collect::<FxHashSet<_>>();

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

        let must_spill = if let Some(fixed_reg) = interval.fixed_reg {
            interval.crosses_call &&
            machine_env.non_preferred_regs.contains(&fixed_reg)
        } else {
            false
        };

        let assigned = if must_spill {
            None
        } else if let Some(fixed) = interval.fixed_reg {
            Some(fixed)
        } else if interval.crosses_call {
            let forbidden = interval.clobber_union.union(interval.arg_conflict_mask);
            if let Some(&reg) = free_preferred.iter().find(|r| !forbidden.contains(r.index as u8)) {
                free_preferred.remove(&reg);
                Some(reg)
            } else if let Some(&reg) = free_non_preferred.iter().find(|r| !forbidden.contains(r.index as u8)) {
                free_non_preferred.remove(&reg);
                Some(reg)
            } else {
                None
            }
        } else {
            if !free_preferred.is_empty() {
                let reg = free_preferred.iter().next().cloned().unwrap();
                free_preferred.remove(&reg);
                Some(reg)
            } else if !free_non_preferred.is_empty() {
                let reg = free_non_preferred.iter().next().cloned().unwrap();
                free_non_preferred.remove(&reg);
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

    debug_assert_eq!(adapter.block_order.len(), adapter.block_order.iter().collect::<FxHashSet<_>>().len());

    let output = RegAllocOutput {
        allocs,
        spills,
        entry_param_pregs: adapter.entry_param_pregs,
    };

    Ok((adapter.block_order, output))
}
