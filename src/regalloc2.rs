use crate::ssa;
use crate::entity::EntityRef;
use crate::ssa::{Value, SsaFunc, InstructionData};

use regalloc2::*;
use rustc_hash::{FxHashSet, FxHashMap};

pub const SCRATCH_REG: u8 = 63;

#[inline(always)]
const fn int_preg(index: u8) -> PReg {
    PReg::new(index as usize, RegClass::Int)
}

#[inline(always)]
const fn int_vreg(index: usize) -> VReg {
    VReg::new(index as usize, RegClass::Int)
}

/// Machine environment describing our register set
pub struct MachineEnv {
    pub scratch_by_class: [Option<PReg>; 1],
    pub preferred_regs_by_class: [Vec<PReg>; 1],
    pub non_preferred_regs_by_class: [Vec<PReg>; 1],
}

impl Default for MachineEnv {
    #[inline]
    fn default() -> Self { Self::new() }
}

impl MachineEnv {
    pub fn new() -> Self {
        // r0-r7 are return value registers (preferred for allocation)
        let preferred = (0..8).map(int_preg).collect();

        // r8-r62 are general purpose registers (non-preferred)
        let non_preferred = (8..63).map(int_preg).collect();

        Self {
            scratch_by_class: [Some(int_preg(SCRATCH_REG))],
            preferred_regs_by_class: [preferred],
            non_preferred_regs_by_class: [non_preferred],
        }
    }
}

/// Adapter to make our SSA IR work with regalloc2
pub struct RegAllocAdapter<'a> {
    func: &'a ssa::SsaFunc,
    block_order: Vec<ssa::Block>,
    block_succs: Vec<Vec<regalloc2::Block>>,
    block_preds: Vec<Vec<regalloc2::Block>>,
    inst_operands_cache: Vec<Vec<Operand>>,
}

impl<'a> RegAllocAdapter<'a> {
    #[must_use]
    pub fn new(func: &'a ssa::SsaFunc) -> Self {
        let mut adapter = Self {
            func,
            block_order: Vec::new(),
            block_succs: Vec::new(),
            block_preds: Vec::new(),
            inst_operands_cache: Vec::new(),
        };

        adapter.compute_block_order();
        adapter.compute_cfg_edges();
        adapter.compute_operands();
        adapter
    }

    #[inline(always)]
    fn value_to_vreg(value: Value) -> VReg {
        VReg::new(value.index(), RegClass::Int)
    }

    fn compute_block_order(&mut self) {
        // Traverse CFG starting from entry block
        if let Some(entry) = self.func.layout.block_entry {
            let mut visited = FxHashSet::default();
            let mut stack = vec![entry];

            while let Some(block) = stack.pop() {
                if visited.contains(&block) { continue }
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

    fn compute_cfg_edges(&mut self) {
        let num_blocks = self.block_order.len();
        self.block_succs = vec![Vec::new(); num_blocks];
        self.block_preds = vec![Vec::new(); num_blocks];

        for (block_idx, &block) in self.block_order.iter().enumerate() {
            let block_data = &self.func.cfg.blocks[block.index()];

            if let Some(&last_inst) = block_data.insts.last() {
                let succs = match &self.func.dfg.insts[last_inst.index()] {
                    InstructionData::Jump   { destination, .. }  => vec![*destination],
                    InstructionData::Branch { destinations, .. } => destinations.to_vec(),
                    _ => vec![],
                };

                for succ in succs {
                    if let Some(succ_idx) = self.block_order.iter().position(|&b| b == succ) {
                        let succ_block = Block::new(succ_idx);
                        self.block_succs[block_idx].push(succ_block);
                        self.block_preds[succ_idx].push(Block::new(block_idx));
                    }
                }
            }
        }
    }

    fn compute_operands(&mut self) {
        let total_insts = self.func.dfg.insts.len();
        self.inst_operands_cache = vec![Vec::new(); total_insts];

        for &block in &self.block_order {
            let block_data = &self.func.cfg.blocks[block.index()];

            for &inst in &block_data.insts {
                let inst_data = &self.func.dfg.insts[inst.index()];
                let mut operands = Vec::new();

                match inst_data {
                    InstructionData::Binary { args, .. } => {
                        operands.push(Operand::reg_use(Self::value_to_vreg(args[0])));
                        operands.push(Operand::reg_use(Self::value_to_vreg(args[1])));
                    }
                    InstructionData::Icmp { args, .. } => {
                        operands.push(Operand::reg_use(Self::value_to_vreg(args[0])));
                        operands.push(Operand::reg_use(Self::value_to_vreg(args[1])));
                    }
                    InstructionData::Unary { arg, .. } => {
                        operands.push(Operand::reg_use(Self::value_to_vreg(*arg)));
                    }
                    InstructionData::Call { args, .. } |
                    InstructionData::CallExt { args, .. } |
                    InstructionData::CallIntrin { args, .. } => {
                        for &arg in args {
                            operands.push(Operand::reg_use(Self::value_to_vreg(arg)));
                        }
                    }
                    InstructionData::Return { args, .. } => {
                        for &arg in args {
                            operands.push(Operand::reg_use(Self::value_to_vreg(arg)));
                        }
                    }
                    InstructionData::Jump { args, .. } => {
                        for &arg in args {
                            operands.push(Operand::reg_use(Self::value_to_vreg(arg)));
                        }
                    }
                    InstructionData::Branch { arg, args, .. } => {
                        operands.push(Operand::reg_use(Self::value_to_vreg(*arg)));
                        for &a in args {
                            operands.push(Operand::reg_use(Self::value_to_vreg(a)));
                        }
                    }
                    InstructionData::StackStore { arg, .. } => {
                        operands.push(Operand::reg_use(Self::value_to_vreg(*arg)));
                    }
                    InstructionData::LoadNoOffset { addr, .. } => {
                        operands.push(Operand::reg_use(Self::value_to_vreg(*addr)));
                    }
                    InstructionData::StoreNoOffset { args, .. } => {
                        operands.push(Operand::reg_use(Self::value_to_vreg(args[0])));
                        operands.push(Operand::reg_use(Self::value_to_vreg(args[1])));
                    }
                    _ => {}
                }

                if let Some(results) = self.func.dfg.inst_results.get(&inst) {
                    for &result in results {
                        operands.push(Operand::reg_def(Self::value_to_vreg(result)));
                    }
                }

                self.inst_operands_cache[inst.index()] = operands;
            }
        }
    }
}

impl Function for RegAllocAdapter<'_> {
    #[inline(always)]
    fn num_insts(&self) -> usize {
        self.func.dfg.insts.len()
    }

    #[inline(always)]
    fn num_blocks(&self) -> usize {
        self.block_order.len()
    }

    #[inline(always)]
    fn entry_block(&self) -> regalloc2::Block {
        Block::new(0)
    }

    #[inline]
    fn block_insns(&self, block: regalloc2::Block) -> InstRange {
        let our_block = self.block_order[block.index()];
        let block_data = &self.func.cfg.blocks[our_block.index()];

        if block_data.insts.is_empty() {
            return InstRange::new(Inst::new(0), Inst::new(0))
        }

        let first = block_data.insts[0].index();
        let last = block_data.insts.last().unwrap().index();

        InstRange::new(
            Inst::new(first),
            Inst::new(last + 1),
        )
    }

    #[inline(always)]
    fn block_succs(&self, block: regalloc2::Block) -> &[regalloc2::Block] {
        &self.block_succs[block.index()]
    }

    #[inline(always)]
    fn block_preds(&self, block: regalloc2::Block) -> &[regalloc2::Block] {
        &self.block_preds[block.index()]
    }

    #[inline]
    fn block_params(&self, block: regalloc2::Block) -> &[VReg] {
        let our_block = self.block_order[block.index()];
        let block_data = &self.func.cfg.blocks[our_block.index()];

        // SAFETY: We're casting &[Value] to &[VReg]. This is safe because:
        // 1. Value and VReg have the same memory layout (both are u32 wrappers)
        // 2. VReg::new just wraps the index, which is what Value contains
        // 3. We're only reading, not writing
        // This avoids allocation for every call
        let v = block_data.params.iter().map(|a| int_vreg(a.index())).collect::<Vec<_>>();
        Box::leak(v.into_boxed_slice())
    }

    #[inline(always)]
    fn is_ret(&self, insn: regalloc2::Inst) -> bool {
        matches!{
            self.func.dfg.insts[insn.index()],
            InstructionData::Return { .. }
        }
    }

    #[inline(always)]
    fn is_branch(&self, insn: regalloc2::Inst) -> bool {
        self.func.dfg.insts[insn.index()].is_terminator()
    }

    #[inline]
    fn branch_blockparams(
        &self,
        _block: Block,
        insn: Inst,
        _succ_idx: usize
    ) -> &[VReg] {
        let inst_data = &self.func.dfg.insts[insn.index()];

        match inst_data {
            InstructionData::Jump { args, .. } => {
                let v = args.iter().map(|a| int_vreg(a.index())).collect::<Vec<_>>();
                Box::leak(v.into_boxed_slice())
            }
            InstructionData::Branch { args, .. } => {
                let v = args.iter().map(|a| int_vreg(a.index())).collect::<Vec<_>>();
                Box::leak(v.into_boxed_slice())
            }
            _ => &[],
        }
    }

    #[inline(always)]
    fn inst_operands(&self, insn: regalloc2::Inst) -> &[Operand] {
        &self.inst_operands_cache[insn.index()]
    }

    #[inline(always)]
    fn inst_clobbers(&self, insn: regalloc2::Inst) -> PRegSet {
        // Calls clobber r0-r7 (return value registers)
        match self.func.dfg.insts[insn.index()] {
            InstructionData::Call { .. } |
            InstructionData::CallExt { .. } |
            InstructionData::CallIntrin { .. } => {
                let mut set = PRegSet::default();
                for i in 0..8 {
                    set.add(int_preg(i));
                }
                set
            }
            _ => PRegSet::default(),
        }
    }

    #[inline(always)]
    fn num_vregs(&self) -> usize {
        self.func.dfg.values.len()
    }

    #[inline(always)]
    fn spillslot_size(&self, _regclass: regalloc2::RegClass) -> usize {
        8 // All our registers are 64-bit max
    }
}

/// Result of register allocation
#[derive(Debug)]
pub struct RegAllocOutput {
    pub allocs: FxHashMap<Value, PReg>,
    pub spills: Vec<(Value, SpillSlot)>,
}

type RegAllocResult = Result<(Vec<ssa::Block>, RegAllocOutput), RegAllocError>;

/// Perform register allocation on a function
pub fn allocate_registers(func: &SsaFunc) -> RegAllocResult {
    let adapter = RegAllocAdapter::new(func);
    let machine_env = MachineEnv::new();

    // Create regalloc2 environment (3 register classes required by regalloc2)
    let env = regalloc2::MachineEnv {
        preferred_regs_by_class: [
            machine_env.preferred_regs_by_class[0].clone(),
            Vec::new(),
            Vec::new(),
        ],
        non_preferred_regs_by_class: [
            machine_env.non_preferred_regs_by_class[0].clone(),
            Vec::new(),
            Vec::new(),
        ],
        scratch_by_class: [
            machine_env.scratch_by_class[0],
            None,
            None
        ],
        fixed_stack_slots: Vec::new()
    };

    let output = regalloc2::run(
        &adapter,
        &env,
        &RegallocOptions::default()
    )?;

    let mut allocs = FxHashMap::default();
    allocs.reserve(output.allocs.len());

    let mut spills = Vec::with_capacity(output.allocs.len());

    for (vreg_idx, alloc) in output.allocs.iter().enumerate() {
        let value = Value::from_u32(vreg_idx as _);
        if let Some(preg) = alloc.as_reg() {
            allocs.insert(value, preg);
        } else if let Some(slot) = alloc.as_stack() {
            spills.push((value, slot));
        }
    }

    let result = RegAllocOutput { allocs, spills };
    Ok((adapter.block_order, result))
}
