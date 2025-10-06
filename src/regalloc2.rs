use crate::ssa;
use crate::entity::EntityRef;
use crate::ssa::{Value, SsaFunc, InstructionData};

use regalloc2::*;
use rustc_hash::{FxHashSet, FxHashMap};

pub const REG_COUNT   : u8 = 64;
pub const SCRATCH_REG : u8 = 63;

#[inline(always)]
const fn int_preg(index: u8) -> PReg {
    PReg::new(index as usize, RegClass::Int)
}

#[inline(always)]
const fn int_vreg(index: usize) -> VReg {
    VReg::new(index as usize, RegClass::Int)
}

/// Machine environment describing our register set
/// Convention: r0-r7 are arg/return registers (caller-saved)
///            r8-r62 are general purpose registers
///            r63 is scratch register
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
        // r8-r62 are general purpose registers (preferred for allocation)
        // These are preferred because they're not clobbered by calls
        let preferred = (8..63).map(int_preg).collect();

        // r0-r7 are argument/return registers (non-preferred)
        // Available for allocation but clobbered by calls
        let non_preferred = (0..8).map(int_preg).collect();

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
    /// Maps entry block parameters to their fixed physical registers (r0-r7)
    pub entry_param_pregs: FxHashMap<Value, PReg>,
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
            entry_param_pregs: FxHashMap::default(),
        };

        adapter.compute_block_order();
        adapter.compute_cfg_edges();
        adapter.compute_entry_params();
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

    /// Map entry block parameters to their physical registers (r0-r7)
    fn compute_entry_params(&mut self) {
        if let Some(entry) = self.func.layout.block_entry {
            let block_data = &self.func.cfg.blocks[entry.index()];

            // First 8 parameters are in r0-r7 by calling convention
            for (i, &param) in block_data.params.iter().enumerate().take(8) {
                self.entry_param_pregs.insert(param, int_preg(i as u8));
            }

            // TODO: Parameters beyond the 8th would need to be on the stack
            // For now, we assume <= 8 parameters
            if block_data.params.len() > 8 {
                // This should be handled at a higher level (SSA construction)
                // by loading from stack slots
                unimplemented!()
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
                        // Return values should go in r0-r7
                        // We mark them as uses here; the lowering phase will
                        // ensure they end up in the right registers
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

        // SAFETY: We're leaking memory here for simplicity. In production code,
        // you'd want to cache these allocations or use a different approach.
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
        // Calls clobber r0-r7 (argument/return registers are caller-saved)
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
    fn spillslot_size(&self, _regclass: RegClass) -> usize {
        8 // All our registers are 64-bit max
    }
}

/// Result of register allocation
#[derive(Debug)]
pub struct RegAllocOutput {
    /// Map from SSA values to physical registers
    pub allocs: FxHashMap<Value, PReg>,
    /// Values that were spilled to stack slots
    pub spills: Vec<(Value, SpillSlot)>,
    /// Entry block parameters are fixed to r0-r7 (not in allocs map)
    pub entry_param_pregs: FxHashMap<Value, PReg>,
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

        // Skip entry parameters - they're handled separately
        if adapter.entry_param_pregs.contains_key(&value) {
            continue;
        }

        if let Some(preg) = alloc.as_reg() {
            allocs.insert(value, preg);
        } else if let Some(slot) = alloc.as_stack() {
            spills.push((value, slot));
        }
    }

    debug_assert_eq!(output.edits.len(), 0);

    let result = RegAllocOutput {
        allocs,
        spills,
        entry_param_pregs: adapter.entry_param_pregs.clone(),
    };

    Ok((adapter.block_order, result))
}
