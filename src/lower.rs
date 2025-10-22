#![cfg_attr(not(debug_assertions), allow(unused_imports))]

use crate::util;
use crate::entity::EntityRef;
use crate::regalloc::{self, RegAllocOutput, SCRATCH_REG};
use crate::bytecode::{
    StackFrameInfo,
    StackSlotAllocation,
    Opcode,
    BytecodeChunk
};
use crate::ssa::{
    Block,
    Inst,
    SsaFunc,
    StackSlot,
    Type,
    Value
};

use rustc_hash::{FxHashMap, FxHashSet};

/// Represents a function that has been lowered to bytecode.
pub struct LoweredSsaFunc<'a> {
    pub context: LoweringContext<'a>,
    pub chunk: BytecodeChunk,
}

#[cfg(debug_assertions)]
#[derive(Clone, Debug)]
pub struct LoInstMeta {
    pub inst: Inst,             // SSA inst id
    pub pc: usize,              // start pc
    pub size: u8,              // byte size
}

//////////////////////////////////////////////////////////////////////
// Lowering from SSA to Bytecode
//
pub struct LoweringContext<'a> {
    pub module_id: u32,

    pub func: &'a SsaFunc,
    pub ssa_to_preg: FxHashMap<Value, u8>,

    next_stack_slot: StackSlot,

    block_offsets: FxHashMap<Block, u32>,

    /// For patching jumps.
    jump_placeholders: Vec<(usize, Block)>,

    /// Stack frame information
    pub frame_info: StackFrameInfo,

    regalloc: RegAllocOutput,

    order: Vec<Block>,

    pub callee_saved_info: Option<Vec<(u8, StackSlot)>>,

    /// Map from Value -> spill `StackSlot` (allocated in `frame_info`)
    pub spill_slots: FxHashMap<Value, StackSlot>,

    #[cfg(debug_assertions)]
    pub pc_to_inst_meta: FxHashMap<usize, LoInstMeta>,  // index == inst index in lowered list
}

impl<'a> LoweringContext<'a> {
    /// Determine which callee-saved registers this function uses.
    fn compute_used_callee_saved_regs(&self) -> Vec<u8> {
        let mut used = FxHashSet::default();

        for &reg in self.ssa_to_preg.values() {
            if regalloc::is_callee_saved(reg) {
                used.insert(reg);
            }
        }

        let mut regs: Vec<u8> = used.into_iter().collect();
        regs.sort_unstable();
        regs
    }

    /// Emit function prologue: save callee-saved registers this function uses.
    pub fn emit_function_prologue(&mut self, chunk: &mut BytecodeChunk) -> Vec<(u8, StackSlot)> {
        let callee_saved = self.compute_used_callee_saved_regs();

        #[cfg(debug_assertions)]
        if !callee_saved.is_empty() {
            eprintln!("[prologue] Saving {} callee-saved registers: {:?}",
                callee_saved.len(), callee_saved);
        }

        let mut saved_slots = Vec::new();

        for &reg in &callee_saved {
            let slot = self.allocate_spill_slot(Type::I64);
            let allocation = &self.frame_info.slot_allocations[&slot];

            chunk.append(Opcode::FpStore64);
            chunk.append(allocation.offset);
            chunk.append(reg);

            saved_slots.push((reg, slot));

            #[cfg(debug_assertions)]
            eprintln!("[prologue]   Saved r{} -> stack[{}]", reg, allocation.offset);
        }

        saved_slots
    }

    /// Emit function epilogue: restore callee-saved registers.
    pub fn emit_function_epilogue(&self, chunk: &mut BytecodeChunk, saved_slots: &[(u8, StackSlot)]) {
        #[cfg(debug_assertions)]
        if !saved_slots.is_empty() {
            eprintln!("[epilogue] Restoring {} callee-saved registers", saved_slots.len());
        }

        for (reg, slot) in saved_slots.iter().rev() {
            let allocation = &self.frame_info.slot_allocations[slot];

            chunk.append(Opcode::FpLoad64);
            chunk.append(*reg);
            chunk.append(allocation.offset);

            #[cfg(debug_assertions)]
            eprintln!("[epilogue]   Restored r{} <- stack[{}]", reg, allocation.offset);
        }
    }
}

#[cfg_attr(not(debug_assertions), allow(unused, dead_code))]
impl<'a> LoweringContext<'a> {
    pub const ARG_REGISTERS_COUNT           : u32 = 8;
    pub const RETURN_VALUES_REGISTERS_COUNT : u32 = 8;

    #[must_use]
    pub fn new(module_id: u32, func: &'a SsaFunc) -> Self {
        let (
            order,
            result
        ) = crate::regalloc::allocate_registers_custom(func).unwrap();

        Self {
            order,
            module_id,
            regalloc: result,
            callee_saved_info: None,
            next_stack_slot: StackSlot::from_u32(func.stack_slots.len() as _),
            #[cfg(debug_assertions)]
            pc_to_inst_meta: FxHashMap::default(),
            frame_info: StackFrameInfo::calculate_layout(func),
            func,
            ssa_to_preg: FxHashMap::default(),
            block_offsets: FxHashMap::default(),
            jump_placeholders: Vec::default(),
            spill_slots: FxHashMap::default(),
        }
    }

    /// Lower the function to a bytecode chunk.
    #[must_use]
    pub fn lower(mut self) -> LoweredSsaFunc<'a> {
        self.ssa_to_preg.reserve(self.regalloc.allocs.len());

        // Map entry parameters to their fixed registers (r0-r7)
        for (&param_value, &preg) in &self.regalloc.entry_param_pregs {
            self.ssa_to_preg.insert(param_value, preg.index() as u8);
        }

        // Map all other allocated values
        for (&v, p) in &self.regalloc.allocs {
            self.ssa_to_preg.insert(v, p.index() as u8);
        }

        self.spill_slots.reserve(self.regalloc.spills.len());
        for i in 0..self.regalloc.spills.len() {
            let (v, _) = self.regalloc.spills[i];
            let ty = self.func.dfg.values[v.index()].ty;
            let slot = self.allocate_spill_slot(ty);
            self.spill_slots.insert(v, slot);
            self.ssa_to_preg.remove(&v);
        }

        // Create chunk but DON'T copy frame_info yet
        let mut chunk = BytecodeChunk::default();

        // Allocate callee-saved register slots (this grows self.frame_info)
        let callee_saved_info = {
            let callee_saved = self.compute_used_callee_saved_regs();
            let mut saved_slots = Vec::new();

            for &reg in &callee_saved {
                let slot = self.allocate_spill_slot(Type::I64);
                saved_slots.push((reg, slot));
            }

            saved_slots
        };

        self.callee_saved_info = Some(callee_saved_info);

        // NOW copy the finalized frame_info to chunk
        chunk.frame_info = self.frame_info.clone();

        // Emit frame setup (uses correct total_size now)
        self.emit_frame_setup(&mut chunk);

        // Emit the actual store instructions for callee-saved regs
        if let Some(ref info) = self.callee_saved_info {
            for &(reg, slot) in info {
                let allocation = &self.frame_info.slot_allocations[&slot];
                chunk.append(Opcode::FpStore64);
                chunk.append(allocation.offset);
                chunk.append(reg);

                #[cfg(debug_assertions)]
                eprintln!("[prologue]   Saved r{} -> stack[{}]", reg, allocation.offset);
            }
        }

        // Emit bytecode for each block
        self.emit_blocks(&mut chunk);

        // Patch jump instructions with correct offsets
        self.patch_jumps(&mut chunk);

        LoweredSsaFunc { context: self, chunk }
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

    /// Allocate a new FP-relative stack slot for a spill and register it in `frame_info`.
    /// Returns the `StackSlot` handle.
    pub fn allocate_spill_slot(&mut self, ty: Type) -> StackSlot {
        let size = ty.bytes() as i32;
        let align = ty.align_bytes();

        // compute new offset above existing frame
        let mut offset = self.frame_info.total_size;
        offset = util::align_up(offset, align);

        let slot = self.create_stack_slot(ty, size as u32);

        self.frame_info.slot_allocations.insert(slot, StackSlotAllocation {
            offset,
            size: size as u32,
            ty,
        });

        // update total_size
        self.frame_info.total_size = util::align_up(
            offset + size as u32,
            16
        );

        slot
    }

    fn create_stack_slot(&mut self, _ty: Type, _size: u32) -> StackSlot {
        let slot = self.next_stack_slot;
        self.next_stack_slot.0 += 1;
        slot
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
        self.ssa_to_preg.len()
    }

    fn emit_blocks(&mut self, chunk: &mut BytecodeChunk) {
        for block_id in self.order.clone() {
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
                    LoInstMeta {
                        inst: inst_id,
                        pc,
                        size: (chunk.code.len() - pc) as u8
                    }
                );
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

    #[track_caller]
    pub fn emit_inst_with_result<F>(
        &mut self,
        chunk: &mut BytecodeChunk,
        result_val: Value,
        emit_body: F
    )
    where
        F: FnOnce(&mut LoweringContext, &mut BytecodeChunk, u8),
    {
        let temp_reg = SCRATCH_REG;
        emit_body(self, chunk, temp_reg);
        self.store_value(chunk, result_val, temp_reg);
    }

    #[track_caller]
    pub fn load_value(&self, chunk: &mut BytecodeChunk, value: Value) -> u8 {
        if let Some(reg) = self.ssa_to_preg.get(&value) {
            *reg
        } else if let Some(slot) = self.spill_slots.get(&value) {
            let allocation = &self.frame_info.slot_allocations[slot];
            let ty = self.func.dfg.values[value.index()].ty;
            let opcode = Opcode::fp_load(ty.bits()).unwrap();
            let temp_reg = SCRATCH_REG;
            chunk.append(opcode);
            chunk.append(temp_reg);
            chunk.append(allocation.offset);
            temp_reg
        } else {
            panic!("Value not found: {value:?}");
        }
    }

    pub fn store_value(&self, chunk: &mut BytecodeChunk, value: Value, reg: u8) {
        if self.ssa_to_preg.contains_key(&value) {
            // It's a register, so we just move it
            let dst_reg = self.ssa_to_preg[&value];
            if dst_reg != reg {
                chunk.append(Opcode::Mov);
                chunk.append(dst_reg);
                chunk.append(reg);
            }
        } else if let Some(slot) = self.spill_slots.get(&value) {
            let allocation = &self.frame_info.slot_allocations[slot];
            let ty = self.func.dfg.values[value.index()].ty;
            let opcode = Opcode::fp_store(ty.bits()).unwrap();
            chunk.append(opcode);
            chunk.append(allocation.offset);
            chunk.append(reg);
        }
    }
}
