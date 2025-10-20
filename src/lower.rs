#![cfg_attr(not(debug_assertions), allow(unused_imports))]

use crate::util;
use crate::entity::EntityRef;
// use crate::regalloc2::{RegAllocOutput, SCRATCH_REG};
use crate::regalloc::{RegAllocOutput, RegMask, RegMaskMap, SCRATCH_REG};
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

use rustc_hash::FxHashMap;

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

    /// Map from Value -> spill `StackSlot` (allocated in `frame_info`)
    pub spill_slots: FxHashMap<Value, StackSlot>,

    #[cfg(debug_assertions)]
    pub pc_to_inst_meta: FxHashMap<usize, LoInstMeta>,  // index == inst index in lowered list

    /// Produced clobber mask for the function being lowered; computed in `lower()`.
    pub produced_clobber_mask: RegMask,
}

/// The context for lowering a single function.
#[cfg_attr(not(debug_assertions), allow(unused, dead_code))]
impl<'a> LoweringContext<'a> {
    pub const ARG_REGISTERS_COUNT           : u32 = 8;
    pub const RETURN_VALUES_REGISTERS_COUNT : u32 = 8;

    #[must_use]
    pub fn new(func: &'a SsaFunc, regmask_map: &RegMaskMap) -> Self {
        let (
            order,
            result
        ) = crate::regalloc::allocate_registers_custom(
            func,
            regmask_map
        ).unwrap();

        Self {
            order,
            regalloc: result,
            next_stack_slot: StackSlot::from_u32(func.stack_slots.len() as _),
            #[cfg(debug_assertions)]
            pc_to_inst_meta: FxHashMap::default(),
            frame_info: StackFrameInfo::calculate_layout(func),
            func,
            ssa_to_preg: FxHashMap::default(),
            block_offsets: FxHashMap::default(),
            jump_placeholders: Vec::default(),
            spill_slots: FxHashMap::default(),
            produced_clobber_mask: RegMask::empty(),
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

        // After possibly growing the frame with spill slots, copy frame info to chunk
        let mut chunk = BytecodeChunk {
            frame_info: self.frame_info.clone(),
            ..Default::default()
        };

        // 4. Emit frame setup at the beginning
        self.emit_frame_setup(&mut chunk);

        // 5. Emit bytecode for each block.
        self.emit_blocks(&mut chunk);

        // 6. Compute clobber mask for this function by scanning emitted bytecode.
        self.produced_clobber_mask = self.compute_clobber_mask(&chunk);
        #[cfg(debug_assertions)]
        eprintln!(
            "[lower] produced_clobber_mask for '{}': 0x{:032X}",
            self.func.name,
            self.produced_clobber_mask.0
        );

        // 7. Patch jump instructions with correct offsets.
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
    fn allocate_spill_slot(&mut self, ty: Type) -> StackSlot {
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

    /// Compute function-level clobber mask by scanning generated bytecode for writes to registers
    /// and including return registers used by `Return`.
    fn compute_clobber_mask(&self, chunk: &BytecodeChunk) -> RegMask {
        let mut mask = RegMask::empty();

        let mut offset = 0usize;
        while offset < chunk.code.len() {
            let opcode: Opcode = unsafe { std::mem::transmute(chunk.code[offset]) };
            match opcode {
                // Single-dst ops (dst at +1)
                Opcode::IConst8 | Opcode::IConst16 | Opcode::IConst32 | Opcode::IConst64 |
                Opcode::FConst32 | Opcode::FConst64 |
                Opcode::IAdd | Opcode::ISub | Opcode::IMul | Opcode::IDiv |
                Opcode::And | Opcode::Or | Opcode::Xor | Opcode::Ushr | Opcode::Ishl |
                Opcode::Band | Opcode::Bor |
                Opcode::IEq | Opcode::INe | Opcode::ISGt | Opcode::ISGe | Opcode::ISLt | Opcode::ISLe |
                Opcode::IUGt | Opcode::IUGe | Opcode::IULt | Opcode::IULe |
                Opcode::FAdd | Opcode::FSub | Opcode::FMul | Opcode::FDiv |
                Opcode::Load32 | Opcode::Load64 |
                Opcode::FpLoad8 | Opcode::FpLoad16 | Opcode::FpLoad32 | Opcode::FpLoad64 |
                Opcode::FpAddr | Opcode::LoadDataAddr |
                Opcode::Ireduce | Opcode::Uextend | Opcode::Sextend => {
                    let dst = chunk.code[offset + 1];
                    mask.set(dst);
                }
                // MOV dst, src
                Opcode::Mov => {
                    let dst = chunk.code[offset + 1];
                    mask.set(dst);
                }
                // Stores don't clobber registers; they read registers and write memory
                Opcode::Store8 | Opcode::Store16 | Opcode::Store32 | Opcode::Store64 |
                Opcode::FpStore8 | Opcode::FpStore16 | Opcode::FpStore32 | Opcode::FpStore64 => {}
                // Calls: results in r0..r7 depending on number of results
                Opcode::Call | Opcode::CallExt | Opcode::CallHook => {
                    // Conservatively mark r0..r7 as clobbered
                    mask = mask.union(RegMask::args_and_returns());
                }
                _ => {}
            }

            // Advance by instruction size without printing
            // offset = crate::bytecode::advance_instruction(chunk, offset);
            offset += opcode.size();
            debug_assert_ne!(offset, 0);
        }

        mask
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
