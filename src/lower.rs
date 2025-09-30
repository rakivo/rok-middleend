// TODO(#14): Spill slots allocations/management is broken
//   I think the lowerer overall works fine, its the
//   register allocator thats broken

use crate::entity::EntityRef;
use crate::regalloc2::RegAllocResult;
use crate::util::{self};
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

use std::collections::HashMap;

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
    pub ssa_to_reg: HashMap<Value, u32>,

    next_stack_slot: StackSlot,

    block_offsets: HashMap<Block, u32>,

    /// For patching jumps.
    jump_placeholders: Vec<(usize, Block)>,

    /// Stack frame information
    pub frame_info: StackFrameInfo,

    regalloc: RegAllocResult,

    order: Vec<Block>,

    /// Map from Value -> spill `StackSlot` (allocated in `frame_info`)
    pub spill_slots: HashMap<Value, StackSlot>,

    #[cfg(debug_assertions)]
    pub pc_to_inst_meta: HashMap<usize, LoInstMeta>,  // index == inst index in lowered list
}

/// The context for lowering a single function.
#[cfg_attr(not(debug_assertions), allow(unused, dead_code))]
impl<'a> LoweringContext<'a> {
    pub const RETURN_VALUES_REGISTERS_COUNT: u32 = 8;

    pub fn new(func: &'a SsaFunc) -> Self {
        let (
            order,
            result
        ) = crate::regalloc2::allocate_registers(func).unwrap();

        Self {
            order,
            regalloc: result,
            next_stack_slot: StackSlot::from_u32(func.stack_slots.len() as _),
            #[cfg(debug_assertions)]
            pc_to_inst_meta: HashMap::new(),
            frame_info: StackFrameInfo::calculate_layout(func),
            func,
            ssa_to_reg: HashMap::default(),
            block_offsets: HashMap::default(),
            jump_placeholders: Vec::default(),
            spill_slots: HashMap::default(),
        }
    }

    /// Lower the function to a bytecode chunk.
    #[must_use]
    pub fn lower(mut self) -> LoweredSsaFunc<'a> {
        self.ssa_to_reg.reserve(self.regalloc.allocs.len());
        for (&v, p) in &self.regalloc.allocs {
            self.ssa_to_reg.insert(v, p.index() as u32);
        }

        self.spill_slots.reserve(self.regalloc.spills.len());
        for i in 0..self.regalloc.spills.len() {
            let (v, _) = self.regalloc.spills[i];
            let ty = self.func.dfg.values[v.index()].ty;
            let slot = self.allocate_spill_slot(ty);
            self.spill_slots.insert(v, slot);
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

        // 6. Patch jump instructions with correct offsets.
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
        let align = ty.align_bytes() as u32;

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
            offset as u32 + size as u32,
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
        self.ssa_to_reg.len()
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
    pub fn load_value(&self, chunk: &mut BytecodeChunk, value: Value) -> u32 {
        if let Some(reg) = self.ssa_to_reg.get(&value) {
            *reg
        } else if let Some(slot) = self.spill_slots.get(&value) {
            let allocation = &self.frame_info.slot_allocations[slot];
            let ty = self.func.dfg.values[value.index()].ty;
            let opcode = Opcode::fp_load(ty.bits()).unwrap();
            let temp_reg = 63;
            chunk.append(opcode);
            chunk.append(temp_reg);
            chunk.append(allocation.offset);
            temp_reg
        } else {
            panic!("Value not found: {:?}\n{:#?}", value, self.func);
        }
    }

    pub fn store_value(&self, chunk: &mut BytecodeChunk, value: Value, reg: u32) {
        if self.ssa_to_reg.contains_key(&value) {
            // It's a register, so we just move it
            let dst_reg = self.ssa_to_reg[&value];
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
