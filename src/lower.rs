#![cfg_attr(not(debug_assertions), allow(unused_imports))]

use crate::util;
use crate::entity::EntityRef;
use crate::bytecode::{
    StackFrameInfo,
    StackSlotAllocation,
    Opcode,
    BytecodeChunk
};
use crate::ssa::{
    Block, Inst, InstructionData, SsaFunc, StackSlot, Type, Value
};

use rustc_hash::{FxHashMap, FxHashSet};

pub struct LoweredSsaFunc<'a> {
    pub context: LoweringContext<'a>,
    pub chunk: BytecodeChunk,
}

#[cfg(debug_assertions)]
#[derive(Clone, Debug)]
pub struct LoInstMeta {
    pub inst: Inst,
    pub pc: usize,
    pub size: u8,
}

//////////////////////////////////////////////////////////////////////
// Lowering from SSA to Bytecode
//
pub struct LoweringContext<'a> {
    pub func: &'a SsaFunc,

    next_stack_slot: StackSlot,

    block_offsets: FxHashMap<Block, u32>,

    /// For patching jumps.
    //                       pos  arg count  target
    jump_placeholders: Vec<(usize,   u8,     Block)>,

    block_order: Vec<Block>,

    pub frame_info: StackFrameInfo,

    #[cfg(debug_assertions)]
    pub pc_to_inst_meta: FxHashMap<usize, LoInstMeta>,  // index == inst index in lowered list
}

#[cfg_attr(not(debug_assertions), allow(unused, dead_code))]
impl<'a> LoweringContext<'a> {
    pub const ARG_REGISTERS_COUNT           : u32 = 8;
    pub const RETURN_VALUES_REGISTERS_COUNT : u32 = 8;

    #[must_use]
    pub fn new(func: &'a SsaFunc) -> Self {
        Self {
            block_order: Vec::new(),
            next_stack_slot: StackSlot::from_u32(func.stack_slots.len() as _),
            #[cfg(debug_assertions)]
            pc_to_inst_meta: FxHashMap::default(),
            frame_info: StackFrameInfo::calculate_layout(func),
            func,
            block_offsets: FxHashMap::default(),
            jump_placeholders: Vec::default(),
        }
    }

    /// Lower the function to a bytecode chunk.
    #[must_use]
    pub fn lower(mut self) -> LoweredSsaFunc<'a> {
        // Create chunk but DON'T copy frame_info yet
        let mut chunk = BytecodeChunk {
            frame_info: self.frame_info.clone(),
            ..Default::default()
        };

        // Emit frame setup (uses correct total_size now)
        self.emit_frame_setup(&mut chunk);

        self.compute_block_order().unwrap();

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
        arg_count: u8,
        dst: Block
    ) {
        let pos = chunk.code.len();
        chunk.append_placeholder::<T>();
        self.jump_placeholders.push((pos, arg_count, dst));
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

    pub fn append_args(&self, chunk: &mut BytecodeChunk, args: &[Value]) {
        assert!(args.len() <= 255, "Too many arguments (max 255)");
        chunk.append(args.len() as u8);
        for &arg in args {
            chunk.append(arg.as_u32());
        }
    }

    pub fn jump_with_args(&mut self, chunk: &mut BytecodeChunk, target: Block, args: &[Value]) {
        let params = &self.func.cfg.blocks[target.index()].params;

        debug_assert_eq!(params.len(), args.len());
        assert!(args.len() <= 255, "Too many arguments (max 255)");

        self.append_jump_placeholder::<i16>(chunk, args.len() as _, target);
        chunk.append(args.len() as u8);
        for (&param, &arg) in args.iter().zip(params) {
            chunk.append(arg.as_u32());
            chunk.append(param.as_u32());
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

    fn compute_block_order(&mut self) -> Result<(), String> {
        let entry = self.func.layout.block_entry
            .ok_or("No entry block")?;

        let mut visited = FxHashSet::default();
        let mut stack = vec![entry];

        while let Some(block) = stack.pop() {
            if visited.contains(&block) { continue; }
            visited.insert(block);
            self.block_order.push(block);

            // Get successors from terminator
            let bd = &self.func.cfg.blocks[block.index()];
            if let Some(&last_inst) = bd.insts.last() {
                let inst_idx = last_inst.index();
                let succs = match &self.func.dfg.insts[inst_idx] {
                    InstructionData::Jump { destination, .. } => vec![*destination],
                    InstructionData::Branch { destinations, .. } => destinations.to_vec(),
                    InstructionData::Return { .. } |
                    InstructionData::Unreachable => vec![],
                    _ => {
                        // Non-terminator: implicit fallthrough
                        if block.index() + 1 < self.func.cfg.blocks.len() {
                            vec![Block::new(block.index() + 1)]
                        } else {
                            vec![]
                        }
                    }
                };

                for succ in succs.iter().rev() {
                    if !visited.contains(succ) {
                        stack.push(*succ);
                    }
                }
            }
        }

        Ok(())
    }

    fn emit_blocks(&mut self, chunk: &mut BytecodeChunk) {
        for block_id in self.block_order.clone() {
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
        for (pos, arg_count, target_block) in &self.jump_placeholders {
            let target_offset = self.block_offsets[target_block];

            // The jump offset is relative to the position *after* the jump instruction.
            let opcode_size = 1 +
                // dst_u32 + src_u32
                (2 * *arg_count as usize * core::mem::size_of::<u32>());

            let opcode_size = opcode_size as i16;
            let offset_size = core::mem::size_of::<i16>() as i16;
            let jump_offset = target_offset as i16 - (*pos as i16 + offset_size + opcode_size);

            let bytes = jump_offset.to_le_bytes();
            chunk.code[*pos] = bytes[0];
            chunk.code[*pos + 1] = bytes[1];
        }
    }
}
