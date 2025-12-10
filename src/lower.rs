#![cfg_attr(not(debug_assertions), allow(unused_imports))]

use crate::util;
use crate::bytecode::{BytecodeChunk, Opcode, StackFrameInfo, StackSlotAllocation};
use crate::ssa::{Block, Inst, InstructionData, SsaFunc, StackSlot, Type, Value};

use rok_entity::{EntityList, SecondaryMap, SparseMap, SparseMapValue};

rok_entity::entity_ref!(Pc);

pub struct LoweredSsaFunc<'a> {
    pub context: LoweringContext<'a>,
    pub chunk: BytecodeChunk,
}

#[cfg(debug_assertions)]
#[derive(Clone, Debug)]
pub struct LoInstMeta {
    pub inst: Inst,
    pub pc: Pc,
}

#[cfg(debug_assertions)]
impl SparseMapValue<Pc> for LoInstMeta {
    fn key(&self) -> Pc { self.pc }
}

//////////////////////////////////////////////////////////////////////
// Lowering from SSA to Bytecode
//
pub struct LoweringContext<'a> {
    pub func: &'a SsaFunc,

    next_stack_slot: StackSlot,

    block_offsets: SecondaryMap<Block, u32>,

    //
    // for patching jumps
    //                    pos  arg-count  target
    jump_placeholders: Vec<(usize, u8, Block)>,

    block_order: Vec<Block>,

    pub frame_info: StackFrameInfo,

    #[cfg(debug_assertions)]
    pub inst_meta: SparseMap<Pc, LoInstMeta>,
}

#[cfg_attr(not(debug_assertions), allow(unused, dead_code))]
impl<'a> LoweringContext<'a> {
    pub const ARG_REGISTERS_COUNT: u32 = 8;
    pub const RETURN_VALUES_REGISTERS_COUNT: u32 = 8;

    #[must_use]
    pub fn new(func: &'a SsaFunc) -> Self {
        let est_blocks = func.cfg.blocks.len();

        Self {
            block_order: Vec::with_capacity(est_blocks),
            next_stack_slot: StackSlot::from_u32(func.stack_slots.len() as _),
            #[cfg(debug_assertions)]
            inst_meta: SparseMap::default(),
            frame_info: StackFrameInfo::calculate_layout(func),
            func,
            block_offsets: SecondaryMap::new(),
            jump_placeholders: Vec::with_capacity(est_blocks),
        }
    }

    /// Lower the function to a bytecode chunk.
   #[must_use]
   #[inline]
   pub fn lower(mut self) -> LoweredSsaFunc<'a> {
        let mut chunk = BytecodeChunk {
            frame_info: self.frame_info.clone(),
            ..Default::default()
        };

        chunk.code.reserve(self.func.dfg.insts.len() * 9); // @Constant

        // Emit frame setup (uses correct total_size now)
        self.emit_frame_setup(&mut chunk);

        self.compute_block_order().unwrap();

        // Emit bytecode for each block
        self.emit_blocks(&mut chunk);

        // Patch jump instructions with correct offsets
        self.patch_jumps(&mut chunk);

        LoweredSsaFunc {
            context: self,
            chunk,
        }
    }

    #[inline(always)]
    pub fn append_jump_placeholder<T>(
        &mut self,
        chunk: &mut BytecodeChunk,
        arg_count: u8,
        dst: Block,
    ) {
        let pos = chunk.code.len();
        chunk.append_placeholder::<T>();
        self.jump_placeholders.push((pos, arg_count, dst));
    }

    /// Allocate a new FP-relative stack slot for a spill and register it in `frame_info`.
    /// Returns the `StackSlot` handle.
    #[inline]
    pub fn allocate_spill_slot(&mut self, ty: Type) -> StackSlot {
        let size = ty.bytes() as i32;
        let align = ty.align_bytes();

        // compute new offset above existing frame
        let mut offset = self.frame_info.total_size;
        offset = util::align_up(offset, align);

        let slot = self.create_stack_slot(ty, size as u32);

        self.frame_info.slot_allocations.insert(
            slot,
            StackSlotAllocation {
                offset,
                size: size as _,
                ty,
            },
        );

        // update total_size
        self.frame_info.total_size = util::align_up(offset + size as u32, 16);

        slot
    }

    #[inline]
    fn create_stack_slot(&mut self, _ty: Type, _size: u32) -> StackSlot {
        let slot = self.next_stack_slot;
        self.next_stack_slot.0 += 1;
        slot
    }

    #[inline]
    pub fn append_args(&self, chunk: &mut BytecodeChunk, args: &EntityList<Value>) {
        let args_slice = args.as_slice(&self.func.values_pool);
        let args_len = args_slice.len();
        assert!(args_len <= 255, "Too many arguments (max 255)");

        chunk.code.reserve(1 + args_len * 4);
        chunk.append(args_len as u8);

        for &arg in args_slice {
            chunk.append(arg.as_u32());
        }
    }

    pub fn jump_with_args(
        &mut self,
        chunk: &mut BytecodeChunk,
        target: Block,
        args: &EntityList<Value>,
    ) {
        let params = &self.func.cfg.blocks[target].params;

        let args_len = args.len(&self.func.values_pool);

        debug_assert_eq!(params.len(&self.func.values_pool), args_len);

        assert!(args_len <= 255, "Too many arguments (max 255)");

        self.append_jump_placeholder::<i16>(chunk, args_len as _, target);
        chunk.append(args_len as u8);
        for (&param, &arg) in args
            .as_slice(&self.func.values_pool)
            .iter()
            .zip(params.as_slice(&self.func.values_pool))
        {
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
        let entry = self.func.layout.block_entry.ok_or("No entry block")?;
        let mut visited = nohash_hasher::IntSet::with_capacity_and_hasher(
            self.func.cfg.blocks.len(),
            nohash_hasher::BuildNoHashHasher::default()
        );
        let mut stack = Vec::with_capacity(32);
        stack.push(entry);

        while let Some(block) = stack.pop() {
            if !visited.insert(block) {
                continue;
            }

            self.block_order.push(block);

            // Cache block data
            let bd = &self.func.cfg.blocks[block];
            if let Some(&last_inst) = bd.insts.as_slice(&self.func.cfg.block_insts_pool).last() {
                let inst_data = &self.func.dfg.insts[last_inst];

                let succs: &[Block] = match inst_data {
                    InstructionData::Jump { destination, .. } => {
                        std::slice::from_ref(destination)
                    }
                    InstructionData::Branch { destinations, .. } => destinations,
                    InstructionData::Return { .. } | InstructionData::Unreachable => &[],
                    _ => &[]
                };

                // Push in reverse for depth-first order
                for &succ in succs.iter().rev() {
                    if !visited.contains(&succ) {
                        stack.push(succ);
                    }
                }
            }
        }
        Ok(())
    }

    fn emit_blocks(&mut self, chunk: &mut BytecodeChunk) {
        for i in 0..self.block_order.len() {
            let block_id = self.block_order[i];

            self.block_offsets.insert(block_id, chunk.code.len() as u32);

            let n = self.func.cfg.blocks[block_id].insts.len(&self.func.cfg.block_insts_pool);

            for i in 0..n {
                let pc = Pc::from_u32(chunk.code.len() as _);

                let inst = self.func.cfg.blocks[block_id].insts.as_slice(&self.func.cfg.block_insts_pool)[i];

                self.generated_emit_inst(inst, chunk);

                #[cfg(debug_assertions)]
                self.inst_meta.insert(LoInstMeta { inst, pc });
            }
        }
    }

    fn patch_jumps(&mut self, chunk: &mut BytecodeChunk) {
        for (pos, arg_count, target_block) in &self.jump_placeholders {
            let target_offset = self.block_offsets[*target_block];

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
