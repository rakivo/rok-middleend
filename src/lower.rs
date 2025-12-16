#![cfg_attr(not(debug_assertions), allow(unused_imports))]

use crate::bytecode::{BytecodeFunction, Opcode, StackFrameInfo};
use crate::ssa::{Block, Inst, InstructionData, SsaFunc, Value};

use nohash_hasher::IntSet;
use rok_entity::{EntityList, SecondaryMap, SparseMap, SparseMapValue};
use smallvec::SmallVec;

rok_entity::entity_ref!(Pc);

#[must_use]
#[inline]
pub fn lower(ssa_func: &SsaFunc) -> LoweredSsaFunc {
    LoweringContext::new(ssa_func).lower()
}

pub struct LoweredSsaFunc {
    #[cfg(debug_assertions)]
    pub inst_meta: SparseMap<Pc, LoInstMeta>,

    pub chunk: BytecodeFunction,
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

pub struct JumpPlaceholder {
    offset: u32,
    dst: Block,
    instruction_end: u32
}

//////////////////////////////////////////////////////////////////////
// Lowering from SSA to Bytecode
//
pub struct LoweringContext<'a> {
    pub func: &'a SsaFunc,

    block_offsets: SecondaryMap<Block, u32>,

    jump_placeholders: Vec<JumpPlaceholder>,

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
    #[inline]
    pub fn new(func: &'a SsaFunc) -> Self {
        let est_blocks = func.cfg.blocks.len() * 2; // @Constant

        Self {
            block_order: Vec::with_capacity(est_blocks),
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
    pub fn lower(mut self) -> LoweredSsaFunc {
        let mut chunk = BytecodeFunction::default();
        chunk.code.reserve(self.func.dfg.insts.len() * 8); // @Constant @Note yeah our bytecode is a bit chunky..

        self.emit_frame_setup(&mut chunk);

        self.compute_block_order();

        self.emit_blocks(&mut chunk);

        self.patch_jumps(&mut chunk);

        chunk.frame_info = self.frame_info;

        LoweredSsaFunc {
            chunk,
            #[cfg(debug_assertions)]
            inst_meta: self.inst_meta
        }
    }

    #[inline(always)]
    pub fn append_jump_placeholder<T>(
        &mut self,
        chunk: &mut BytecodeFunction,
        dst: Block,
    ) {
        let offset = chunk.code.len() as u32;
        chunk.append_placeholder::<T>();
        self.jump_placeholders.push(JumpPlaceholder {
            offset,
            dst,
            instruction_end: offset
        });
    }

    #[inline]
    pub fn append_args(&self, chunk: &mut BytecodeFunction, args: &EntityList<Value>) {
        let args_slice = args.as_slice(&self.func.values_pool);
        let args_len = args_slice.len();
        assert!(args_len <= 255, "Too many arguments (max 255)");

        chunk.code.reserve(1 + args_len * core::mem::size_of::<u32>());
        chunk.append(args_len as u8);

        for &arg in args_slice {
            chunk.append(arg.as_u32());
        }
    }

    #[inline]
    pub fn jump_with_args(
        &mut self,
        chunk: &mut BytecodeFunction,
        target: Block,
        args: &EntityList<Value>,
    ) {
        let params = &self.func.cfg.blocks[target].params;
        let args_len = args.len(&self.func.values_pool);
        debug_assert_eq!(params.len(&self.func.values_pool), args_len);
        debug_assert!(args_len <= 255, "Too many arguments (max 255)");

        let offset_pos = chunk.code.len() as u32;
        chunk.append(0xDED_i16); // placeholder

        chunk.append(args_len as u8);
        for (&param, &arg) in args
            .as_slice(&self.func.values_pool)
            .iter()
            .zip(params.as_slice(&self.func.values_pool))
        {
            chunk.append(arg.as_u32());
            chunk.append(param.as_u32());
        }

        let instruction_end = chunk.code.len() as u32;

        self.jump_placeholders.push(JumpPlaceholder {
            offset: offset_pos,
            dst: target,
            instruction_end,
        });
    }

    #[inline]
    pub fn brif_with_args(
        &mut self,
        chunk: &mut BytecodeFunction,
        then: Block,
        els: Block,
        args: &EntityList<Value>,
    ) {
        let args_len = args.len(&self.func.values_pool);
        debug_assert!(args_len <= 255, "Too many arguments (max 255)");

        let then_offset_pos = chunk.code.len() as u32;
        chunk.append(0xDED_i16); // then placeholder

        let els_offset_pos = chunk.code.len() as u32;
        chunk.append(0xDED_i16); // else placeholder

        chunk.append(args_len as u8);

        let params = &self.func.cfg.blocks[then].params;
        for (&param, &arg) in args
            .as_slice(&self.func.values_pool)
            .iter()
            .zip(params.as_slice(&self.func.values_pool))
        {
            chunk.append(arg.as_u32());
            chunk.append(param.as_u32());
        }

        let instruction_end = chunk.code.len() as u32;

        self.jump_placeholders.push(JumpPlaceholder {
            offset: then_offset_pos,
            dst: then,
            instruction_end,
        });

        self.jump_placeholders.push(JumpPlaceholder {
            offset: els_offset_pos,
            dst: els,
            instruction_end,
        });
    }

    #[inline(always)]
    pub fn emit_frame_setup(&mut self, chunk: &mut BytecodeFunction) {
        if self.frame_info.total_size > 0 {
            chunk.append(Opcode::FrameSetup);
            chunk.append(self.frame_info.total_size);
        }
    }

    #[inline(always)]
    pub fn emit_frame_teardown(&mut self, chunk: &mut BytecodeFunction) {
        if self.frame_info.total_size > 0 {
            chunk.append(Opcode::FrameTeardown);
        }
    }

    fn compute_block_order(&mut self) {
        let Some(entry) = self.func.layout.block_entry else {
            return;
        };

        let mut visited = IntSet::with_capacity_and_hasher(
            self.func.cfg.blocks.len(),
            nohash_hasher::BuildNoHashHasher::default()
        );
        let mut postorder = SmallVec::<[Block; 64]>::new();
        let mut stack = SmallVec::<[_; 32]>::new();

        stack.push((entry, false));

        while let Some((block, processed)) = stack.pop() {
            if processed {
                postorder.push(block);
                continue;
            }

            if !visited.insert(block) {
                continue;
            }

            stack.push((block, true));

            let bd = &self.func.cfg.blocks[block];
            if let Some(&last_inst) = bd.insts.as_slice(&self.func.cfg.block_insts_pool).last() {
                let inst_data = &self.func.dfg.insts[last_inst];

                match inst_data {
                    InstructionData::Jump { destination, .. } => {
                        // Unconditional jump - target is effectively a fallthrough candidate
                        if !visited.contains(destination) {
                            stack.push((*destination, false));
                        }
                    }
                    InstructionData::Branch { destinations, .. } => {
                        // For Branch, destinations[0] is typically the "true/taken" branch,
                        // destinations[1] is the "false/fallthrough" branch
                        // Push taken branch FIRST so fallthrough is explored LAST
                        // (last explored = appears next in RPO)

                        let [true_dest, false_dest] = *destinations;

                        if !visited.contains(&true_dest) {
                            stack.push((true_dest, false));
                        }

                        if !visited.contains(&false_dest) {
                            stack.push((false_dest, false));
                        }
                    }
                    InstructionData::Return { .. } | InstructionData::Unreachable => {
                        // No successors
                    }
                    _ => {}
                }
            }
        }

        // RPO
        self.block_order.extend(postorder.iter().rev());

        // unreachable blocks
        for (block, _) in &self.func.cfg.blocks {
            if !visited.contains(&block) {
                self.block_order.push(block);
            }
        }
    }

    #[inline]
    fn emit_blocks(&mut self, chunk: &mut BytecodeFunction) {
        for i in 0..self.block_order.len() {
            let block_id = self.block_order[i];

            self.block_offsets.insert(block_id, chunk.code.len() as _);

            let insts = self.func.cfg.blocks[block_id]
                .insts
                .as_slice(&self.func.cfg.block_insts_pool);

            for &inst in insts {
                #[cfg(debug_assertions)]
                let pc = Pc::from_u32(chunk.code.len() as _);

                self.generated_emit_inst(inst, chunk);

                #[cfg(debug_assertions)]
                self.inst_meta.insert(LoInstMeta { inst, pc });
            }
        }
    }

    #[inline]
    fn patch_jumps(&mut self, chunk: &mut BytecodeFunction) {
        for JumpPlaceholder { offset, instruction_end, dst, .. } in &self.jump_placeholders {
            let target_offset = self.block_offsets[*dst];

            // The offset is relative to the end of the entire instruction
            // (after all the parallel moves)
            let jump_offset = target_offset as i32 - *instruction_end as i32;

            let bytes = (jump_offset as i16).to_le_bytes();
            chunk.code[*offset as usize + 0] = bytes[0];
            chunk.code[*offset as usize + 1] = bytes[1];
        }
    }
}
