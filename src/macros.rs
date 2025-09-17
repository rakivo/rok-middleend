#[macro_export]
macro_rules! define_opcodes {
    (
        $context:ident,
        $(
            $opcode:ident($($arg_name:ident: $arg_type:ty),*) = $val:expr
            $(
                ,
                @
                $idata_pattern:pat
                $(if bits == $size_guard:expr)?
                => |$results:ident, $chunk:ident $(,$inst_id:ident)?|
                $emitter_body:block
            )?
        ),*
    ) => {
        /// Opcodes for the VM.
        #[repr(u8)]
        #[non_exhaustive]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Opcode {
            $(
                $opcode,
            )*
        }

        impl<'a> $crate::lower::LoweringContext<'a> {
            pub fn generated_emit_inst(
                &mut $context,
                inst_id: Inst,
                chunk: &mut BytecodeChunk
            ) {
                use crate::entity::EntityRef;

                let inst = unsafe { crate::util::reborrow(&$context.func.dfg.insts[inst_id.index()]) };
                let results = $context.func.dfg.inst_results.get(&inst_id);

                #[allow(unused, dead_code)]
                #[warn(unreachable_patterns)]
                match inst {
                    $(
                        $(
                            $idata_pattern $(if {
                                $size_guard == inst.bits(inst_id, &$context.func)
                            })? => {
                                let $results = results;
                                let $chunk = chunk;
                                $( let $inst_id = inst_id; )?
                                $emitter_body
                            }
                        )?
                    )*

                    IData::IConst { .. }     => unreachable!("invalid bitwidth"),
                    IData::FConst { .. }     => unreachable!("invalid bitwidth"),
                    IData::LoadNoOffset { .. }  => unreachable!("invalid bitwidth"),
                    IData::StoreNoOffset { .. }  => unreachable!("invalid bitwidth"),
                    IData::StackLoad { .. }  => unreachable!("invalid bitwidth"),
                    IData::StackStore { .. } => unreachable!("invalid bitwidth"),
                }
            }
        }

        #[must_use]
        pub fn generated_disassemble_instruction(
            _lowered_func: &$crate::lower::LoweredSsaFunc,
            _offset: usize
        ) -> usize {
            unimplemented!()
        }
    };
}
