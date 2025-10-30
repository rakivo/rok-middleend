#[macro_export]
#[doc(hidden)]
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
    ) => { paste::paste!{
        #[repr(u8)]
        #[non_exhaustive]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Opcode {
            $( $opcode, )*
        }

        impl Opcode {
            $(
                pub const fn [< $opcode:snake:lower _ size >]() -> usize {
                    #[allow(unused_mut)]
                    let mut size = 0;
                    $(
                        size += core::mem::size_of::<$arg_type>();
                    )*
                    size
                }
            )*

            pub const fn size(self) -> usize {
                match self {
                    $(
                        Opcode::$opcode => 1 + Self::[< $opcode:snake:lower _size >](),
                    )*
                }
            }
        }

        impl<'a> $crate::lower::LoweringContext<'a> {
            pub fn generated_emit_inst(
                &mut $context,
                inst_id: Inst,
                chunk: &mut BytecodeChunk
            ) {
                use $crate::entity::EntityRef;

                let inst = unsafe { $crate::util::reborrow(&$context.func.dfg.insts[inst_id.index()]) };
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

                    IData::IConst { .. }        |
                    IData::FConst { .. }        |
                    IData::LoadNoOffset { .. }  |
                    IData::StoreNoOffset { .. } |
                    IData::StackLoad { .. }     |
                    IData::StackStore { .. } => unreachable!("invalid bitwidth"),
                }
            }
        }
    }};
}
