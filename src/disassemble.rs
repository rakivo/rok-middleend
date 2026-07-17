#![cfg_attr(not(debug_assertions), allow(unused_imports))]

use crate::{lower::LoweredSsaFunc, ssa::SsaFunc};
#[cfg(debug_assertions)]
use crate::lower::Pc;
use crate::{bytecode::Opcode, ssa::SourceLoc};

use std::fmt::{self, Write};

/// A bytecode reader that provides methods to read different data types
pub struct BytecodeReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> BytecodeReader<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn read_u8(&mut self) -> u8 {
        let val = self.data[self.offset];
        self.offset += 1;
        val
    }

    pub fn read_i8(&mut self) -> i8 {
        self.read_u8() as i8
    }

    pub fn read_u16(&mut self) -> u16 {
        let bytes = [self.data[self.offset], self.data[self.offset + 1]];
        self.offset += 2;
        u16::from_le_bytes(bytes)
    }

    pub fn read_i16(&mut self) -> i16 {
        self.read_u16() as i16
    }

    pub fn read_u32(&mut self) -> u32 {
        let bytes = [
            self.data[self.offset],
            self.data[self.offset + 1],
            self.data[self.offset + 2],
            self.data[self.offset + 3],
        ];
        self.offset += 4;
        u32::from_le_bytes(bytes)
    }

    pub fn read_i32(&mut self) -> i32 {
        self.read_u32() as i32
    }

    pub fn read_u64(&mut self) -> u64 {
        let bytes = [
            self.data[self.offset],
            self.data[self.offset + 1],
            self.data[self.offset + 2],
            self.data[self.offset + 3],
            self.data[self.offset + 4],
            self.data[self.offset + 5],
            self.data[self.offset + 6],
            self.data[self.offset + 7],
        ];
        self.offset += 8;
        u64::from_le_bytes(bytes)
    }

    pub fn read_i64(&mut self) -> i64 {
        self.read_u64() as i64
    }

    pub fn read_f32(&mut self) -> f32 {
        f32::from_bits(self.read_u32())
    }

    pub fn read_f64(&mut self) -> f64 {
        f64::from_bits(self.read_u64())
    }

    #[must_use]
    pub fn position(&self) -> usize {
        self.offset
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }
}

impl Opcode {
    /// Converts a u8 discriminant to an Opcode variant
    /// Returns None if the discriminant doesn't match any opcode
    #[must_use]
    pub fn from_u8(val: u8) -> Option<Self> {
        if val > Opcode::Halt as u8 { return None }

        Some(unsafe { core::mem::transmute(val) })
    }
}

/// Formats an instruction in assembly-like format with proper alignment
pub fn print_instruction(reader: &mut BytecodeReader, f: &mut impl Write) -> fmt::Result {
    if reader.remaining() == 0 {
        return write!(f, "<end of bytecode>");
    }

    let opcode_byte = reader.read_u8();
    let opcode = unsafe { core::mem::transmute(opcode_byte) };

    match opcode {
        // Constants
        Opcode::IConst8 => {
            let dst = reader.read_u32();
            let val = reader.read_i8();
            write!(f, "{:<16} r{}, {}", "iconst.i8", dst, val)
        }
        Opcode::IConst16 => {
            let dst = reader.read_u32();
            let val = reader.read_i16();
            write!(f, "{:<16} r{}, {}", "iconst.i16", dst, val)
        }
        Opcode::IConst32 => {
            let dst = reader.read_u32();
            let val = reader.read_i32();
            write!(f, "{:<16} r{}, {}", "iconst.i32", dst, val)
        }
        Opcode::IConst64 => {
            let dst = reader.read_u32();
            let val = reader.read_i64();
            write!(f, "{:<16} r{}, {}", "iconst.i64", dst, val)
        }
        Opcode::FConst32 => {
            let dst = reader.read_u32();
            let val = reader.read_f32();
            write!(f, "{:<16} r{}, {}", "fconst.f32", dst, val)
        }
        Opcode::FConst64 => {
            let dst = reader.read_u32();
            let val = reader.read_f64();
            write!(f, "{:<16} r{}, {}", "fconst.f64", dst, val)
        }

        // Integer Arithmetic
        Opcode::IAdd => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "iadd", dst, a, b)
        }
        Opcode::SRem => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "srem", dst, a, b)
        }
        Opcode::URem => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "urem", dst, a, b)
        }
        Opcode::ISub => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "isub", dst, a, b)
        }
        Opcode::IMul => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "imul", dst, a, b)
        }
        Opcode::SDiv => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "sdiv", dst, a, b)
        }
        Opcode::UDiv => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "udiv", dst, a, b)
        }

        // Logical Operations
        Opcode::And => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "and", dst, a, b)
        }
        Opcode::Or => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "or", dst, a, b)
        }
        Opcode::Xor => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "xor", dst, a, b)
        }

        // Shift Operations
        Opcode::Ushr => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "ushr", dst, a, b)
        }
        Opcode::Sshr => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "sshr", dst, a, b)
        }
        Opcode::Ishl => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "ishl", dst, a, b)
        }

        // Bitwise Operations
        Opcode::Band => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "band", dst, a, b)
        }
        Opcode::Bor => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "bor", dst, a, b)
        }

        // Float Arithmetic
        Opcode::FAdd32 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fadd.f32", dst, a, b)
        }
        Opcode::FAdd64 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fadd.f64", dst, a, b)
        }
        Opcode::FSub32 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fsub.f32", dst, a, b)
        }
        Opcode::FSub64 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fsub.f64", dst, a, b)
        }
        Opcode::FMul32 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fmul.f32", dst, a, b)
        }
        Opcode::FMul64 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fmul.f64", dst, a, b)
        }
        Opcode::FDiv32 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fdiv.f32", dst, a, b)
        }
        Opcode::FDiv64 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fdiv.f64", dst, a, b)
        }
        Opcode::FRem32 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "frem.f32", dst, a, b)
        }
        Opcode::FRem64 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "frem.f64", dst, a, b)
        }

        // Disassembler - Float Comparisons
        Opcode::FEq32 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.eq.f32", dst, a, b)
        }
        Opcode::FEq64 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.eq.f64", dst, a, b)
        }
        Opcode::FNe32 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.ne.f32", dst, a, b)
        }
        Opcode::FNe64 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.ne.f64", dst, a, b)
        }
        Opcode::FGt32 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.gt.f32", dst, a, b)
        }
        Opcode::FGt64 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.gt.f64", dst, a, b)
        }
        Opcode::FGe32 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.ge.f32", dst, a, b)
        }
        Opcode::FGe64 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.ge.f64", dst, a, b)
        }
        Opcode::FLt32 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.lt.f32", dst, a, b)
        }
        Opcode::FLt64 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.lt.f64", dst, a, b)
        }
        Opcode::FLe32 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.le.f32", dst, a, b)
        }
        Opcode::FLe64 => {
            let dst = reader.read_u32(); let a = reader.read_u32(); let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "fcmp.le.f64", dst, a, b)
        }

        // Control Flow
        Opcode::Jump32 => {
            let offset = reader.read_i32();
            let num_args = reader.read_u8();
            let mut moves = Vec::new();
            for _ in 0..num_args {
                let src = reader.read_u32();
                let dst = reader.read_u32();
                moves.push((src, dst));
            }
            if moves.is_empty() {
                write!(f, "{:<16} {:05X}", "jump", offset)
            } else {
                let moves_str = moves
                    .iter()
                    .map(|(src, dst)| format!("r{} -> r{}", src, dst))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "{:<16} {:05X} ({})", "jump", offset, moves_str)
            }
        }

        Opcode::BranchIf32 => {
            let cond = reader.read_u32();
            let true_offset = reader.read_i32();
            let else_offset = reader.read_i32();

            // Read true branch moves
            let num_args_true = reader.read_u8();
            let mut moves_true = Vec::new();
            for _ in 0..num_args_true {
                let src = reader.read_u32();
                let dst = reader.read_u32();
                moves_true.push((src, dst));
            }

            // Read else branch moves (Crucial: to advance the reader position!)
            let num_args_else = reader.read_u8();
            let mut moves_else = Vec::new();
            for _ in 0..num_args_else {
                let src = reader.read_u32();
                let dst = reader.read_u32();
                moves_else.push((src, dst));
            }

            let true_moves_str = if moves_true.is_empty() {
                String::new()
            } else {
                format!(
                    " then:({})",
                    moves_true
                        .iter()
                        .map(|(src, dst)| format!("r{src} -> r{dst}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };

            let else_moves_str = if moves_else.is_empty() {
                String::new()
            } else {
                format!(
                    " else:({})",
                    moves_else
                        .iter()
                        .map(|(src, dst)| format!("r{src} -> r{dst}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };

            write!(
                f,
                "{:<16} r{}, then:{:05X}, else:{:05X}{}{}",
                "branchif", cond, true_offset, else_offset, true_moves_str, else_moves_str
            )
        }

        Opcode::Return => {
            // append_args writes: count (u8) followed by each arg (u32)
            let num_args = reader.read_u8();
            let mut args = Vec::new();
            for _ in 0..num_args {
                args.push(reader.read_u32());
            }

            if args.is_empty() {
                write!(f, "{:<16}", "return")
            } else {
                let args_str = args
                    .iter()
                    .map(|a| format!("r{a}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "{:<16} {}", "return", args_str)
            }
        }

        Opcode::Call => {
            let num_results = reader.read_u8();
            let mut results = Vec::new();
            for _ in 0..num_results {
                results.push(reader.read_u32());
            }
            let func_id = reader.read_u32();

            // Read arguments
            let num_args = reader.read_u8();
            let mut args = Vec::new();
            for _ in 0..num_args {
                args.push(reader.read_u32());
            }

            // Format output
            let args_str = if args.is_empty() {
                String::new()
            } else {
                format!(
                    "({})",
                    args.iter()
                        .map(|a| format!("r{a}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };

            if results.is_empty() {
                write!(f, "{:<16} func_{func_id}{}", "call", args_str)
            } else if results.len() == 1 {
                write!(
                    f,
                    "{:<16} r{} = func_{func_id}{}",
                    "call", results[0], args_str
                )
            } else {
                let results_str = results
                    .iter()
                    .map(|r| format!("r{r}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    f,
                    "{:<16} ({}) = func_{func_id}{}",
                    "call", results_str, args_str
                )
            }
        }

        Opcode::CallHook => {
            let result = reader.read_u32();
            let hook_id = reader.read_u32();

            // Read arguments
            let num_args = reader.read_u8();
            let mut args = Vec::new();
            for _ in 0..num_args {
                args.push(reader.read_u32());
            }

            let args_str = if args.is_empty() {
                String::new()
            } else {
                format!(
                    "({})",
                    args.iter()
                        .map(|a| format!("r{a}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };

            if result == u32::MAX {
                write!(f, "{:<16} hook_{}{}", "call.hook", hook_id, args_str)
            } else {
                write!(
                    f,
                    "{:<16} r{} = hook_{}{}",
                    "call.hook", result, hook_id, args_str
                )
            }
        }

        Opcode::CallExt => {
            let num_results = reader.read_u8();
            let mut results = Vec::new();
            for _ in 0..num_results {
                results.push(reader.read_u32());
            }
            let func_id = reader.read_u32();

            // Read arguments
            let num_args = reader.read_u8();
            let mut args = Vec::new();
            for _ in 0..num_args {
                args.push(reader.read_u32());
            }

            // Format output
            let args_str = if args.is_empty() {
                String::new()
            } else {
                format!(
                    "({})",
                    args.iter()
                        .map(|a| format!("r{a}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };

            if results.is_empty() {
                write!(f, "{:<16} extfunc_{}{}", "call.ext", func_id, args_str)
            } else if results.len() == 1 {
                write!(
                    f,
                    "{:<16} r{} = extfunc_{}{}",
                    "call.ext", results[0], func_id, args_str
                )
            } else {
                let results_str = results
                    .iter()
                    .map(|r| format!("r{r}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    f,
                    "{:<16} ({}) = extfunc_{}{}",
                    "call.ext", results_str, func_id, args_str
                )
            }
        }

        // Type Conversions
        Opcode::Ireduce => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            let bits = reader.read_u8();
            write!(f, "{:<16} r{}, r{}, i{}", "ireduce", dst, src, bits)
        }
        Opcode::Uextend => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            let from_bits = reader.read_u8();
            let to_bits = reader.read_u8();
            write!(
                f,
                "{:<16} r{}, r{}, i{} -> i{}",
                "uextend", dst, src, from_bits, to_bits
            )
        }
        Opcode::Sextend => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "sextend", dst, src)
        }
        Opcode::Bitcast => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            let bits = reader.read_u8();
            write!(f, "{:<16} r{}, r{}, i{}", "bitcast", dst, src, bits)
        }

        // Memory Operations - Load
        Opcode::Load8 => {
            let dst = reader.read_u32();
            let addr = reader.read_u32();
            write!(f, "{:<16} r{}, [r{}]", "load.i8", dst, addr)
        }
        Opcode::Load16 => {
            let dst = reader.read_u32();
            let addr = reader.read_u32();
            write!(f, "{:<16} r{}, [r{}]", "load.i16", dst, addr)
        }
        Opcode::Load32 => {
            let dst = reader.read_u32();
            let addr = reader.read_u32();
            write!(f, "{:<16} r{}, [r{}]", "load.i32", dst, addr)
        }
        Opcode::Load64 => {
            let dst = reader.read_u32();
            let addr = reader.read_u32();
            write!(f, "{:<16} r{}, [r{}]", "load.i64", dst, addr)
        }

        // Memory Operations - Store
        Opcode::Store8 => {
            let addr = reader.read_u32();
            let val = reader.read_u32();
            write!(f, "{:<16} [r{}], r{}", "store.i8", addr, val)
        }
        Opcode::Store16 => {
            let addr = reader.read_u32();
            let val = reader.read_u32();
            write!(f, "{:<16} [r{}], r{}", "store.i16", addr, val)
        }
        Opcode::Store32 => {
            let addr = reader.read_u32();
            let val = reader.read_u32();
            write!(f, "{:<16} [r{}], r{}", "store.i32", addr, val)
        }
        Opcode::Store64 => {
            let addr = reader.read_u32();
            let val = reader.read_u32();
            write!(f, "{:<16} [r{}], r{}", "store.i64", addr, val)
        }

        // Stack Operations
        Opcode::Mov => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "mov", dst, src)
        }

        // Stack Frame Management
        Opcode::FrameSetup => {
            let size = reader.read_u32();
            write!(f, "{:<16} {}", "frame.setup", size)
        }
        Opcode::FrameTeardown => write!(f, "{:<16}", "frame.teardown"),
        Opcode::SpAdd => {
            let offset = reader.read_u32();
            write!(f, "{:<16} {}", "sp.add", offset)
        }
        Opcode::SpSub => {
            let offset = reader.read_u32();
            write!(f, "{:<16} {}", "sp.sub", offset)
        }

        // Float Conversions
        Opcode::FPromote => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "fpromote", dst, src)
        }
        Opcode::FDemote => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "fdemote", dst, src)
        }
        Opcode::FNeg32 => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "fneg.f32", dst, src)
        }
        Opcode::FNeg64 => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "fneg.f64", dst, src)
        }

        // Frame Pointer Operations - Load
        Opcode::FpLoad8 => {
            let dst = reader.read_u32();
            let offset = reader.read_i32();
            write!(f, "{:<16} r{}, [fp{:+}]", "load.i8", dst, offset)
        }
        Opcode::FpLoad16 => {
            let dst = reader.read_u32();
            let offset = reader.read_i32();
            write!(f, "{:<16} r{}, [fp{:+}]", "load.i16", dst, offset)
        }
        Opcode::FpLoad32 => {
            let dst = reader.read_u32();
            let offset = reader.read_i32();
            write!(f, "{:<16} r{}, [fp{:+}]", "load.i32", dst, offset)
        }
        Opcode::FpLoad64 => {
            let dst = reader.read_u32();
            let offset = reader.read_i32();
            write!(f, "{:<16} r{}, [fp{:+}]", "load.i64", dst, offset)
        }

        // Frame Pointer Operations - Store
        Opcode::FpStore8 => {
            let offset = reader.read_i32();
            let src = reader.read_u32();
            write!(f, "{:<16} [fp{:+}], r{}", "store.i8", offset, src)
        }
        Opcode::FpStore16 => {
            let offset = reader.read_i32();
            let src = reader.read_u32();
            write!(f, "{:<16} [fp{:+}], r{}", "store.i16", offset, src)
        }
        Opcode::FpStore32 => {
            let offset = reader.read_i32();
            let src = reader.read_u32();
            write!(f, "{:<16} [fp{:+}], r{}", "store.i32", offset, src)
        }
        Opcode::FpStore64 => {
            let offset = reader.read_i32();
            let src = reader.read_u32();
            write!(f, "{:<16} [fp{:+}], r{}", "store.i64", offset, src)
        }

        // Stack Pointer Operations - Load
        Opcode::SpLoad8 => {
            let dst = reader.read_u32();
            let offset = reader.read_i32();
            write!(f, "{:<16} r{}, [sp{:+}]", "load.i8", dst, offset)
        }
        Opcode::SpLoad16 => {
            let dst = reader.read_u32();
            let offset = reader.read_i32();
            write!(f, "{:<16} r{}, [sp{:+}]", "load.i16", dst, offset)
        }
        Opcode::SpLoad32 => {
            let dst = reader.read_u32();
            let offset = reader.read_i32();
            write!(f, "{:<16} r{}, [sp{:+}]", "load.i32", dst, offset)
        }
        Opcode::SpLoad64 => {
            let dst = reader.read_u32();
            let offset = reader.read_i32();
            write!(f, "{:<16} r{}, [sp{:+}]", "load.i64", dst, offset)
        }

        // Stack Pointer Operations - Store
        Opcode::SpStore8 => {
            let offset = reader.read_i32();
            let src = reader.read_u32();
            write!(f, "{:<16} [sp{:+}], r{}", "store.i8", offset, src)
        }
        Opcode::SpStore16 => {
            let offset = reader.read_i32();
            let src = reader.read_u32();
            write!(f, "{:<16} [sp{:+}], r{}", "store.i16", offset, src)
        }
        Opcode::SpStore32 => {
            let offset = reader.read_i32();
            let src = reader.read_u32();
            write!(f, "{:<16} [sp{:+}], r{}", "store.i32", offset, src)
        }
        Opcode::SpStore64 => {
            let offset = reader.read_i32();
            let src = reader.read_u32();
            write!(f, "{:<16} [sp{:+}], r{}", "store.i64", offset, src)
        }

        // Address Calculation
        Opcode::FpAddr => {
            let dst = reader.read_u32();
            let offset = reader.read_i32();
            write!(f, "{:<16} r{}, fp{:+}", "addr", dst, offset)
        }
        Opcode::SpAddr => {
            let dst = reader.read_u32();
            let offset = reader.read_i32();
            write!(f, "{:<16} r{}, sp{:+}", "addr", dst, offset)
        }

        // Data Address
        Opcode::LoadDataAddr => {
            let dst = reader.read_u32();
            let data_id = reader.read_u32();
            write!(f, "{:<16} r{}, data_{}", "load.data.addr", dst, data_id)
        }

        // Integer Comparisons
        Opcode::IEq => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "icmp.eq", dst, a, b)
        }
        Opcode::INe => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "icmp.ne", dst, a, b)
        }
        Opcode::ISGt => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "icmp.sgt", dst, a, b)
        }
        Opcode::ISGe => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "icmp.sge", dst, a, b)
        }
        Opcode::ISLt => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "icmp.slt", dst, a, b)
        }
        Opcode::ISLe => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "icmp.sle", dst, a, b)
        }
        Opcode::IUGt => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "icmp.ugt", dst, a, b)
        }
        Opcode::IUGe => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "icmp.uge", dst, a, b)
        }
        Opcode::IULt => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "icmp.ult", dst, a, b)
        }
        Opcode::IULe => {
            let dst = reader.read_u32();
            let a = reader.read_u32();
            let b = reader.read_u32();
            write!(f, "{:<16} r{}, r{}, r{}", "icmp.ule", dst, a, b)
        }

        // Float-Int Conversions
        Opcode::FloatToSInt32 => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "f32.to.sint", dst, src)
        }
        Opcode::FloatToUInt32 => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "f32.to.uint", dst, src)
        }
        Opcode::SIntToFloat32 => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "sint.to.f32", dst, src)
        }
        Opcode::UIntToFloat32 => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "uint.to.f32", dst, src)
        }

        // Float-Int Conversions
        Opcode::FloatToSInt64 => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "f64.to.sint", dst, src)
        }
        Opcode::FloatToUInt64 => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "f64.to.uint", dst, src)
        }
        Opcode::SIntToFloat64 => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "sint.to.f64", dst, src)
        }
        Opcode::UIntToFloat64 => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "uint.to.f64", dst, src)
        }

        Opcode::CallIndirect => {
            let num_results = reader.read_u8();
            let mut results = Vec::new();
            for _ in 0..num_results {
                results.push(reader.read_u32());
            }
            let callee = reader.read_u32();

            let num_args = reader.read_u8();
            let mut args = Vec::new();
            for _ in 0..num_args {
                args.push(reader.read_u32());
            }

            let args_str = if args.is_empty() {
                String::new()
            } else {
                format!(
                    "({})",
                    args.iter()
                        .map(|a| format!("r{a}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };

            if results.is_empty() {
                write!(f, "{:<16} r{}{}", "call.indirect", callee, args_str)
            } else if results.len() == 1 {
                write!(
                    f,
                    "{:<16} r{} = r{}{}",
                    "call.indirect", results[0], callee, args_str
                )
            } else {
                let results_str = results
                    .iter()
                    .map(|r| format!("r{r}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    f,
                    "{:<16} ({}) = r{}{}",
                    "call.indirect", results_str, callee, args_str
                )
            }
        }

        // Special Instructions
        Opcode::Nop => write!(f, "{:<16}", "nop"),
        Opcode::Halt => write!(f, "{:<16}", "halt"),
    }
}

/// Disassembles bytecode with optional metadata annotations in compiler assembly style
#[must_use]
pub fn disassemble(
    bytecode: &[u8],
    _ssa: Option<&SsaFunc>,
    _lowered: Option<&LoweredSsaFunc>,
    _srcloc_formatter: Option<impl Fn(SourceLoc) -> Option<String>>,
) -> String {
    let mut reader = BytecodeReader::new(bytecode);
    let mut output = String::new();
    #[allow(unused_mut, unused)]
    let mut curr_block: Option<crate::ssa::Block> = None;

    if let Some(ssa) = _ssa {
        print!("function {}\n{:05X} ;", ssa.name(), 0);
    }

    while reader.remaining() > 0 {
        let pc = reader.position();
        let offset_str = format!("{pc:05X}");

        // Print metadata if available
        #[cfg(debug_assertions)]
        if let Some(lowered) = _lowered
        && let Some(crate::lower::LoInstMeta { inst, .. }) =
                lowered.inst_meta.get(Pc::from_u32(pc as _))
        && let Some(ssa) = _ssa
        {
            use rok_entity::EntityRef;

            // Look up the block this instruction belongs to
            if let Some(block) = ssa.layout.inst_block(*inst)
                && Some(block) != curr_block
            {
                curr_block = Some(block);
                _ = write!(
                    &mut output,
                    "\n{} ; block({}) -------------------------------------",
                    offset_str,
                    block.index()
                );
            }

            output.push('\n');

            if let Some(srcloc_formatter) = &_srcloc_formatter {
                let srcloc = ssa.srclocs[*inst];
                if let Some(snippet) = srcloc_formatter(srcloc) {
                    for line in snippet.lines() {
                        _ = writeln!(&mut output, "{offset_str} ; {line}");
                    }
                }
                _ = writeln!(&mut output, "{offset_str} ;");
            }
        }

        _ = write!(&mut output, "{offset_str}   ");

        if print_instruction(&mut reader, &mut output).is_err() {
            output.push_str("<error>");
        }

        output.push('\n');
    }

    output
}
