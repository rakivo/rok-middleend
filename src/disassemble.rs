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
        // This uses the discriminants from define_opcodes! macro
        match val {
            0 => Some(Opcode::IConst8),
            1 => Some(Opcode::IConst16),
            2 => Some(Opcode::IConst32),
            3 => Some(Opcode::IConst64),
            4 => Some(Opcode::FConst32),
            5 => Some(Opcode::FConst64),
            10 => Some(Opcode::IAdd),
            11 => Some(Opcode::ISub),
            12 => Some(Opcode::IMul),
            13 => Some(Opcode::SDiv),
            252 => Some(Opcode::UDiv),
            14 => Some(Opcode::And),
            15 => Some(Opcode::Or),
            16 => Some(Opcode::Xor),
            17 => Some(Opcode::Ushr),
            253 => Some(Opcode::Sshr),
            18 => Some(Opcode::Ishl),
            19 => Some(Opcode::Band),
            20 => Some(Opcode::Bor),
            21 => Some(Opcode::SRem),
            251 => Some(Opcode::URem),
            // from_u8 additions:
            22 => Some(Opcode::FAdd32),
            23 => Some(Opcode::FSub32),
            24 => Some(Opcode::FMul32),
            25 => Some(Opcode::FDiv32),
            112 => Some(Opcode::FRem32),
            106 => Some(Opcode::FEq32),
            107 => Some(Opcode::FNe32),
            108 => Some(Opcode::FGt32),
            234 => Some(Opcode::FGe32),
            236 => Some(Opcode::FLt32),
            238 => Some(Opcode::FLe32),
            232 => Some(Opcode::FAdd64),
            231 => Some(Opcode::FSub64),
            230 => Some(Opcode::FMul64),
            229 => Some(Opcode::FDiv64),
            228 => Some(Opcode::FRem64),
            227 => Some(Opcode::FEq64),
            226 => Some(Opcode::FNe64),
            233 => Some(Opcode::FGt64),
            235 => Some(Opcode::FGe64),
            237 => Some(Opcode::FLt64),
            239 => Some(Opcode::FLe64),
            26 => Some(Opcode::Jump32),
            27 => Some(Opcode::BranchIf32),
            28 => Some(Opcode::Return),
            29 => Some(Opcode::Call),
            30 => Some(Opcode::Ireduce),
            31 => Some(Opcode::Uextend),
            32 => Some(Opcode::Sextend),
            33 => Some(Opcode::Bitcast),
            40 => Some(Opcode::Load8),
            41 => Some(Opcode::Load16),
            42 => Some(Opcode::Load32),
            43 => Some(Opcode::Load64),
            44 => Some(Opcode::Store8),
            45 => Some(Opcode::Store16),
            47 => Some(Opcode::Store32),
            50 => Some(Opcode::Mov),
            60 => Some(Opcode::FrameSetup),
            61 => Some(Opcode::FrameTeardown),
            62 => Some(Opcode::SpAdd),
            63 => Some(Opcode::SpSub),
            67 => Some(Opcode::FPromote),
            69 => Some(Opcode::FNeg),
            70 => Some(Opcode::FpLoad8),
            71 => Some(Opcode::FpLoad16),
            72 => Some(Opcode::FpLoad32),
            73 => Some(Opcode::FpLoad64),
            74 => Some(Opcode::FpStore8),
            75 => Some(Opcode::FpStore16),
            76 => Some(Opcode::FpStore32),
            77 => Some(Opcode::FpStore64),
            80 => Some(Opcode::SpLoad8),
            81 => Some(Opcode::SpLoad16),
            82 => Some(Opcode::SpLoad32),
            83 => Some(Opcode::SpLoad64),
            84 => Some(Opcode::SpStore8),
            85 => Some(Opcode::SpStore16),
            86 => Some(Opcode::SpStore32),
            87 => Some(Opcode::SpStore64),
            90 => Some(Opcode::FpAddr),
            91 => Some(Opcode::SpAddr),
            95 => Some(Opcode::LoadDataAddr),
            96 => Some(Opcode::IEq),
            97 => Some(Opcode::INe),
            98 => Some(Opcode::ISGt),
            99 => Some(Opcode::ISGe),
            100 => Some(Opcode::ISLt),
            101 => Some(Opcode::ISLe),
            102 => Some(Opcode::IUGt),
            103 => Some(Opcode::IUGe),
            104 => Some(Opcode::IULt),
            105 => Some(Opcode::IULe),
            128 => Some(Opcode::Nop),
            135 => Some(Opcode::CallHook),
            136 => Some(Opcode::CallExt),
            137 => Some(Opcode::CallIndirect),
            200 => Some(Opcode::FDemote),
            201 => Some(Opcode::FloatToSInt32),
            202 => Some(Opcode::FloatToUInt32),
            203 => Some(Opcode::SIntToFloat32),
            204 => Some(Opcode::UIntToFloat32),
            255 => Some(Opcode::Halt),
            _ => None,
        }
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

            // jump_with_args writes: count (u8) followed by pairs of (arg, param) as u32
            let num_args = reader.read_u8();
            let mut moves = Vec::new();
            for _ in 0..num_args {
                let arg = reader.read_u32();
                let param = reader.read_u32();
                moves.push((arg, param));
            }

            if moves.is_empty() {
                write!(f, "{:<16} {:05X}", "jump", offset)
            } else {
                let moves_str = moves
                    .iter()
                    .map(|(arg, param)| format!("r{arg} -> r{param}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "{:<16} {:05X} ({})", "jump", offset, moves_str)
            }
        }

        Opcode::BranchIf32 => {
            let cond = reader.read_u32();
            let true_offset = reader.read_i32();
            let else_offset = reader.read_i32();

            // jump_with_args for true branch
            let num_args_true = reader.read_u8();
            let mut moves_true = Vec::new();
            for _ in 0..num_args_true {
                let arg = reader.read_u32();
                let param = reader.read_u32();
                moves_true.push((arg, param));
            }

            let moves_str = if moves_true.is_empty() {
                String::new()
            } else {
                format!(
                    " ({})",
                    moves_true
                        .iter()
                        .map(|(arg, param)| format!("r{arg} -> r{param}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };

            write!(
                f,
                "{:<16} r{}, then:{:05X}, else:{:05X}{}",
                "branchif", cond, true_offset, else_offset, moves_str
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
        Opcode::FNeg => {
            let dst = reader.read_u32();
            let src = reader.read_u32();
            write!(f, "{:<16} r{}, r{}", "fneg", dst, src)
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
        print!("function {}\n{:05X} ;", ssa.name, 0);
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
            if let Some(&block) = ssa.layout.inst_blocks.get(*inst)
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
