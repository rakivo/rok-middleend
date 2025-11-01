use crate::entity::EntityRef;
use crate::lower::LoweredSsaFunc;
use crate::util::{self, IntoBytes};
use crate::ssa::{
    Inst,
    DataId,
    InstructionData as IData,
    SsaFunc,
    BinaryOp,
    StackSlot,
    UnaryOp,
    Type,
    IntCC
};

use std::mem;

use indexmap::IndexMap;

define_opcodes! {
    self,

    // Constants
    IConst8(dst: u32, val: i8)       = 0,
    @ IData::IConst { value, .. } if bits == 8 => |results, chunk| {
        let val = *value;
        let result_val = results.unwrap()[0];
        chunk.append(Opcode::IConst8);
        chunk.append(result_val.as_u32());
        chunk.append(val as i8);
    },

    IConst16(dst: u32, val: i16)      = 1,
    @ IData::IConst { value, .. } if bits == 16 => |results, chunk| {
        let val = *value;
        let result_val = results.unwrap()[0];
        chunk.append(Opcode::IConst16);
        chunk.append(result_val.as_u32());
        chunk.append(val as i16);
    },

    IConst32(dst: u32, val: i32)      = 2,
    @ IData::IConst { value, .. } if bits == 32 => |results, chunk| {
        let val = *value;
        let result_val = results.unwrap()[0];
        chunk.append(Opcode::IConst32);
        chunk.append(result_val.as_u32());
        chunk.append(val as i32);
    },

    IConst64(dst: u32, val: i64)      = 3,
    @ IData::IConst { value, .. } if bits == 64 => |results, chunk| {
        let val = *value;
        let result_val = results.unwrap()[0];
        chunk.append(Opcode::IConst64);
        chunk.append(result_val.as_u32());
        chunk.append(val as u64);
    },

    FConst32(dst: u32, val: f32)      = 4,
    @ IData::FConst { value, .. } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];;
        let val = *value as f32;
        chunk.append(Opcode::FConst32);
        chunk.append(dst);
        chunk.append(val);
    },

    FConst64(dst: u32, val: f64)      = 5,
    @ IData::FConst { value, .. } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];;
        chunk.append(Opcode::FConst64);
        chunk.append(dst);
        chunk.append(*value);
    },

    // Arithmetic
    IAdd(dst: u32, a: u32, b: u32)           = 10,
    @ IData::Binary { binop: BinaryOp::IAdd, args } => |results, chunk| {
        let dst = results.unwrap()[0];;
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IAdd);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    ISub(dst: u32, a: u32, b: u32)           = 11,
    @ IData::Binary { binop: BinaryOp::ISub, args } => |results, chunk| {
        let dst = results.unwrap()[0];;
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISub);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    IMul(dst: u32, a: u32, b: u32)           = 12,
    @ IData::Binary { binop: BinaryOp::IMul, args } => |results, chunk| {
        let dst = results.unwrap()[0];;
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IMul);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    IDiv(dst: u32, a: u32, b: u32)           = 13,
    @ IData::Binary { binop: BinaryOp::IDiv, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IDiv);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    And(dst: u32, a: u32, b: u32)            = 14,
    @ IData::Binary { binop: BinaryOp::And, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::And);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    Or(dst: u32, a: u32, b: u32)             = 15,
    @ IData::Binary { binop: BinaryOp::Or, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Or);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    Xor(dst: u32, a: u32, b: u32)            = 16,
    @ IData::Binary { binop: BinaryOp::Xor, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Xor);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Ushr(dst: u32, a: u32, b: u32)            = 17,
    @ IData::Binary { binop: BinaryOp::Ushr, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Ushr);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Ishl(dst: u32, a: u32, b: u32)            = 18,
    @ IData::Binary { binop: BinaryOp::Ishl, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Ishl);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Band(dst: u32, a: u32, b: u32)            = 19,
    @ IData::Binary { binop: BinaryOp::Band, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Band);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Bor(dst: u32, a: u32, b: u32)             = 20,
    @ IData::Binary { binop: BinaryOp::Bor, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Bor);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },


    IEq(dst: u32, a: u32, b: u32)            = 96,
    @ IData::Icmp { code: IntCC::Equal, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IEq);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    INe(dst: u32, a: u32, b: u32)            = 97,
    @ IData::Icmp { code: IntCC::NotEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::INe);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    ISGt(dst: u32, a: u32, b: u32)           = 98,
    @ IData::Icmp { code: IntCC::SignedGreaterThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISGt);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    ISGe(dst: u32, a: u32, b: u32)           = 99,
    @ IData::Icmp { code: IntCC::SignedGreaterThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISGe);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    ISLt(dst: u32, a: u32, b: u32)           = 100,
    @ IData::Icmp { code: IntCC::SignedLessThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISLt);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    ISLe(dst: u32, a: u32, b: u32)           = 101,
    @ IData::Icmp { code: IntCC::SignedLessThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISLe);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    IUGt(dst: u32, a: u32, b: u32)           = 102,
    @ IData::Icmp { code: IntCC::UnsignedGreaterThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IUGt);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    IUGe(dst: u32, a: u32, b: u32)           = 103,
    @ IData::Icmp { code: IntCC::UnsignedGreaterThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IUGe);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    IULt(dst: u32, a: u32, b: u32)           = 104,
    @ IData::Icmp { code: IntCC::UnsignedLessThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IULt);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    IULe(dst: u32, a: u32, b: u32)           = 105,
    @ IData::Icmp { code: IntCC::UnsignedLessThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IULe);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    FAdd(dst: u32, a: u32, b: u32)          = 22,
    @ IData::Binary { binop: BinaryOp::FAdd, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::FAdd);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FSub(dst: u32, a: u32, b: u32)          = 23,
    @ IData::Binary { binop: BinaryOp::FSub, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::FSub);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FMul(dst: u32, a: u32, b: u32)          = 24,
    @ IData::Binary { binop: BinaryOp::FMul, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::FMul);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FDiv(dst: u32, a: u32, b: u32)          = 25,
    @ IData::Binary { binop: BinaryOp::FDiv, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::FDiv);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Jump16(offset: i16) = 26,
    @ IData::Jump { destination, args, .. } => |_results, chunk| {
        let dest_block = &self.func.cfg.blocks[destination.index()];

        chunk.append(Opcode::Jump16);
        self.jump_with_args(chunk, *destination, args);
    },

    BranchIf16(cond: u32, offset: i16) = 27,
    @ IData::Branch { arg, destinations, args, .. } => |_results, chunk| {
        let [t, e] = *destinations;

        let cond_reg = *arg;
        chunk.append(Opcode::BranchIf16);
        chunk.append(cond_reg);
        self.jump_with_args(chunk, t, args);

        // Unconditional jump for the false branch
        chunk.append(Opcode::Jump16);
        self.jump_with_args(chunk, e, args);
    },

    Return() = 28,
    @ IData::Return { args, .. } => |_results, chunk| {
        // Teardown stack frame
        self.emit_frame_teardown(chunk);

        // Emit return instruction with arguments
        chunk.append(Opcode::Return);
        self.append_args(chunk, args);
    },

    Call(key: u64) = 29,
    @ IData::Call { func_id: _, args, parent, foreign_func_id } => |results, chunk, inst_id| {
        chunk.append(Opcode::Call);
        if let Some(results) = results {
            chunk.append(results.len() as u8);
            for result in results {
                chunk.append(result.as_u32());
            }
        } else {
            chunk.append(0u8);
        }
        let key: u64 = ((*parent as u64) << 32) | (foreign_func_id.index() as u64);
        chunk.append(key);
        self.append_args(chunk, args);
    },

    CallHook(hook_id: u32) = 135,
    @ IData::CallHook { hook_id, args } => |results, chunk, inst_id| {
        chunk.append(Opcode::CallHook);
        if let Some(result) = results.and_then(|v| v.first()) {
            chunk.append(result.as_u32());
        } else {
            chunk.append(u32::MAX); // sentinel
        }
        chunk.append(hook_id.index() as u32);
        self.append_args(chunk, args);
    },

    CallExt(key: u64) = 136,
    @ IData::CallExt { func_id, args, parent } => |results, chunk, inst_id| {
        chunk.append(Opcode::CallExt);
        if let Some(results) = results {
            chunk.append(results.len() as u8);
            for result in results {
                chunk.append(result.as_u32());
            }
        } else {
            chunk.append(0u8);
        }
        let key: u64 = ((*parent as u64) << 32) | (func_id.index() as u64);
        chunk.append(key);
        self.append_args(chunk, args);
    },

    Ireduce(dst: u32, src: u32, bits: u32) = 30,
    @ IData::Unary { unop: UnaryOp::Ireduce, arg } => |results, chunk| {
        let result_ty = self.func.dfg.values[results.unwrap()[0].index()].ty;
        let bits = result_ty.bits() as u8;
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::Ireduce);
        chunk.append(dst);
        chunk.append(src);
        chunk.append(bits);
    },
    Uextend(dst: u32, src: u32, from_bits: u32, to_bits: u32) = 31,
    @ IData::Unary { unop: UnaryOp::Uextend, arg } => |results, chunk| {
        let src_ty = self.func.dfg.values[arg.index()].ty;
        let dst_ty = self.func.dfg.values[results.unwrap()[0].index()].ty;
        let from_bits = src_ty.bits() as u8;
        let to_bits = dst_ty.bits() as u8;
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::Uextend);
        chunk.append(dst);
        chunk.append(src);
        chunk.append(from_bits);
        chunk.append(to_bits);
    },
    Sextend(dst: u32, src: u32) = 32,
    @ IData::Unary { unop: UnaryOp::Sextend, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::Sextend);
        chunk.append(dst);
        chunk.append(src);
    },
    FPromote(dst: u32, src: u32) = 67,
    @ IData::Unary { unop: UnaryOp::FPromote, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        // @Note: We only support f32 and f64, so we're not
        // encoding the dst type ..
        chunk.append(Opcode::FPromote);
        chunk.append(dst);
        chunk.append(src);
    },
    FDemote(dst: u32, src: u32) = 200,
    @ IData::Unary { unop: UnaryOp::FDemote, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FDemote);
        chunk.append(dst);
        chunk.append(src);
    },
    FloatToSInt(dst: u32, src: u32) = 201,
    @ IData::Unary { unop: UnaryOp::FloatToSInt, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FloatToSInt);
        chunk.append(dst);
        chunk.append(src);
    },
    FloatToUInt(dst: u32, src: u32) = 202,
    @ IData::Unary { unop: UnaryOp::FloatToUInt, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FloatToUInt);
        chunk.append(dst);
        chunk.append(src);
    },
    SIntToFloat(dst: u32, src: u32) = 203,
    @ IData::Unary { unop: UnaryOp::SIntToFloat, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::SIntToFloat);
        chunk.append(dst);
        chunk.append(src);
    },
    UIntToFloat(dst: u32, src: u32) = 204,
    @ IData::Unary { unop: UnaryOp::UIntToFloat, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::UIntToFloat);
        chunk.append(dst);
        chunk.append(src);
    },
    FNeg(dst: u32, src: u32) = 69,
    @ IData::Unary { unop: UnaryOp::FNeg, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FNeg);
        chunk.append(dst);
        chunk.append(src);
    },
    Bitcast(dst: u32, src: u32, ty: u32) = 33,
    @ IData::Unary { unop: UnaryOp::Bitcast, arg } => |results, chunk| {
        let result_ty = self.func.dfg.values[results.unwrap()[0].index()].ty;
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::Bitcast);
        chunk.append(dst);
        chunk.append(src);
        chunk.append(result_ty.bits() as u8);
    },

    // Memory
    Load8(dst: u32, addr: u32)         = 40,
    @ IData::LoadNoOffset { ty, addr } if bits == 8 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load8);
        chunk.append(dst);
        chunk.append(addr);
    },
    Load16(dst: u32, addr: u32)        = 41,
    @ IData::LoadNoOffset { ty, addr } if bits == 16 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load16);
        chunk.append(dst);
        chunk.append(addr);
    },
    Load32(dst: u32, addr: u32)        = 42,
    @ IData::LoadNoOffset { ty, addr } if bits == 32 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load32);
        chunk.append(dst);
        chunk.append(addr);
    },
    Load64(dst: u32, addr: u32)        = 43,
    @ IData::LoadNoOffset { ty, addr } if bits == 64 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load64);
        chunk.append(dst);
        chunk.append(addr);
    },

    Store8(addr: u32, val: u32) = 44,
    @ IData::StoreNoOffset { args } if bits == 8 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store8;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    Store16(addr: u32, val: u32) = 45,
    @ IData::StoreNoOffset { args } if bits == 16 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store16;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    Store32(addr: u32, val: u32) = 47,
    @ IData::StoreNoOffset { args } if bits == 32 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store32;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    Store64(addr: u32, val: u32) = 47,
    @ IData::StoreNoOffset { args } if bits == 64 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store64;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    // Stack operations
    Mov(dst: u32, src: u32)           = 50,

    // Stack frame management
    FrameSetup(size: u32)    = 60,
    FrameTeardown() = 61,

    // Direct stack pointer operations
    SpAdd(offset: u32)         = 62,
    SpSub(offset: u32)         = 63,

    // Frame pointer relative operations
    FpLoad8(dst: u32, offset: i32)       = 70,
    @ IData::StackLoad { slot, .. } if bits == 8 => |results, chunk| {
        let dst = results.unwrap()[0];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad8;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpLoad16(dst: u32, offset: i32)      = 71,
    @ IData::StackLoad { slot, .. } if bits == 16 => |results, chunk| {
        let dst = results.unwrap()[0];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad16;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpLoad32(dst: u32, offset: i32)      = 72,
    @ IData::StackLoad { slot, .. } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad32;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpLoad64(dst: u32, offset: i32)      = 73,
    @ IData::StackLoad { slot, .. } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad64;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpStore8(offset: i32, src: u32)      = 74,
    @ IData::StackStore { slot, arg, .. } if bits == 8 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore8;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    FpStore16(offset: i32, src: u32)     = 75,
    @ IData::StackStore { slot, arg, .. } if bits == 16 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore16;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    FpStore32(offset: i32, src: u32)     = 76,
    @ IData::StackStore { slot, arg, .. } if bits == 32 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore32;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    FpStore64(offset: i32, src: u32)     = 77,
    @ IData::StackStore { slot, arg, .. } if bits == 64 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore64;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },

    // Stack pointer relative operations
    SpLoad8(dst: u32, offset: i32)       = 80,
    SpLoad16(dst: u32, offset: i32)      = 81,
    SpLoad32(dst: u32, offset: i32)      = 82,
    SpLoad64(dst: u32, offset: i32)      = 83,
    SpStore8(offset: i32, src: u32)      = 84,
    SpStore16(offset: i32, src: u32)     = 85,
    SpStore32(offset: i32, src: u32)     = 86,
    SpStore64(offset: i32, src: u32)     = 87,

    // Address calculation
    FpAddr(dst: u32, offset: i32)        = 90,
    @ IData::StackAddr { slot, .. } => |results, chunk| {
        let dst = results.unwrap()[0];
        chunk.append(Opcode::FpAddr);
        chunk.append(dst);
        let allocation = &self.frame_info.slot_allocations[slot];
        chunk.append(allocation.offset);
    },
    SpAddr(dst: u32, offset: i32)        = 91,

    LoadDataAddr(dst: u32, data_id: DataId) = 95,
    @ IData::DataAddr { data_id } => |results, chunk| {
        let dst = results.unwrap()[0];
        chunk.append(Opcode::LoadDataAddr);
        chunk.append(dst);
        chunk.append(*data_id);
    },

    Nop() = 128,
    @ IData::Nop => |results, chunk| {},

    Halt()          = 255,
    @ IData::Unreachable => |results, chunk| {
        chunk.append(Opcode::Halt);
    }
}

impl Opcode {
    #[inline]
    #[must_use]
    pub const fn from_int_cc(cc: IntCC) -> Option<Self> {
        Some(match cc {
            IntCC::Equal => Opcode::IEq,
            IntCC::NotEqual => Opcode::INe,
            IntCC::SignedGreaterThan => Opcode::ISGt,
            IntCC::SignedGreaterThanOrEqual => Opcode::ISGe,
            IntCC::SignedLessThan => Opcode::ISLt,
            IntCC::SignedLessThanOrEqual => Opcode::ISLe,
            IntCC::UnsignedGreaterThan => Opcode::IUGt,
            IntCC::UnsignedGreaterThanOrEqual => Opcode::IUGe,
            IntCC::UnsignedLessThan => Opcode::IULt,
            IntCC::UnsignedLessThanOrEqual => Opcode::IULe,
        })
    }

    #[inline]
    #[must_use]
    pub const fn from_binary(op: BinaryOp) -> Option<Self> {
        Some(match op {
            BinaryOp::IAdd => Opcode::IAdd,
            BinaryOp::ISub => Opcode::ISub,
            BinaryOp::IMul => Opcode::IMul,
            BinaryOp::IDiv => Opcode::IDiv,
            BinaryOp::And => Opcode::And,
            BinaryOp::Or => Opcode::Or,
            BinaryOp::Xor => Opcode::Xor,
            BinaryOp::Ushr => Opcode::Ushr,
            BinaryOp::Ishl => Opcode::Ishl,
            BinaryOp::Band => Opcode::Band,
            BinaryOp::Bor => Opcode::Bor,
            _ => return None,
        })
    }

    #[inline]
    #[must_use]
    pub const fn fp_load(bits: u32) -> Option<Self> {
        Some(match bits {
             8 => Opcode::FpLoad8,
            16 => Opcode::FpLoad16,
            32 => Opcode::FpLoad32,
            64 => Opcode::FpLoad64,
            _ => return None
        })
    }

    #[inline]
    #[must_use]
    pub const fn fp_store(bits: u32) -> Option<Self> {
        Some(match bits {
             8 => Opcode::FpStore8,
            16 => Opcode::FpStore16,
            32 => Opcode::FpStore32,
            64 => Opcode::FpStore64,
            _ => return None
        })
    }
}

/// Stack slot allocation information
#[derive(Debug, Clone)]
pub struct StackSlotAllocation {
    pub offset: u32,    // Offset from frame pointer (negative for locals)
    pub size: u32,      // Size in bytes
    pub ty: Type,       // Type of the slot
}

/// Stack frame layout information
#[derive(Debug, Clone, Default)]
pub struct StackFrameInfo {
    pub regs_used: u32,
    pub total_size: u32,
    pub slot_allocations: IndexMap<StackSlot, StackSlotAllocation>,
}

impl StackFrameInfo {
    /// Calculate stack frame layout for the given function
    #[must_use]
    pub fn calculate_layout(func: &SsaFunc) -> Self {
        let mut frame_info = StackFrameInfo::default();
        let mut curr_offset = 0u32; // start at FP+0

        // Allocate stack slots (growing upward)
        for (slot_idx, slot_data) in func.stack_slots.iter().enumerate() {
            let slot = StackSlot::from_u32(slot_idx as _);
            let align = slot_data.ty.align_bytes();

            // Align current offset upward
            curr_offset = util::align_up(curr_offset, align);

            let size = slot_data.size;
            frame_info.slot_allocations.insert(slot, StackSlotAllocation {
                size,
                offset: curr_offset,
                ty: slot_data.ty,
            });

            // Move current offset past this slot
            curr_offset += size;
        }

        // Total frame size (still aligned to 16 bytes for ABI)
        frame_info.total_size = util::align_up(curr_offset, 16);

        frame_info.regs_used = func.dfg.values.len() as _;

        frame_info
    }
}

/// A chunk of bytecode for a single function.
#[derive(Debug, Clone, Default)]
pub struct BytecodeChunk {
    pub code: Vec<u8>,
    pub frame_info: StackFrameInfo,
}

impl BytecodeChunk {
    #[inline(always)]
    pub fn append<'a>(&mut self, x: impl IntoBytes<'a>) {
        self.code.extend_from_slice(&x.into_bytes());
    }

    #[inline(always)]
    pub fn append_placeholder_bytes(&mut self, n: usize) {
        let len = self.code.len();
        self.code.resize(len + n, 0);
    }

    #[inline(always)]
    pub fn append_placeholder<T>(&mut self) {
        self.append_placeholder_bytes(mem::size_of::<T>());
    }
}

//-////////////////////////////////////////////////////////////////////
// Bytecode Disassembler
//

pub fn disassemble_chunk(
    lowered_func: &LoweredSsaFunc,
    name: &str,
    print_metadata_: bool
) {
    println!("== {name} ==");
    println!("Frame size: {} bytes", lowered_func.chunk.frame_info.total_size);

    // Print stack slot allocations
    for (slot, allocation) in &lowered_func.chunk.frame_info.slot_allocations {
        println!("  s{}: {:?} at FP{:+} (size: {})",
                slot.index(), allocation.ty, allocation.offset, allocation.size);
    }
    println!();

    let mut offset = 0;
    let mut curr_block = None;
    while offset < lowered_func.chunk.code.len() {
        if print_metadata_ {
            print_metadata(
                lowered_func,
                offset,
                &mut curr_block
            );
        }

        offset = disassemble_instruction(
            &lowered_func.chunk,
            offset,
        );

        if offset == 0 {
            // Unknown opcode
            break
        }
    }
}

#[cfg(debug_assertions)]
fn print_metadata(
    lowered: &LoweredSsaFunc,
    offset: usize,
    curr_block: &mut Option<crate::ssa::Block>,
) {
    let offset_str = format!("{offset:05X} ");

    if let Some(crate::lower::LoInstMeta {
        pc, inst, size
    }) = lowered.context.pc_to_inst_meta.get(&offset) {
        // look up the block this instruction belongs to
        if let Some(&block) = lowered.context.func.layout.inst_blocks.get(inst)
            && Some(block) != *curr_block {
                *curr_block = Some(block);
                println!();
                println!("{offset_str} ; block({})", block.index());
            }

        println!();
        println!("{offset_str};");
        println!("{offset_str}; original SSA instruction:");
        println!("{offset_str}; {inst}", inst = lowered.context.func.pretty_print_inst(*inst));
        if let Some(comment) = lowered.context.func.metadata.comments.get(inst) {
            println!("{offset_str};");
            println!("{offset_str}; comment:");
            println!("{offset_str}; {comment}");
        }
        println!("{offset_str};");
        print!("{offset_str};");
        println!("  pc={pc:?} inst_id={inst:?}, size={size}");
        println!("{offset_str};");
    }
}

#[cfg(not(debug_assertions))]
fn print_metadata(
    _lowered: &LoweredSsaFunc,
    offset: usize,
    _curr_block: &mut Option<crate::ssa::Block>,
) {
    print!("{offset:05X}");
}

fn print_aligned(name: &str, operands: &str) {
    let mut output = String::with_capacity(name.len() + operands.len());
    let padding = 16 - name.len();
    let padding = " ".repeat(padding);
    output.push_str(name);
    output.push_str(&padding);

    let mut first = true;
    let mut operand_iter = operands.split(',').peekable();
    while let Some(operand) = operand_iter.next() {
        let operand = operand.trim();
        if !first {
            output.push_str(", ");
        }
        first = false;

        output.push_str(operand);

        if operand_iter.peek().is_some() {
            let padding = 10_usize.saturating_sub(operand.len());
            let padding = " ".repeat(padding);
            output.push_str(&padding);
        }
    }

    println!("{output}");
}

#[inline(always)]
fn read_u32_le(code: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(code[offset..offset + 4].try_into().unwrap())
}

fn read_args_for_disasm(chunk: &BytecodeChunk, mut offset: usize) -> (usize, String) {
    let count = chunk.code[offset];
    offset += 1;

    if count == 0 {
        return (offset, String::new());
    }

    let mut args_str = String::from(" (");
    for i in 0..count {
        if i > 0 {
            args_str.push_str(", ");
        }
        let reg = read_u32_le(&chunk.code, offset);
        args_str.push_str(&format!("v{reg}"));
        offset += 4;
    }
    args_str.push(')');

    (offset, args_str)
}

fn read_moves_for_disasm(chunk: &BytecodeChunk, mut offset: usize) -> (usize, String) {
    let count = chunk.code[offset];
    offset += 1;

    if count == 0 {
        return (offset, String::new());
    }

    let mut args_str = String::from(" (");
    for i in 0..count {
        if i > 0 {
            args_str.push_str(", ");
        }
        let dst = read_u32_le(&chunk.code, offset);
        let src = read_u32_le(&chunk.code, offset);
        args_str.push_str(&format!("v{dst} = v{src}"));
        offset += 8;
    }
    args_str.push(')');

    (offset, args_str)
}

pub fn disassemble_instruction(chunk: &BytecodeChunk, offset: usize) -> usize {
    let offset_str = format!("{offset:05X} ");
    print!("{offset_str}");

    let opcode_byte = chunk.code[offset];
    let opcode: Opcode = unsafe { std::mem::transmute(opcode_byte) };

    match opcode {
        Opcode::LoadDataAddr => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let data_id =
                u32::from_le_bytes(chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("LOAD_DATA_ADDR", &format!("v{dst}, D{data_id}"));
            offset + 9
        }

        Opcode::IConst8 => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let val = i8::from_le_bytes(chunk.code[offset + 5..offset + 6].try_into().unwrap());
            print_aligned("ICONST8", &format!("v{dst}, {val}_i8"));
            offset + 6
        }

        Opcode::IConst32 => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let val =
                u32::from_le_bytes(chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("ICONST32", &format!("v{dst}, {val}_i32"));
            offset + 9
        }

        Opcode::IConst64 => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let val =
                u64::from_le_bytes(chunk.code[offset + 5..offset + 13].try_into().unwrap());
            print_aligned("ICONST64", &format!("v{dst}, {val}_i64"));
            offset + 13
        }

        Opcode::FConst32 => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let val =
                f32::from_le_bytes(chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("FCONST32", &format!("v{dst}, {val}_f64"));
            offset + 9
        }

        Opcode::FConst64 => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let val =
                f64::from_le_bytes(chunk.code[offset + 5..offset + 13].try_into().unwrap());
            print_aligned("FCONST64", &format!("v{dst}, {val}_f64"));
            offset + 13
        }

        // Binary int ops
        Opcode::Ishl | Opcode::IAdd | Opcode::ISub | Opcode::IMul | Opcode::IDiv |
        Opcode::And  | Opcode::Or   | Opcode::Xor  | Opcode::Band |
        Opcode::IEq | Opcode::INe | Opcode::ISGt | Opcode::ISGe |
        Opcode::ISLt | Opcode::ISLe | Opcode::IUGt | Opcode::IUGe | Opcode::IULt | Opcode::IULe => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let a   = read_u32_le(&chunk.code, offset + 5);
            let b   = read_u32_le(&chunk.code, offset + 9);
            let name = match opcode {
                Opcode::Ishl => "ISHL",
                Opcode::IAdd => "IADD",
                Opcode::ISub => "ISUB",
                Opcode::IMul => "IMUL",
                Opcode::IDiv => "IDIV",
                Opcode::And  => "AND",
                Opcode::Band => "BAND",
                Opcode::Or   => "OR",
                Opcode::Xor  => "XOR",
                Opcode::IEq  => "IEQ",
                Opcode::INe  => "INE",
                Opcode::ISGt => "ISGT",
                Opcode::ISGe => "ISGE",
                Opcode::ISLt => "ISLT",
                Opcode::ISLe => "ISLE",
                Opcode::IUGt => "IUGT",
                Opcode::IUGe => "IUGE",
                Opcode::IULt => "IULT",
                Opcode::IULe => "IULE",
                _ => unreachable!(),
            };
            print_aligned(name, &format!("v{dst}, v{a}, v{b}"));
            offset + 13
        }

        // Float ops
        Opcode::FAdd | Opcode::FSub | Opcode::FMul | Opcode::FDiv => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let a   = read_u32_le(&chunk.code, offset + 5);
            let b   = read_u32_le(&chunk.code, offset + 9);
            let op_name = match opcode {
                Opcode::FAdd => "FADD",
                Opcode::FSub => "FSUB",
                Opcode::FMul => "FMUL",
                Opcode::FDiv => "FDIV",
                _ => unreachable!(),
            };
            print_aligned(op_name, &format!("v{dst}, v{a}, v{b}"));
            offset + 13
        }

        // Memory loads/stores
        Opcode::Load8 | Opcode::Load16 | Opcode::Load32 | Opcode::Load64 => {
            let dst  = read_u32_le(&chunk.code, offset + 1);
            let addr = read_u32_le(&chunk.code, offset + 5);
            let name = match opcode {
                Opcode::Load8  => "LOAD8",
                Opcode::Load16 => "LOAD16",
                Opcode::Load32 => "LOAD32",
                Opcode::Load64 => "LOAD64",
                _ => unreachable!(),
            };
            print_aligned(name, &format!("v{dst}, v{addr}"));
            offset + 9
        }

        Opcode::Store8 | Opcode::Store32 | Opcode::Store64 => {
            let addr = read_u32_le(&chunk.code, offset + 1);
            let val  = read_u32_le(&chunk.code, offset + 5);
            let name = match opcode {
                Opcode::Store8  => "STORE8",
                Opcode::Store32 => "STORE32",
                Opcode::Store64 => "STORE64",
                _ => unreachable!(),
            };
            print_aligned(name, &format!("v{addr}, v{val}"));
            offset + 9
        }

        Opcode::Jump16 => {
            let jmp =
                i16::from_le_bytes(chunk.code[offset + 1..offset + 3].try_into().unwrap());
            let (new_offset, args_str) = read_moves_for_disasm(chunk, offset + 3);
            let sign = if jmp < 0 { "-" } else { "+" };
            let target_addr = offset as i16 + 3 + jmp;
            print_aligned("JUMP16", &format!("{target_addr:04X} ({sign}0x{jmp:X}){args_str}"));
            new_offset
        }

        Opcode::BranchIf16 => {
            let cond = read_u32_le(&chunk.code, offset + 1);
            let jmp =
                i16::from_le_bytes(chunk.code[offset + 5..offset + 7].try_into().unwrap());
            let (new_offset, args_str) = read_moves_for_disasm(chunk, offset + 7);
            let target_addr = offset as i16 + 7 + jmp;
            let sign = if jmp < 0 { "-" } else { "+" };
            print_aligned("BRANCH_IF16", &format!("v{cond}, {target_addr:04X} ({sign}0x{jmp:X}){args_str}"));
            new_offset
        }

        Opcode::Call => {
            let ret_reg = read_u32_le(&chunk.code, offset + 1);
            let key =
                u64::from_le_bytes(chunk.code[offset + 5..offset + 13].try_into().unwrap());
            let (new_offset, args_str) = read_args_for_disasm(chunk, offset + 13);
            let module_id = key >> 32;
            let func_id = key & 0xFFFFFFFF;
            if ret_reg != u32::MAX {
                print_aligned(&format!("v{ret_reg} = CALL"), &format!("FUNC_{func_id} ModuleId({module_id}){args_str}"));
            } else {
                print_aligned("CALL", &format!("FUNC_{func_id} ModuleId({module_id}){args_str}"));

            }
            new_offset
        }

        Opcode::CallExt => {
            let ret_reg = read_u32_le(&chunk.code, offset + 1);
            let key =
                u64::from_le_bytes(chunk.code[offset + 5..offset + 13].try_into().unwrap());
            let (new_offset, args_str) = read_args_for_disasm(chunk, offset + 13);
            let module_id = key >> 32;
            let func_id = key & 0xFFFFFFFF;
            if ret_reg != u32::MAX {
                print_aligned(&format!("v{ret_reg} = CALL_EXT"), &format!("EXT_{func_id} ModuleId({module_id}){args_str}"));
            } else {
                print_aligned("CALL_EXT", &format!("EXT_{func_id} ModuleId({module_id}){args_str}"));

            }
            new_offset
        }

        Opcode::CallHook => {
            let ret_reg = read_u32_le(&chunk.code, offset + 1);
            let hook_id =
                u32::from_le_bytes(chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let (new_offset, args_str) = read_args_for_disasm(chunk, offset + 9);
            if ret_reg != u32::MAX {
                print_aligned(&format!("v{ret_reg} = CALL_HOOK"), &format!("HOOK_{hook_id}{args_str}"));
            } else {
                print_aligned("CALL_HOOK", &format!("HOOK_{hook_id}{args_str}"));

            }
            new_offset
        }

        Opcode::Bor => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let a   = read_u32_le(&chunk.code, offset + 5);
            let b   = read_u32_le(&chunk.code, offset + 9);
            print_aligned("BOR", &format!("v{dst}, v{a}, v{b}"));
            offset + 13
        }

        Opcode::Ireduce => {
            let dst  = read_u32_le(&chunk.code, offset + 1);
            let src  = read_u32_le(&chunk.code, offset + 5);
            let bits = chunk.code[offset + 9];
            print_aligned("IREDUCE", &format!("v{dst}, v{src}, {bits}"));
            offset + 10
        }

        Opcode::Sextend => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let src = read_u32_le(&chunk.code, offset + 5);
            print_aligned("SEXTEND", &format!("v{dst}, v{src}"));
            offset + 9
        }

        Opcode::Uextend => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let src = read_u32_le(&chunk.code, offset + 5);
            let from_bits = chunk.code[offset + 9];
            let to_bits   = chunk.code[offset + 10];
            print_aligned("UEXTEND", &format!("v{dst}, v{src}, {from_bits}, {to_bits}"));
            offset + 11
        }

        Opcode::FPromote => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let src = read_u32_le(&chunk.code, offset + 5);
            print_aligned("FPROMOTE", &format!("v{dst}, v{src}"));
            offset + 9
        }

        Opcode::Bitcast => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let src = read_u32_le(&chunk.code, offset + 5);
            let ty  = chunk.code[offset + 9];
            print_aligned("BITCAST", &format!("v{dst}, v{src}, {ty}"));
            offset + 10
        }

        Opcode::Mov => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let src = read_u32_le(&chunk.code, offset + 5);
            print_aligned("MOV", &format!("v{dst}, v{src}"));
            offset + 9
        }

        Opcode::Return => {
            let (new_offset, args_str) = read_args_for_disasm(chunk, offset + 1);
            print_aligned("RETURN", &args_str.trim_start());
            new_offset
        }

        // Stack frame management
        Opcode::FrameSetup => {
            let size =
                u32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            print_aligned("FRAME_SETUP", &format!("{size}"));
            offset + 5
        }

        Opcode::FrameTeardown => {
            print_aligned("FRAME_TEARDOWN", "");
            offset + 1
        }

        // Frame-pointer-relative operations
        Opcode::FpLoad8 | Opcode::FpLoad16 | Opcode::FpLoad32 | Opcode::FpLoad64 => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let name = match opcode {
                Opcode::FpLoad8  => "FP_LOAD8",
                Opcode::FpLoad16 => "FP_LOAD16",
                Opcode::FpLoad32 => "FP_LOAD32",
                Opcode::FpLoad64 => "FP_LOAD64",
                _ => unreachable!(),
            };
            print_aligned(name, &format!("v{dst}, FP{fp_offset:+}"));
            offset + 9
        }

        Opcode::FpStore8 | Opcode::FpStore16 | Opcode::FpStore32 | Opcode::FpStore64 => {
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = read_u32_le(&chunk.code, offset + 5);
            let name = match opcode {
                Opcode::FpStore8  => "FP_STORE8",
                Opcode::FpStore16 => "FP_STORE16",
                Opcode::FpStore32 => "FP_STORE32",
                Opcode::FpStore64 => "FP_STORE64",
                _ => unreachable!(),
            };
            print_aligned(name, &format!("FP{fp_offset:+}, v{src}"));
            offset + 9
        }

        Opcode::FpAddr => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("FP_ADDR", &format!("v{dst}, FP{fp_offset:+}"));
            offset + 9
        }

        // Stack-pointer-relative operations
        Opcode::SpAdd | Opcode::SpSub => {
            let sp_offset =
                u32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let name = match opcode {
                Opcode::SpAdd => "SP_ADD",
                Opcode::SpSub => "SP_SUB",
                _ => unreachable!(),
            };
            print_aligned(name, &format!("{sp_offset}"));
            offset + 5
        }

        Opcode::SpAddr => {
            let dst = read_u32_le(&chunk.code, offset + 1);
            let sp_offset =
                i32::from_le_bytes(chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("SP_ADDR", &format!("v{dst}, SP{sp_offset:+}"));
            offset + 9
        }

        Opcode::Halt => {
            print_aligned("HALT", "");
            offset + 1
        }

        _ => {
            unimplemented!("disassembly not implemented for {:?}", opcode);
        }
    }
}
