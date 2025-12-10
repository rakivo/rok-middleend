use crate::ssa::{
    BinaryOp, DataId, Inst, InstructionData as IData, IntCC, SsaFunc, StackSlot, Type, UnaryOp,
};
use crate::util::{self, IntoBytes};

use std::mem;

use rok_entity::SecondaryMap;

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
        chunk.append(dst.as_u32());
        chunk.append(val);
    },

    FConst64(dst: u32, val: f64)      = 5,
    @ IData::FConst { value, .. } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];;
        chunk.append(Opcode::FConst64);
        chunk.append(dst.as_u32());
        chunk.append(*value);
    },

    // Arithmetic
    IAdd(dst: u32, a: u32, b: u32)           = 10,
    @ IData::Binary { binop: BinaryOp::IAdd, args } => |results, chunk| {
        let dst = results.unwrap()[0];;
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IAdd);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },
    ISub(dst: u32, a: u32, b: u32)           = 11,
    @ IData::Binary { binop: BinaryOp::ISub, args } => |results, chunk| {
        let dst = results.unwrap()[0];;
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISub);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },
    IMul(dst: u32, a: u32, b: u32)           = 12,
    @ IData::Binary { binop: BinaryOp::IMul, args } => |results, chunk| {
        let dst = results.unwrap()[0];;
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IMul);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },
    IDiv(dst: u32, a: u32, b: u32)           = 13,
    @ IData::Binary { binop: BinaryOp::IDiv, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IDiv);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    And(dst: u32, a: u32, b: u32)            = 14,
    @ IData::Binary { binop: BinaryOp::And, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::And);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },
    Or(dst: u32, a: u32, b: u32)             = 15,
    @ IData::Binary { binop: BinaryOp::Or, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Or);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },
    Xor(dst: u32, a: u32, b: u32)            = 16,
    @ IData::Binary { binop: BinaryOp::Xor, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Xor);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    Ushr(dst: u32, a: u32, b: u32)            = 17,
    @ IData::Binary { binop: BinaryOp::Ushr, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Ushr);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    Ishl(dst: u32, a: u32, b: u32)            = 18,
    @ IData::Binary { binop: BinaryOp::Ishl, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Ishl);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    Band(dst: u32, a: u32, b: u32)            = 19,
    @ IData::Binary { binop: BinaryOp::Band, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Band);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    Bor(dst: u32, a: u32, b: u32)             = 20,
    @ IData::Binary { binop: BinaryOp::Bor, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Bor);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },


    IEq(dst: u32, a: u32, b: u32)            = 96,
    @ IData::Icmp { code: IntCC::Equal, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IEq);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    INe(dst: u32, a: u32, b: u32)            = 97,
    @ IData::Icmp { code: IntCC::NotEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::INe);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    ISGt(dst: u32, a: u32, b: u32)           = 98,
    @ IData::Icmp { code: IntCC::SignedGreaterThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISGt);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    ISGe(dst: u32, a: u32, b: u32)           = 99,
    @ IData::Icmp { code: IntCC::SignedGreaterThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISGe);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    ISLt(dst: u32, a: u32, b: u32)           = 100,
    @ IData::Icmp { code: IntCC::SignedLessThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISLt);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    ISLe(dst: u32, a: u32, b: u32)           = 101,
    @ IData::Icmp { code: IntCC::SignedLessThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISLe);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    IUGt(dst: u32, a: u32, b: u32)           = 102,
    @ IData::Icmp { code: IntCC::UnsignedGreaterThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IUGt);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    IUGe(dst: u32, a: u32, b: u32)           = 103,
    @ IData::Icmp { code: IntCC::UnsignedGreaterThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IUGe);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    IULt(dst: u32, a: u32, b: u32)           = 104,
    @ IData::Icmp { code: IntCC::UnsignedLessThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IULt);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    IULe(dst: u32, a: u32, b: u32)           = 105,
    @ IData::Icmp { code: IntCC::UnsignedLessThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IULe);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    FAdd(dst: u32, a: u32, b: u32)          = 22,
    @ IData::Binary { binop: BinaryOp::FAdd, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::FAdd);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },
    FSub(dst: u32, a: u32, b: u32)          = 23,
    @ IData::Binary { binop: BinaryOp::FSub, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::FSub);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },
    FMul(dst: u32, a: u32, b: u32)          = 24,
    @ IData::Binary { binop: BinaryOp::FMul, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::FMul);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },
    FDiv(dst: u32, a: u32, b: u32)          = 25,
    @ IData::Binary { binop: BinaryOp::FDiv, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::FDiv);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    },

    Jump16(offset: i16) = 26,
    @ IData::Jump { destination, args, .. } => |_results, chunk| {
        let dest_block = &self.func.cfg.blocks[*destination];

        chunk.append(Opcode::Jump16);
        self.jump_with_args(chunk, *destination, args);
    },

    BranchIf16(cond: u32, offset: i16) = 27,
    @ IData::Branch { arg, destinations, args, .. } => |_results, chunk| {
        let [t, e] = *destinations;

        let cond_reg = *arg;
        chunk.append(Opcode::BranchIf16);
        chunk.append(cond_reg.as_u32());
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

    Call(func_id: u32) = 29,
    @ IData::Call { func_id, args } => |results, chunk, inst_id| {
        chunk.append(Opcode::Call);
        if let Some(results) = results {
            chunk.append(results.len() as u8);
            for result in results.iter() {
                chunk.append(result.as_u32());
            }
        } else {
            chunk.append(0u8);
        }
        chunk.append(func_id.as_u32());
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

    CallExt(func_id: u32) = 136,
    @ IData::CallExt { func_id, args } => |results, chunk, inst_id| {
        chunk.append(Opcode::CallExt);
        if let Some(results) = results {
            chunk.append(results.len() as u8);
            for result in results.iter() {
                chunk.append(result.as_u32());
            }
        } else {
            chunk.append(0u8);
        }
        chunk.append(func_id.as_u32());
        self.append_args(chunk, args);
    },

    Ireduce(dst: u32, src: u32, bits: u32) = 30,
    @ IData::Unary { unop: UnaryOp::Ireduce, arg } => |results, chunk| {
        let result_ty = self.func.dfg.values[results.unwrap()[0]].ty;
        let bits = result_ty.bits() as u8;
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::Ireduce);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
        chunk.append(bits);
    },
    Uextend(dst: u32, src: u32, from_bits: u32, to_bits: u32) = 31,
    @ IData::Unary { unop: UnaryOp::Uextend, arg } => |results, chunk| {
        let src_ty = self.func.dfg.values[*arg].ty;
        let dst_ty = self.func.dfg.values[results.unwrap()[0]].ty;
        let from_bits = src_ty.bits() as u8;
        let to_bits = dst_ty.bits() as u8;
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::Uextend);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
        chunk.append(from_bits);
        chunk.append(to_bits);
    },
    Sextend(dst: u32, src: u32) = 32,
    @ IData::Unary { unop: UnaryOp::Sextend, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::Sextend);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    },
    FPromote(dst: u32, src: u32) = 67,
    @ IData::Unary { unop: UnaryOp::FPromote, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        // @Note: We only support f32 and f64, so we're not
        // encoding the dst type ..
        chunk.append(Opcode::FPromote);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    },
    FDemote(dst: u32, src: u32) = 200,
    @ IData::Unary { unop: UnaryOp::FDemote, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FDemote);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    },
    FloatToSInt(dst: u32, src: u32) = 201,
    @ IData::Unary { unop: UnaryOp::FloatToSInt, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FloatToSInt);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    },
    FloatToUInt(dst: u32, src: u32) = 202,
    @ IData::Unary { unop: UnaryOp::FloatToUInt, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FloatToUInt);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    },
    SIntToFloat(dst: u32, src: u32) = 203,
    @ IData::Unary { unop: UnaryOp::SIntToFloat, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::SIntToFloat);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    },
    UIntToFloat(dst: u32, src: u32) = 204,
    @ IData::Unary { unop: UnaryOp::UIntToFloat, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::UIntToFloat);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    },
    FNeg(dst: u32, src: u32) = 69,
    @ IData::Unary { unop: UnaryOp::FNeg, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FNeg);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    },
    Bitcast(dst: u32, src: u32, ty: u32) = 33,
    @ IData::Unary { unop: UnaryOp::Bitcast, arg } => |results, chunk| {
        let result_ty = self.func.dfg.values[results.unwrap()[0]].ty;
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::Bitcast);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
        chunk.append(result_ty.bits() as u8);
    },

    // Memory
    Load8(dst: u32, addr: u32)         = 40,
    @ IData::LoadNoOffset { ty, addr } if bits == 8 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load8);
        chunk.append(dst.as_u32());
        chunk.append(addr.as_u32());
    },
    Load16(dst: u32, addr: u32)        = 41,
    @ IData::LoadNoOffset { ty, addr } if bits == 16 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load16);
        chunk.append(dst.as_u32());
        chunk.append(addr.as_u32());
    },
    Load32(dst: u32, addr: u32)        = 42,
    @ IData::LoadNoOffset { ty, addr } if bits == 32 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load32);
        chunk.append(dst.as_u32());
        chunk.append(addr.as_u32());
    },
    Load64(dst: u32, addr: u32)        = 43,
    @ IData::LoadNoOffset { ty, addr } if bits == 64 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load64);
        chunk.append(dst.as_u32());
        chunk.append(addr.as_u32());
    },

    Store8(addr: u32, val: u32) = 44,
    @ IData::StoreNoOffset { args } if bits == 8 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store8;
        chunk.append(opcode);
        chunk.append(addr.as_u32());
        chunk.append(val.as_u32());
    },

    Store16(addr: u32, val: u32) = 45,
    @ IData::StoreNoOffset { args } if bits == 16 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store16;
        chunk.append(opcode);
        chunk.append(addr.as_u32());
        chunk.append(val.as_u32());
    },

    Store32(addr: u32, val: u32) = 47,
    @ IData::StoreNoOffset { args } if bits == 32 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store32;
        chunk.append(opcode);
        chunk.append(addr.as_u32());
        chunk.append(val.as_u32());
    },

    Store64(addr: u32, val: u32) = 47,
    @ IData::StoreNoOffset { args } if bits == 64 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store64;
        chunk.append(opcode);
        chunk.append(addr.as_u32());
        chunk.append(val.as_u32());
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
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpLoad8;
        chunk.append(opcode);
        chunk.append(dst.as_u32());
        chunk.append(allocation.offset);
    },
    FpLoad16(dst: u32, offset: i32)      = 71,
    @ IData::StackLoad { slot, .. } if bits == 16 => |results, chunk| {
        let dst = results.unwrap()[0];
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpLoad16;
        chunk.append(opcode);
        chunk.append(dst.as_u32());
        chunk.append(allocation.offset);
    },
    FpLoad32(dst: u32, offset: i32)      = 72,
    @ IData::StackLoad { slot, .. } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpLoad32;
        chunk.append(opcode);
        chunk.append(dst.as_u32());
        chunk.append(allocation.offset);
    },
    FpLoad64(dst: u32, offset: i32)      = 73,
    @ IData::StackLoad { slot, .. } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpLoad64;
        chunk.append(opcode);
        chunk.append(dst.as_u32());
        chunk.append(allocation.offset);
    },
    FpStore8(offset: i32, src: u32)      = 74,
    @ IData::StackStore { slot, arg, .. } if bits == 8 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpStore8;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src.as_u32());
    },
    FpStore16(offset: i32, src: u32)     = 75,
    @ IData::StackStore { slot, arg, .. } if bits == 16 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpStore16;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src.as_u32());
    },
    FpStore32(offset: i32, src: u32)     = 76,
    @ IData::StackStore { slot, arg, .. } if bits == 32 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpStore32;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src.as_u32());
    },
    FpStore64(offset: i32, src: u32)     = 77,
    @ IData::StackStore { slot, arg, .. } if bits == 64 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpStore64;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src.as_u32());
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
        chunk.append(dst.as_u32());
        let allocation = &self.frame_info.slot_allocations[*slot];
        chunk.append(allocation.offset);
    },
    SpAddr(dst: u32, offset: i32)        = 91,

    LoadDataAddr(dst: u32, data_id: DataId) = 95,
    @ IData::DataAddr { data_id } => |results, chunk| {
        let dst = results.unwrap()[0];
        chunk.append(Opcode::LoadDataAddr);
        chunk.append(dst.as_u32());
        chunk.append(data_id.as_u32());
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
            _ => return None,
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
            _ => return None,
        })
    }
}

/// Stack slot allocation information
#[derive(Eq, Debug, Clone, PartialEq)]
pub struct StackSlotAllocation {
    pub offset: u32, // Offset from frame pointer
    pub size: u16,   // Size in bytes
    pub ty: Type,    // Type of the slot
}

impl Default for StackSlotAllocation {
    fn default() -> Self {
        Self {
            offset: u32::MAX,
            size: u16::MAX,
            ty: Type::Ptr
        }
    }
}

/// Stack frame layout information
#[derive(Debug, Clone)]
pub struct StackFrameInfo {
    pub regs_used: u32,
    pub total_size: u32,
    pub slot_allocations: SecondaryMap<StackSlot, StackSlotAllocation>,
}

impl Default for StackFrameInfo {
    fn default() -> Self {
        Self {
            regs_used: u32::MAX,
            total_size: u32::MAX,
            slot_allocations: SecondaryMap::default()
        }
    }
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
            frame_info.slot_allocations.insert(
                slot,
                StackSlotAllocation {
                    size,
                    offset: curr_offset,
                    ty: slot_data.ty,
                },
            );

            // Move current offset past this slot
            curr_offset += size as u32;
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
