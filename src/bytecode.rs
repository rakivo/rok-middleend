use crate::util::{self, IntoBytes};
use crate::ssa::{
    BinaryOp,
    DataId,
    FloatCC,
    Inst,
    InstructionData as IData,
    IntCC,
    SsaFunc,
    StackSlot,
    Type,
    UnaryOp,
};

use core::mem;

use rok_entity::PrimaryMap;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Loc<T> {
    Slot(T),
    Scratch,
}

// moves: (src, dst) pairs, meaning "dst := src". All dst values must be
// distinct (one write per destination, which block params always are).
//
// Returns a sequence of (src, dst) steps safe to execute in order, with
// Scratch used to break any cycles (e.g. a, b = b, a).
pub fn sequentialize_moves<T: Copy + Eq>(moves: &[(T, T)]) -> Vec<(Loc<T>, Loc<T>)> {
    let mut pending: Vec<(Loc<T>, T)> =
        moves.iter().map(|&(src, dst)| (Loc::Slot(src), dst)).collect();
    let mut result: Vec<(Loc<T>, Loc<T>)> = Vec::with_capacity(pending.len());

    while !pending.is_empty() {
        // A move is safe to do now if nothing still pending needs to read
        // its destination first.
        let ready = pending.iter().position(|&(_, dst)| {
            !pending.iter().any(|&(src, _)| src == Loc::Slot(dst))
        });

        if let Some(idx) = ready {
            let (src, dst) = pending.remove(idx);
            result.push((src, Loc::Slot(dst)));
            continue;
        }

        // Every remaining move is part of a cycle. Save the destination's
        // current value in scratch before it gets overwritten, perform the
        // move, then redirect anyone still waiting to read that old
        // destination value so they read scratch instead.
        let (src, dst) = pending.remove(0);
        result.push((Loc::Slot(dst), Loc::Scratch));
        result.push((src, Loc::Slot(dst)));
        for m in pending.iter_mut() {
            if m.0 == Loc::Slot(dst) {
                m.0 = Loc::Scratch;
            }
        }
    }

    result
}

define_opcodes! {
    self,

    // Constants
    IConst8(dst: u32, val: i8)
    @ IData::IConst { value, .. } if bits == 8 => |results, chunk| {
        let val = *value;
        let result_val = results.unwrap()[0];
        chunk.append(Opcode::IConst8);
        chunk.append(result_val.as_u32());
        chunk.append(val as i8);
    }

    IConst16(dst: u32, val: i16)
    @ IData::IConst { value, .. } if bits == 16 => |results, chunk| {
        let val = *value;
        let result_val = results.unwrap()[0];
        chunk.append(Opcode::IConst16);
        chunk.append(result_val.as_u32());
        chunk.append(val as i16);
    }

    IConst32(dst: u32, val: i32)
    @ IData::IConst { value, .. } if bits == 32 => |results, chunk| {
        let val = *value;
        let result_val = results.unwrap()[0];
        chunk.append(Opcode::IConst32);
        chunk.append(result_val.as_u32());
        chunk.append(val as i32);
    }

    IConst64(dst: u32, val: i64)
    @ IData::IConst { value, .. } if bits == 64 => |results, chunk| {
        let val = *value;
        let result_val = results.unwrap()[0];
        chunk.append(Opcode::IConst64);
        chunk.append(result_val.as_u32());
        chunk.append(val as u64);
    }

    FConst32(dst: u32, val: f32)
    @ IData::FConst { value, .. } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];;
        let val = *value as f32;
        chunk.append(Opcode::FConst32);
        chunk.append(dst.as_u32());
        chunk.append(val);
    }

    FConst64(dst: u32, val: f64)
    @ IData::FConst { value, .. } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];;
        chunk.append(Opcode::FConst64);
        chunk.append(dst.as_u32());
        chunk.append(*value);
    }

    // Arithmetic
    IAdd(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::IAdd, args } => |results, chunk| {
        let dst = results.unwrap()[0];;
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IAdd);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }
    ISub(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::ISub, args } => |results, chunk| {
        let dst = results.unwrap()[0];;
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISub);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }
    IMul(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::IMul, args } => |results, chunk| {
        let dst = results.unwrap()[0];;
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IMul);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }
    SDiv(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::SDiv, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::SDiv);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }
    UDiv(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::UDiv, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::UDiv);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    And(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::And, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::And);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }
    Or(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::Or, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Or);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }
    Xor(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::Xor, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Xor);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    Ushr(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::Ushr, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Ushr);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }
    Sshr(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::Sshr, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Sshr);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    Ishl(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::Ishl, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Ishl);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    Band(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::Band, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Band);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    Bor(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::Bor, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::Bor);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    SRem(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::SRem, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::SRem);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    URem(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::URem, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::URem);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    IEq(dst: u32, a: u32, b: u32)
    @ IData::Icmp { code: IntCC::Equal, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IEq);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    INe(dst: u32, a: u32, b: u32)
    @ IData::Icmp { code: IntCC::NotEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::INe);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    ISGt(dst: u32, a: u32, b: u32)
    @ IData::Icmp { code: IntCC::SignedGreaterThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISGt);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    ISGe(dst: u32, a: u32, b: u32)
    @ IData::Icmp { code: IntCC::SignedGreaterThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISGe);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    ISLt(dst: u32, a: u32, b: u32)
    @ IData::Icmp { code: IntCC::SignedLessThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISLt);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    ISLe(dst: u32, a: u32, b: u32)
    @ IData::Icmp { code: IntCC::SignedLessThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::ISLe);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    IUGt(dst: u32, a: u32, b: u32)
    @ IData::Icmp { code: IntCC::UnsignedGreaterThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IUGt);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    IUGe(dst: u32, a: u32, b: u32)
    @ IData::Icmp { code: IntCC::UnsignedGreaterThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IUGe);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    IULt(dst: u32, a: u32, b: u32)
    @ IData::Icmp { code: IntCC::UnsignedLessThan, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IULt);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    IULe(dst: u32, a: u32, b: u32)
    @ IData::Icmp { code: IntCC::UnsignedLessThanOrEqual, args } => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0];
        let b = args[1];
        chunk.append(Opcode::IULe);
        chunk.append(dst.as_u32());
        chunk.append(a.as_u32());
        chunk.append(b.as_u32());
    }

    FNeg32(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::FNeg, arg } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FNeg32);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }
    FNeg64(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::FNeg, arg } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FNeg64);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }

    FAdd32(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::FAdd, args } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FAdd32);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }
    FAdd64(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::FAdd, args } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FAdd64);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }

    FSub32(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::FSub, args } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FSub32);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }
    FSub64(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::FSub, args } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FSub64);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }

    FMul32(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::FMul, args } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FMul32);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }
    FMul64(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::FMul, args } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FMul64);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }

    FDiv32(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::FDiv, args } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FDiv32);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }
    FDiv64(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::FDiv, args } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FDiv64);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }

    FRem32(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::FRem, args } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FRem32);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }
    FRem64(dst: u32, a: u32, b: u32)
    @ IData::Binary { binop: BinaryOp::FRem, args } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FRem64);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }

    FEq32(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::Equal, args } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FEq32);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }
    FEq64(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::Equal, args } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FEq64);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }

    FNe32(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::NotEqual, args } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FNe32);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }
    FNe64(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::NotEqual, args } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FNe64);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }

    FGt32(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::GreaterThan, args } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FGt32);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }
    FGt64(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::GreaterThan, args } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FGt64);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }

    FGe32(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::GreaterThanOrEqual, args } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FGe32);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }
    FGe64(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::GreaterThanOrEqual, args } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FGe64);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }

    FLt32(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::LessThan, args } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FLt32);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }
    FLt64(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::LessThan, args } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FLt64);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }

    FLe32(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::LessThanOrEqual, args } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FLe32);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }
    FLe64(dst: u32, a: u32, b: u32)
    @ IData::Fcmp { code: FloatCC::LessThanOrEqual, args } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let a = args[0]; let b = args[1];
        chunk.append(Opcode::FLe64);
        chunk.append(dst.as_u32()); chunk.append(a.as_u32()); chunk.append(b.as_u32());
    }

    Jump32(offset: i32)
    @ IData::Jump { destination, args, .. } => |_results, chunk| {
        let dest_block = &self.func.cfg.blocks[*destination];

        chunk.append(Opcode::Jump32);
        self.jump_with_args(chunk, *destination, args);
    }

    BranchIf32(cond: u32, offset: i32)
    @ IData::Branch { arg, destinations, args, .. } => |_results, chunk| {
        let [t, e] = *destinations;
        let [t_args, e_args] = args;

        let cond_reg = *arg;
        chunk.append(Opcode::BranchIf32);
        chunk.append(cond_reg.as_u32());
        self.brif_with_args(chunk, t, t_args, e, e_args);
    }

    Return()
    @ IData::Return { args, .. } => |_results, chunk| {
        // Teardown stack frame
        self.emit_frame_teardown(chunk);

        // Emit return instruction with arguments
        chunk.append(Opcode::Return);
        self.append_args(chunk, args);
    }

    Call(func_id: u32)
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
    }

    CallHook(hook_id: u32)
    @ IData::CallHook { hook_id, args } => |results, chunk, inst_id| {
        chunk.append(Opcode::CallHook);
        if let Some(result) = results.and_then(|v| v.first()) {
            chunk.append(result.as_u32());
        } else {
            chunk.append(u32::MAX); // sentinel
        }
        chunk.append(hook_id.index() as u32);
        self.append_args(chunk, args);
    }

    CallExt(func_id: u32)
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
    }

    CallIndirect(callee: u32)
    @ IData::CallIndirect { callee, args } => |results, chunk, inst_id| {
        chunk.append(Opcode::CallIndirect);
        if let Some(results) = results {
            chunk.append(results.len() as u8);
            for result in results.iter() {
                chunk.append(result.as_u32());
            }
        } else {
            chunk.append(0u8);
        }
        chunk.append(callee.as_u32());
        self.append_args(chunk, args);
    }

    Ireduce(dst: u32, src: u32, bits: u32)
    @ IData::Unary { unop: UnaryOp::Ireduce, arg } => |results, chunk| {
        let result_ty = self.func.dfg.values[results.unwrap()[0]].ty;
        let bits = result_ty.bits() as u8;
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::Ireduce);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
        chunk.append(bits);
    }
    Uextend(dst: u32, src: u32, from_bits: u32, to_bits: u32)
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
    }
    Sextend(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::Sextend, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::Sextend);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }
    FPromote(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::FPromote, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        // @Note: We only support f32 and f64, so we're not
        // encoding the dst type ..
        chunk.append(Opcode::FPromote);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }
    FDemote(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::FDemote, arg } => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FDemote);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }

    FloatToSInt32(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::FloatToSInt, arg } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FloatToSInt32);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }
    FloatToUInt32(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::FloatToUInt, arg } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FloatToUInt32);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }
    SIntToFloat32(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::SIntToFloat, arg } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::SIntToFloat32);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }
    UIntToFloat32(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::UIntToFloat, arg } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::UIntToFloat32);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }

    FloatToSInt64(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::FloatToSInt, arg } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FloatToSInt64);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }
    FloatToUInt64(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::FloatToUInt, arg } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::FloatToUInt64);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }
    SIntToFloat64(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::SIntToFloat, arg } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::SIntToFloat64);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }
    UIntToFloat64(dst: u32, src: u32)
    @ IData::Unary { unop: UnaryOp::UIntToFloat, arg } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::UIntToFloat64);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
    }

    Bitcast(dst: u32, src: u32, ty: u32)
    @ IData::Unary { unop: UnaryOp::Bitcast, arg } => |results, chunk| {
        let result_ty = self.func.dfg.values[results.unwrap()[0]].ty;
        let dst = results.unwrap()[0];
        let src = *arg;
        chunk.append(Opcode::Bitcast);
        chunk.append(dst.as_u32());
        chunk.append(src.as_u32());
        chunk.append(result_ty.bits() as u8);
    }

    // Memory
    Load8(dst: u32, addr: u32)
    @ IData::LoadNoOffset { ty, addr } if bits == 8 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load8);
        chunk.append(dst.as_u32());
        chunk.append(addr.as_u32());
    }
    Load16(dst: u32, addr: u32)
    @ IData::LoadNoOffset { ty, addr } if bits == 16 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load16);
        chunk.append(dst.as_u32());
        chunk.append(addr.as_u32());
    }
    Load32(dst: u32, addr: u32)
    @ IData::LoadNoOffset { ty, addr } if bits == 32 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load32);
        chunk.append(dst.as_u32());
        chunk.append(addr.as_u32());
    }
    Load64(dst: u32, addr: u32)
    @ IData::LoadNoOffset { ty, addr } if bits == 64 => |results, chunk| {
        let addr = *addr;
        let dst = results.unwrap()[0];
        chunk.append(Opcode::Load64);
        chunk.append(dst.as_u32());
        chunk.append(addr.as_u32());
    }

    Store8(addr: u32, val: u32)
    @ IData::StoreNoOffset { args } if bits == 8 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store8;
        chunk.append(opcode);
        chunk.append(addr.as_u32());
        chunk.append(val.as_u32());
    }

    Store16(addr: u32, val: u32)
    @ IData::StoreNoOffset { args } if bits == 16 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store16;
        chunk.append(opcode);
        chunk.append(addr.as_u32());
        chunk.append(val.as_u32());
    }

    Store32(addr: u32, val: u32)
    @ IData::StoreNoOffset { args } if bits == 32 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store32;
        chunk.append(opcode);
        chunk.append(addr.as_u32());
        chunk.append(val.as_u32());
    }

    Store64(addr: u32, val: u32)
    @ IData::StoreNoOffset { args } if bits == 64 => |_results, chunk| {
        let addr = args[0];
        let val = args[1];
        let opcode = Opcode::Store64;
        chunk.append(opcode);
        chunk.append(addr.as_u32());
        chunk.append(val.as_u32());
    }

    // Stack operations
    Mov(dst: u32, src: u32)

    // Stack frame management
    FrameSetup(size: u32)
    FrameTeardown()

    // Direct stack pointer operations
    SpAdd(offset: u32)
    SpSub(offset: u32)

    // Frame pointer relative operations
    FpLoad8(dst: u32, offset: i32)
    @ IData::StackLoad { slot, .. } if bits == 8 => |results, chunk| {
        let dst = results.unwrap()[0];
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpLoad8;
        chunk.append(opcode);
        chunk.append(dst.as_u32());
        chunk.append(allocation.offset);
    }
    FpLoad16(dst: u32, offset: i32)
    @ IData::StackLoad { slot, .. } if bits == 16 => |results, chunk| {
        let dst = results.unwrap()[0];
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpLoad16;
        chunk.append(opcode);
        chunk.append(dst.as_u32());
        chunk.append(allocation.offset);
    }
    FpLoad32(dst: u32, offset: i32)
    @ IData::StackLoad { slot, .. } if bits == 32 => |results, chunk| {
        let dst = results.unwrap()[0];
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpLoad32;
        chunk.append(opcode);
        chunk.append(dst.as_u32());
        chunk.append(allocation.offset);
    }
    FpLoad64(dst: u32, offset: i32)
    @ IData::StackLoad { slot, .. } if bits == 64 => |results, chunk| {
        let dst = results.unwrap()[0];
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpLoad64;
        chunk.append(opcode);
        chunk.append(dst.as_u32());
        chunk.append(allocation.offset);
    }
    FpStore8(offset: i32, src: u32)
    @ IData::StackStore { slot, arg, .. } if bits == 8 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpStore8;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src.as_u32());
    }
    FpStore16(offset: i32, src: u32)
    @ IData::StackStore { slot, arg, .. } if bits == 16 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpStore16;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src.as_u32());
    }
    FpStore32(offset: i32, src: u32)
    @ IData::StackStore { slot, arg, .. } if bits == 32 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpStore32;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src.as_u32());
    }
    FpStore64(offset: i32, src: u32)
    @ IData::StackStore { slot, arg, .. } if bits == 64 => |_results, chunk| {
        let src = *arg;
        let allocation = &self.frame_info.slot_allocations[*slot];
        let opcode = Opcode::FpStore64;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src.as_u32());
    }

    // Stack pointer relative operations
    SpLoad8(dst: u32, offset: i32)
    SpLoad16(dst: u32, offset: i32)
    SpLoad32(dst: u32, offset: i32)
    SpLoad64(dst: u32, offset: i32)
    SpStore8(offset: i32, src: u32)
    SpStore16(offset: i32, src: u32)
    SpStore32(offset: i32, src: u32)
    SpStore64(offset: i32, src: u32)

    // Address calculation
    FpAddr(dst: u32, offset: i32)
    @ IData::StackAddr { slot, .. } => |results, chunk| {
        let dst = results.unwrap()[0];
        chunk.append(Opcode::FpAddr);
        chunk.append(dst.as_u32());
        let allocation = &self.frame_info.slot_allocations[*slot];
        chunk.append(allocation.offset);
    }
    SpAddr(dst: u32, offset: i32)

    LoadDataAddr(dst: u32, data_id: DataId)
    @ IData::DataAddr { data_id } => |results, chunk| {
        let dst = results.unwrap()[0];
        chunk.append(Opcode::LoadDataAddr);
        chunk.append(dst.as_u32());
        chunk.append(data_id.as_u32());
    }

    Nop()
    @ IData::Nop => |results, chunk| {}

    Halt()
    @ IData::Unreachable => |results, chunk| {
        chunk.append(Opcode::Halt);
    }
}

impl Opcode {

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
    pub slot_allocations: PrimaryMap<StackSlot, StackSlotAllocation>,
}

impl Default for StackFrameInfo {
    fn default() -> Self {
        Self {
            regs_used: u32::MAX,
            total_size: u32::MAX,
            slot_allocations: PrimaryMap::default()
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
        for (_, slot_data) in &func.stack_slots {
            let align = slot_data.ty.align_bytes();

            // Align current offset upward
            curr_offset = util::align_up(curr_offset, align);

            let size = slot_data.size;
            frame_info.slot_allocations.push(
                StackSlotAllocation {
                    size,
                    offset: curr_offset,
                    ty: slot_data.ty,
                },
            );

            curr_offset += size as u32;
        }

        // Total frame size (still aligned to 16 bytes for ABI..?)
        frame_info.total_size = util::align_up(curr_offset, 16);

        frame_info.regs_used = func.dfg.values.len() as _;

        frame_info
    }
}

#[derive(Debug, Clone, Default)]
pub struct BytecodeFunction {
    pub code: Vec<u8>,
    pub frame_info: StackFrameInfo,
}

impl BytecodeFunction {
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
