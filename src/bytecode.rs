use crate::entity::EntityRef;
use crate::lower::LoweredSsaFunc;
use crate::util::{self, IntoBytes};
use crate::ssa::{
    Inst,
    Block,
    InstructionData as IData,
    SsaFunc,
    BinaryOp,
    StackSlot,
    UnaryOp,
    Type,
    Value
};

use std::mem;

use indexmap::IndexMap;

//-////////////////////////////////////////////////////////////////////
// Bytecode Data Structures
//

define_opcodes! {
    self,

    // Constants
    IConst8(dst: u32, val: i8)       = 0,
    @ IData::IConst { value, .. } if bits == 8 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let val = *value as i8;
        chunk.append(Opcode::IConst8);
        chunk.append(dst);
        chunk.append(val);
    },

    IConst16(dst: u32, val: i16)      = 1,
    @ IData::IConst { value, .. } if bits == 16 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let val = *value as i16;
        chunk.append(Opcode::IConst16);
        chunk.append(dst);
        chunk.append(val);
    },

    IConst32(dst: u32, val: i32)      = 2,
    @ IData::IConst { value, .. } if bits == 32 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let val = *value as i32;
        chunk.append(Opcode::IConst32);
        chunk.append(dst);
        chunk.append(val);
    },

    IConst64(dst: u32, val: i64)      = 3,
    @ IData::IConst { value, .. } if bits == 64 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let val = *value as i64;
        chunk.append(Opcode::IConst64);
        chunk.append(dst);
        chunk.append((val as u64));
    },

    FConst32(dst: u32, val: f32)      = 4,
    @ IData::FConst { value, .. } if bits == 32 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let val = *value as f32;
        chunk.append(Opcode::FConst32);
        chunk.append(dst);
        chunk.append(val);
    },

    FConst64(dst: u32, val: f64)      = 5,
    @ IData::FConst { value, .. } if bits == 64 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        chunk.append(Opcode::FConst64);
        chunk.append(dst);
        chunk.append(*value);
    },

    // Arithmetic
    IAdd(dst: u32, a: u32, b: u32)           = 10,
    @ IData::Binary { binop: BinaryOp::IAdd, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::IAdd);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    ISub(dst: u32, a: u32, b: u32)           = 11,
    @ IData::Binary { binop: BinaryOp::ISub, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::ISub);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    IMul(dst: u32, a: u32, b: u32)           = 12,
    @ IData::Binary { binop: BinaryOp::IMul, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::IMul);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    IDiv(dst: u32, a: u32, b: u32)           = 13,
    @ IData::Binary { binop: BinaryOp::IDiv, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::IDiv);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    And(dst: u32, a: u32, b: u32)            = 14,
    @ IData::Binary { binop: BinaryOp::And, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::And);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    Or(dst: u32, a: u32, b: u32)             = 15,
    @ IData::Binary { binop: BinaryOp::Or, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::Or);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    Xor(dst: u32, a: u32, b: u32)            = 16,
    @ IData::Binary { binop: BinaryOp::Xor, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::Xor);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Ushr(dst: u32, a: u32, b: u32)            = 17,
    @ IData::Binary { binop: BinaryOp::Ushr, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::Ushr);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Ishl(dst: u32, a: u32, b: u32)            = 18,
    @ IData::Binary { binop: BinaryOp::Ishl, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::Ishl);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Band(dst: u32, a: u32, b: u32)            = 19,
    @ IData::Binary { binop: BinaryOp::Band, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::Band);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Bor(dst: u32, a: u32, b: u32)             = 20,
    @ IData::Binary { binop: BinaryOp::Bor, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::Bor);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    ILt(dst: u32, a: u32, b: u32)            = 21,
    @ IData::Binary { binop: BinaryOp::ILt, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::ILt);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FAdd(dst: u32, a: u32, b: u32)          = 22,
    @ IData::Binary { binop: BinaryOp::FAdd, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::FAdd);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FSub(dst: u32, a: u32, b: u32)          = 23,
    @ IData::Binary { binop: BinaryOp::FSub, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::FSub);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FMul(dst: u32, a: u32, b: u32)          = 24,
    @ IData::Binary { binop: BinaryOp::FMul, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::FMul);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FDiv(dst: u32, a: u32, b: u32)          = 25,
    @ IData::Binary { binop: BinaryOp::FDiv, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::FDiv);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Jump16(offset: i32)        = 26,
    @ IData::Jump { destination, .. } => |_results, chunk| {
        chunk.append(Opcode::Jump16);
        self.append_jump_placeholder::<i16>(chunk, *destination);
    },
    BranchIf16(cond: u32, offset: i32)    = 27,
    @ IData::Branch { arg, destinations, .. } => |_results, chunk| {
        let [t, e] = *destinations;

        let cond_slot = self.ssa_to_reg[arg];
        chunk.append(Opcode::BranchIf16);
        chunk.append(cond_slot);
        self.append_jump_placeholder::<i16>(chunk, t);

        // Unconditional jump for the false branch
        chunk.append(Opcode::Jump16);
        self.append_jump_placeholder::<i16>(chunk, e);
    },

    Return()        = 28,
    @ IData::Return { args, .. } => |_results, chunk| {
        // Move return values to the first N registers (r0, r1, ...).
        for (i, &arg) in args.iter().enumerate() {
            let arg_slot = self.ssa_to_reg[&arg];
            if arg_slot != i as u32 {
                chunk.append(Opcode::Mov);
                chunk.append(i as u32); // dst
                chunk.append(arg_slot);      // src
            }
        }

        // Emit frame teardown before return
        self.emit_frame_teardown(chunk);
        chunk.append(Opcode::Return);
    },

    Call(func_id: u32)          = 29,
    @ IData::Call { func_id, args, .. } => |results, chunk, inst_id| {
        // 0) Emit stores for spilled values live across this call
        let l = self.liveness();
        if let Some(vals) = l.live_across_call.get(&inst_id) {
            for &v in vals {
                if let Some(&spill_slot) = self.spill_slots.get(&v) {
                    let allocation = &self.frame_info.slot_allocations[&spill_slot];
                    let src_reg = self.ssa_to_reg[&v];
                    let opcode = Opcode::fp_store(allocation.ty.bits()).unwrap();
                    chunk.append(opcode);
                    chunk.append(allocation.offset as u32);
                    chunk.append(src_reg);
                }
            }
        }

        // 1) Move arguments to registers starting from r8.
        for (i, &arg) in args.iter().enumerate() {
            let arg_slot = self.ssa_to_reg[&arg];
            chunk.append(Opcode::Mov);
            chunk.append((i + 8) as u32); // dst
            chunk.append(arg_slot);         // src
        }

        // 2) Emit call
        chunk.append(Opcode::Call);
        chunk.append(func_id.index() as u32);

        // 3) Move result(s) from r0 to destination register(s) BEFORE reloading spills.
        let mut result_vals: Vec<Value> = Vec::new();
        if let Some(results) = results {
            if !results.is_empty() {
                result_vals.push(results[0]);
                let result_slot = self.ssa_to_reg[&results[0]];
                if result_slot != 0 {
                    chunk.append(Opcode::Mov);
                    chunk.append(result_slot); // dst
                    chunk.append(0u32);       // src (r0)
                }
            }
        }

        // 4) Reload spilled values, but skip values that are call results (we just wrote them).
        let l = self.liveness();
        if let Some(vals) = l.live_across_call.get(&inst_id) {
            for &v in vals {
                if result_vals.contains(&v) { continue; }
                if let Some(&spill_slot) = self.spill_slots.get(&v) {
                    let allocation = &self.frame_info.slot_allocations[&spill_slot];
                    let dst_reg = self.ssa_to_reg[&v];
                    let opcode = Opcode::fp_load(allocation.ty.bits()).unwrap();
                    chunk.append(opcode);
                    chunk.append(dst_reg);
                    chunk.append(allocation.offset as u32);
                }
            }
        }
    },

    Ireduce(dst: u32, src: u32) = 30,
    @ IData::Unary { unop: UnaryOp::Ireduce, arg } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let src = self.ssa_to_reg[arg];
        chunk.append(Opcode::Ireduce);
        chunk.append(dst);
        chunk.append(src);
    },
    Uextend(dst: u32, src: u32) = 31,
    @ IData::Unary { unop: UnaryOp::Uextend, arg } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let src = self.ssa_to_reg[arg];
        chunk.append(Opcode::Uextend);
        chunk.append(dst);
        chunk.append(src);
    },
    Sextend(dst: u32, src: u32) = 32,
    @ IData::Unary { unop: UnaryOp::Sextend, arg } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let src = self.ssa_to_reg[arg];
        chunk.append(Opcode::Sextend);
        chunk.append(dst);
        chunk.append(src);
    },

    // Memory
    Load8(dst: u32, addr: u32)         = 40,
    @ IData::LoadNoOffset { ty, addr } if bits == 8 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let addr = self.ssa_to_reg[addr];
        chunk.append(Opcode::Load8);
        chunk.append(dst);
        chunk.append(addr);
    },
    Load16(dst: u32, addr: u32)        = 41,
    @ IData::LoadNoOffset { ty, addr } if bits == 16 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let addr = self.ssa_to_reg[addr];
        chunk.append(Opcode::Load16);
        chunk.append(dst);
        chunk.append(addr);
    },
    Load32(dst: u32, addr: u32)        = 42,
    @ IData::LoadNoOffset { ty, addr } if bits == 32 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let addr = self.ssa_to_reg[addr];
        chunk.append(Opcode::Load32);
        chunk.append(dst);
        chunk.append(addr);
    },
    Load64(dst: u32, addr: u32)        = 43,
    @ IData::LoadNoOffset { ty, addr } if bits == 64 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let addr = self.ssa_to_reg[addr];
        chunk.append(Opcode::Load64);
        chunk.append(dst);
        chunk.append(addr);
    },

    Store8(addr: u32, val: u32) = 44,
    @ IData::StoreNoOffset { args } if bits == 8 => |_results, chunk| {
        let addr = self.ssa_to_reg[&args[0]];
        let val = self.ssa_to_reg[&args[1]];
        let opcode = Opcode::Store8;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    Store16(addr: u32, val: u32) = 45,
    @ IData::StoreNoOffset { args } if bits == 16 => |_results, chunk| {
        let addr = self.ssa_to_reg[&args[0]];
        let val = self.ssa_to_reg[&args[1]];
        let opcode = Opcode::Store16;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    Store32(addr: u32, val: u32) = 47,
    @ IData::StoreNoOffset { args } if bits == 32 => |_results, chunk| {
        let addr = self.ssa_to_reg[&args[0]];
        let val = self.ssa_to_reg[&args[1]];
        let opcode = Opcode::Store32;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    Store64(addr: u32, val: u32) = 47,
    @ IData::StoreNoOffset { args } if bits == 64 => |_results, chunk| {
        let addr = self.ssa_to_reg[&args[0]];
        let val = self.ssa_to_reg[&args[1]];
        let opcode = Opcode::Store64;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    // Stack operations
    Mov(dst: u32, src: u32)           = 50,

    // Stack frame management
    FrameSetup()    = 60,
    FrameTeardown() = 61,

    // Direct stack pointer operations
    SpAdd(offset: u32)         = 62,
    SpSub(offset: u32)         = 63,

    // Frame pointer relative operations
    FpLoad8(dst: u32, offset: i32)       = 70,
    @ IData::StackLoad { slot, .. } if bits == 8 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad8;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpLoad16(dst: u32, offset: i32)      = 71,
    @ IData::StackLoad { slot, .. } if bits == 16 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad16;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpLoad32(dst: u32, offset: i32)      = 72,
    @ IData::StackLoad { slot, .. } if bits == 32 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad32;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpLoad64(dst: u32, offset: i32)      = 73,
    @ IData::StackLoad { slot, .. } if bits == 64 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad64;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpStore8(offset: i32, src: u32)      = 74,
    @ IData::StackStore { slot, arg, .. } if bits == 8 => |_results, chunk| {
        let src = self.ssa_to_reg[arg];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore8;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    FpStore16(offset: i32, src: u32)     = 75,
    @ IData::StackStore { slot, arg, .. } if bits == 16 => |_results, chunk| {
        let src = self.ssa_to_reg[arg];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore16;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    FpStore32(offset: i32, src: u32)     = 76,
    @ IData::StackStore { slot, arg, .. } if bits == 32 => |_results, chunk| {
        let src = self.ssa_to_reg[arg];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore32;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    FpStore64(offset: i32, src: u32)     = 77,
    @ IData::StackStore { slot, arg, .. } if bits == 64 => |_results, chunk| {
        let src = self.ssa_to_reg[arg];
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
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];

        chunk.append(Opcode::FpAddr);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    SpAddr(dst: u32, offset: i32)        = 91,

    LoadDataAddr(dst: u32, data_id: DataId) = 95,
    @ IData::DataAddr { data_id } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        chunk.append(Opcode::LoadDataAddr);
        chunk.append(dst);
        chunk.append(*data_id);
    },

    Nop() = 128,
    @ IData::Nop => |results, chunk| {
        chunk.append(Opcode::Nop);
    },

    // VM control
    Halt()          = 255,
    @ IData::Unreachable => |results, chunk| {
        chunk.append(Opcode::Halt);
    }
}

impl Opcode {
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
    pub total_size: u32,
    pub slot_allocations: IndexMap<StackSlot, StackSlotAllocation>,
}

impl StackFrameInfo {
    /// Calculate stack frame layout for the given function
    #[must_use]
    pub fn calculate_layout(func: &SsaFunc) -> Self {
        let mut frame_info = StackFrameInfo::default();
        let mut current_offset = 0u32; // start at FP+0

        // Allocate stack slots (growing upward)
        for (slot_idx, slot_data) in func.stack_slots.iter().enumerate() {
            let slot = StackSlot::from_u32(slot_idx as _);
            let align = slot_data.ty.align_bytes() as u32;

            // Align current offset upward
            current_offset = util::align_up(current_offset, align);

            let size = slot_data.size;
            frame_info.slot_allocations.insert(slot, StackSlotAllocation {
                size,
                offset: current_offset,
                ty: slot_data.ty,
            });

            // Move current offset past this slot
            current_offset += size;
        }

        // Total frame size (still aligned to 16 bytes for ABI)
        frame_info.total_size = util::align_up(current_offset as u32, 16);

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

pub fn disassemble_chunk(lowered_func: &LoweredSsaFunc, name: &str) {
    let print_metadata = false;

    println!("== {name} ==");
    println!("Frame size: {} bytes", lowered_func.chunk.frame_info.total_size);

    // Print stack slot allocations
    for (slot, allocation) in &lowered_func.chunk.frame_info.slot_allocations {
        println!("  s{}: {:?} at FP{:+} (size: {})",
                slot.index(), allocation.ty, allocation.offset, allocation.size);
    }
    println!();

    let mut offset = 0;
    let mut curr_block: Option<Block> = None;
    while offset < lowered_func.chunk.code.len() {
        offset = disassemble_instruction(
            lowered_func,
            offset,
            &mut curr_block,
            print_metadata
        );

        if offset == 0 {
            // Unknown opcode
            break
        }
    }
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
            let padding = 10 - operand.len();
            let padding = " ".repeat(padding);
            output.push_str(&padding);
        }
    }

    println!("{output}");
}

#[must_use]
#[cfg_attr(not(debug_assertions), allow(unused, dead_code))]
pub fn disassemble_instruction(
    lowered: &LoweredSsaFunc,
    offset: usize,
    current_block: &mut Option<Block>,
    print_metadata: bool,
) -> usize {
    let offset_str = format!("{offset:05X} ");

    #[cfg(debug_assertions)]
    if print_metadata {
        if let Some(crate::lower::LoInstMeta { pc, inst, size }) =
            lowered.context.pc_to_inst_meta.get(&offset)
        {
            // look up the block this instruction belongs to
            if let Some(&block) = lowered.context.func.layout.inst_blocks.get(inst) {
                if Some(block) != *current_block {
                    *current_block = Some(block);
                    println!();
                    println!("{offset_str} ; block({})", block.index());
                }
            }

            println!();
            println!("{offset_str};");
            print!("{offset_str};");
            println!("{}", lowered.context.func.pretty_print_inst(*inst));
            println!("{offset_str};");
            print!("{offset_str};");
            println!("  pc={pc:?} inst_id={inst:?}, size={size}");
            println!("{offset_str};");
        }
    }

    print!("{offset_str}");

    let opcode_byte = lowered.chunk.code[offset];
    let opcode: Opcode = unsafe { std::mem::transmute(opcode_byte) };

    match opcode {
        Opcode::LoadDataAddr => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let data_id =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("LOAD_DATA_ADDR", &format!("v{dst}, D{data_id}"));
            offset + 9
        }
        Opcode::IConst32 => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("ICONST32", &format!("v{dst}, {val}_i32"));
            offset + 9
        }
        Opcode::IConst64 => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val =
                u64::from_le_bytes(lowered.chunk.code[offset + 5..offset + 13].try_into().unwrap());
            print_aligned("ICONST64", &format!("v{dst}, {val}_i64"));
            offset + 13
        }
        Opcode::FConst64 => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val =
                f64::from_le_bytes(lowered.chunk.code[offset + 5..offset + 13].try_into().unwrap());
            print_aligned("FCONST64", &format!("v{dst}, {val}_f64"));
            offset + 13
        }
        Opcode::IAdd => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b =
                u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            print_aligned("IADD", &format!("v{dst}, v{a}, v{b}"));
            offset + 13
        }
        Opcode::ISub => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b =
                u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            print_aligned("ISUB", &format!("v{dst}, v{a}, v{b}"));
            offset + 13
        }
        Opcode::IMul => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b =
                u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            print_aligned("IMUL", &format!("v{dst}, v{a}, v{b}"));
            offset + 13
        }
        Opcode::IDiv => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b =
                u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            print_aligned("IDIV", &format!("v{dst}, v{a}, v{b}"));
            offset + 13
        }
        Opcode::And => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b =
                u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            print_aligned("AND", &format!("v{dst}, v{a}, v{b}"));
            offset + 13
        }
        Opcode::Or => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b =
                u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            print_aligned("OR", &format!("v{dst}, v{a}, v{b}"));
            offset + 13
        }
        Opcode::Xor => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b =
                u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            print_aligned("XOR", &format!("v{dst}, v{a}, v{b}"));
            offset + 13
        }
        Opcode::ILt => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b =
                u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            print_aligned("LT", &format!("v{dst}, v{a}, v{b}"));
            offset + 13
        }
        Opcode::FAdd | Opcode::FSub | Opcode::FMul | Opcode::FDiv => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b =
                u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
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
        Opcode::Load32 => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let addr =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("LOAD32", &format!("v{dst}, v{addr}"));
            offset + 9
        }
        Opcode::Load64 => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let addr =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("LOAD64", &format!("v{dst}, v{addr}"));
            offset + 9
        }
        Opcode::Store32 => {
            let addr =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("STORE32", &format!("v{addr}, v{val}"));
            offset + 9
        }
        Opcode::Store64 => {
            let addr =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("STORE64", &format!("v{addr}, v{val}"));
            offset + 9
        }
        Opcode::Jump16 => {
            let jmp =
                i16::from_le_bytes(lowered.chunk.code[offset + 1..offset + 3].try_into().unwrap());
            let sign = if jmp < 0 { "-" } else { "+" };
            let target_addr = offset as i16 + 3 + jmp;
            print_aligned(
                "JUMP16",
                &format!("{target_addr:04X} ({sign}0x{jmp:X})"),
            );
            offset + 3
        }
        Opcode::BranchIf16 => {
            let cond =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let jmp =
                i16::from_le_bytes(lowered.chunk.code[offset + 5..offset + 7].try_into().unwrap());
            let target_addr = offset as i16 + 7 + jmp;
            let sign = if jmp < 0 { "-" } else { "+" };
            print_aligned(
                "BRANCH_IF16",
                &format!("v{cond}, {target_addr:04X} ({sign}0x{jmp:X})"),
            );
            offset + 7
        }
        Opcode::Call => {
            let func_id =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            print_aligned("CALL", &format!("F{func_id}"));
            offset + 5
        }
        Opcode::Mov => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("MOV", &format!("v{dst}, v{src}"));
            offset + 9
        }
        Opcode::Return => {
            print_aligned("RETURN", "");
            offset + 1
        }

        // New stack frame operations
        Opcode::FrameSetup => {
            let size =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            print_aligned("FRAME_SETUP", &format!("{size}"));
            offset + 5
        }
        Opcode::FrameTeardown => {
            print_aligned("FRAME_TEARDOWN", "");
            offset + 1
        }

        // Frame pointer relative operations
        Opcode::FpLoad32 => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset =
                i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("FP_LOAD32", &format!("v{dst}, FP{fp_offset:+}"));
            offset + 9
        }
        Opcode::FpLoad64 => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset =
                i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("FP_LOAD64", &format!("v{dst}, FP{fp_offset:+}"));
            offset + 9
        }
        Opcode::FpStore32 => {
            let fp_offset =
                i32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("FP_STORE32", &format!("FP{fp_offset:+}, v{src}"));
            offset + 9
        }
        Opcode::FpStore64 => {
            let fp_offset =
                i32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src =
                u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("FP_STORE64", &format!("FP{fp_offset:+}, v{src}"));
            offset + 9
        }
        Opcode::FpAddr => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset =
                i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("FP_ADDR", &format!("v{dst}, FP{fp_offset:+}"));
            offset + 9
        }

        // Stack pointer operations
        Opcode::SpAdd => {
            let sp_offset =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            print_aligned("SP_ADD", &format!("{sp_offset}"));
            offset + 5
        }
        Opcode::SpSub => {
            let sp_offset =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            print_aligned("SP_SUB", &format!("{sp_offset}"));
            offset + 5
        }
        Opcode::SpAddr => {
            let dst =
                u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let sp_offset =
                i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            print_aligned("SP_ADDR", &format!("v{dst}, SP{sp_offset:+}"));
            offset + 9
        }

        _ => {
            println!("Unknown opcode: {opcode_byte}");
            0
        }
    }
}

