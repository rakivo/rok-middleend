use crate::entity::EntityRef;
use crate::lower::LoweredSsaFunc;
use crate::util::{self, IntoBytes};
use crate::ssa::{
    Inst,
    Block,
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
    IConst8(dst: u8, val: i8)       = 0,
    @ IData::IConst { value, .. } if bits == 8 => |results, chunk| {
        let val = *value;
        let result_val = results.unwrap()[0];
        self.emit_inst_with_result(chunk, result_val, |_, chunk, dst| {
            chunk.append(Opcode::IConst8);
            chunk.append(dst);
            chunk.append(val as i8);
        });
    },

    IConst16(dst: u8, val: i16)      = 1,
    @ IData::IConst { value, .. } if bits == 16 => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let val = *value as i16;
        chunk.append(Opcode::IConst16);
        chunk.append(dst);
        chunk.append(val);
    },

    IConst32(dst: u8, val: i32)      = 2,
    @ IData::IConst { value, .. } if bits == 32 => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let val = *value as i32;
        chunk.append(Opcode::IConst32);
        chunk.append(dst);
        chunk.append(val);
    },

    IConst64(dst: u8, val: i64)      = 3,
    @ IData::IConst { value, .. } if bits == 64 => |results, chunk| {
        let val = *value;
        let result_val = results.unwrap()[0];
        self.emit_inst_with_result(chunk, result_val, |_, chunk, dst| {
            chunk.append(Opcode::IConst64);
            chunk.append(dst);
            chunk.append(val as u64);
        });
    },

    FConst32(dst: u8, val: f32)      = 4,
    @ IData::FConst { value, .. } if bits == 32 => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let val = *value as f32;
        chunk.append(Opcode::FConst32);
        chunk.append(dst);
        chunk.append(val);
    },

    FConst64(dst: u8, val: f64)      = 5,
    @ IData::FConst { value, .. } if bits == 64 => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        chunk.append(Opcode::FConst64);
        chunk.append(dst);
        chunk.append(*value);
    },

    // Arithmetic
    IAdd(dst: u8, a: u8, b: u8)           = 10,
    @ IData::Binary { binop: BinaryOp::IAdd, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::IAdd);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    ISub(dst: u8, a: u8, b: u8)           = 11,
    @ IData::Binary { binop: BinaryOp::ISub, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::ISub);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    IMul(dst: u8, a: u8, b: u8)           = 12,
    @ IData::Binary { binop: BinaryOp::IMul, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::IMul);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    IDiv(dst: u8, a: u8, b: u8)           = 13,
    @ IData::Binary { binop: BinaryOp::IDiv, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::IDiv);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    And(dst: u8, a: u8, b: u8)            = 14,
    @ IData::Binary { binop: BinaryOp::And, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::And);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    Or(dst: u8, a: u8, b: u8)             = 15,
    @ IData::Binary { binop: BinaryOp::Or, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::Or);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    Xor(dst: u8, a: u8, b: u8)            = 16,
    @ IData::Binary { binop: BinaryOp::Xor, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::Xor);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Ushr(dst: u8, a: u8, b: u8)            = 17,
    @ IData::Binary { binop: BinaryOp::Ushr, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::Ushr);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Ishl(dst: u8, a: u8, b: u8)            = 18,
    @ IData::Binary { binop: BinaryOp::Ishl, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::Ishl);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Band(dst: u8, a: u8, b: u8)            = 19,
    @ IData::Binary { binop: BinaryOp::Band, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::Band);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Bor(dst: u8, a: u8, b: u8)             = 20,
    @ IData::Binary { binop: BinaryOp::Bor, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::Bor);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },


    IEq(dst: u8, a: u8, b: u8)            = 96,
    @ IData::Icmp { code: IntCC::Equal, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::IEq);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    INe(dst: u8, a: u8, b: u8)            = 97,
    @ IData::Icmp { code: IntCC::NotEqual, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::INe);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    ISGt(dst: u8, a: u8, b: u8)           = 98,
    @ IData::Icmp { code: IntCC::SignedGreaterThan, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::ISGt);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    ISGe(dst: u8, a: u8, b: u8)           = 99,
    @ IData::Icmp { code: IntCC::SignedGreaterThanOrEqual, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::ISGe);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    ISLt(dst: u8, a: u8, b: u8)           = 100,
    @ IData::Icmp { code: IntCC::SignedLessThan, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::ISLt);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    ISLe(dst: u8, a: u8, b: u8)           = 101,
    @ IData::Icmp { code: IntCC::SignedLessThanOrEqual, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::ISLe);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    IUGt(dst: u8, a: u8, b: u8)           = 102,
    @ IData::Icmp { code: IntCC::UnsignedGreaterThan, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::IUGt);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    IUGe(dst: u8, a: u8, b: u8)           = 103,
    @ IData::Icmp { code: IntCC::UnsignedGreaterThanOrEqual, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::IUGe);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    IULt(dst: u8, a: u8, b: u8)           = 104,
    @ IData::Icmp { code: IntCC::UnsignedLessThan, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::IULt);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    IULe(dst: u8, a: u8, b: u8)           = 105,
    @ IData::Icmp { code: IntCC::UnsignedLessThanOrEqual, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::IULe);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    FAdd(dst: u8, a: u8, b: u8)          = 22,
    @ IData::Binary { binop: BinaryOp::FAdd, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::FAdd);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FSub(dst: u8, a: u8, b: u8)          = 23,
    @ IData::Binary { binop: BinaryOp::FSub, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::FSub);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FMul(dst: u8, a: u8, b: u8)          = 24,
    @ IData::Binary { binop: BinaryOp::FMul, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::FMul);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FDiv(dst: u8, a: u8, b: u8)          = 25,
    @ IData::Binary { binop: BinaryOp::FDiv, args } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let a = self.load_value(chunk, args[0]);
        let b = self.load_value(chunk, args[1]);
        chunk.append(Opcode::FDiv);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Jump16(offset: i16)        = 26,
    @ IData::Jump { destination, args, .. } => |_results, chunk| {
        let dest_block = &self.func.cfg.blocks[destination.index()];

        // Move SSA values into destination block parameters
        for (i, &arg_value) in args.iter().enumerate() {
            let arg_val = self.load_value(chunk, arg_value);
            let param = dest_block.params[i];
            self.store_value(chunk, param, arg_val);
        }

        // Emit the jump
        chunk.append(Opcode::Jump16);
        self.append_jump_placeholder::<i16>(chunk, *destination);
    },
    BranchIf16(cond: u8, offset: i16)    = 27,
    @ IData::Branch { arg, destinations, args, .. } => |_results, chunk| {
        let [t, e] = *destinations;

        let true_dest_block = &self.func.cfg.blocks[t.index()];
        for (i, &arg_value) in args.iter().enumerate() {
            let arg_reg = self.load_value(chunk, arg_value);
            let param = true_dest_block.params[i];
            self.store_value(chunk, param, arg_reg);
        }

        let cond_slot = self.load_value(chunk, *arg);
        chunk.append(Opcode::BranchIf16);
        chunk.append(cond_slot);
        self.append_jump_placeholder::<i16>(chunk, t);

        let false_dest_block = &self.func.cfg.blocks[e.index()];
        for (i, &arg_value) in args.iter().enumerate() {
            let arg_reg = self.load_value(chunk, arg_value);
            let param = false_dest_block.params[i];
            self.store_value(chunk, param, arg_reg);
        }

        // Unconditional jump for the false branch
        chunk.append(Opcode::Jump16);
        self.append_jump_placeholder::<i16>(chunk, e);
    },

    Return()        = 28,
    @ IData::Return { args, .. } => |_results, chunk| {
        // Move return values to r0-r7
        for (i, &arg) in args.iter().take(8).enumerate() {
            let arg_reg = self.load_value(chunk, arg);
            let target_reg = i as u8; // r0, r1, r2, ... r7

            // Only emit move if source != destination
            if arg_reg != target_reg {
                chunk.append(Opcode::Mov);
                chunk.append(target_reg); // dst
                chunk.append(arg_reg);    // src
            }
        }

        // Teardown stack frame
        self.emit_frame_teardown(chunk);

        // Emit return instruction
        chunk.append(Opcode::Return);
    },

    Call(func_id: u32)          = 29,
    @ IData::Call { func_id, args, .. } => |results, chunk, inst_id| {
        // 1) Move arguments to r0-r7 (up to 8 args)
        for (i, &arg) in args.iter().take(8).enumerate() {
            let arg_reg = self.load_value(chunk, arg);
            let target_reg = i as u8; // r0, r1, r2, ... r7

            // Only emit move if source != destination
            if arg_reg != target_reg {
                chunk.append(Opcode::Mov);
                chunk.append(target_reg); // dst
                chunk.append(arg_reg);    // src
            }
        }

        // TODO(#18): Call: If more than 8 args, push extras onto stack
        // For now, assume <= 8 arguments
        if args.len() > 8 {
            panic!("Functions with more than 8 arguments not yet supported");
        }

        // 2) Emit call instruction
        chunk.append(Opcode::Call);
        chunk.append(func_id.index() as u32);

        // 3) Move result(s) from r0-r7 to destination register(s)
        // Results are already in r0-r7, just need to map them
        if let Some(results) = results {
            for (i, result) in results.iter().enumerate() {
                let return_reg = i as u8; // r0, r1, r2, ... r7
                self.store_value(chunk, *result, return_reg);
            }
        }
    },

    Ireduce(dst: u8, src: u8, bits: u8) = 30,
    @ IData::Unary { unop: UnaryOp::Ireduce, arg } => |results, chunk| {
        let result_ty = self.func.dfg.values[results.unwrap()[0].index()].ty;
        let bits = result_ty.bits() as u8;
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let src = self.load_value(chunk, *arg);
        chunk.append(Opcode::Ireduce);
        chunk.append(dst);
        chunk.append(src);
        chunk.append(bits);
    },
    Uextend(dst: u8, src: u8, from_bits: u8, to_bits: u8) = 31,
    @ IData::Unary { unop: UnaryOp::Uextend, arg } => |results, chunk| {
        let src_ty = self.func.dfg.values[arg.index()].ty;
        let dst_ty = self.func.dfg.values[results.unwrap()[0].index()].ty;
        let from_bits = src_ty.bits() as u8;
        let to_bits = dst_ty.bits() as u8;
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let src = self.load_value(chunk, *arg);
        chunk.append(Opcode::Uextend);
        chunk.append(dst);
        chunk.append(src);
        chunk.append(from_bits);
        chunk.append(to_bits);
    },
    Sextend(dst: u8, src: u8) = 32,
    @ IData::Unary { unop: UnaryOp::Sextend, arg } => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let src = self.load_value(chunk, *arg);
        chunk.append(Opcode::Sextend);
        chunk.append(dst);
        chunk.append(src);
    },

    // Memory
    Load8(dst: u8, addr: u8)         = 40,
    @ IData::LoadNoOffset { ty, addr } if bits == 8 => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let addr = self.load_value(chunk, *addr);
        chunk.append(Opcode::Load8);
        chunk.append(dst);
        chunk.append(addr);
    },
    Load16(dst: u8, addr: u8)        = 41,
    @ IData::LoadNoOffset { ty, addr } if bits == 16 => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let addr = self.load_value(chunk, *addr);
        chunk.append(Opcode::Load16);
        chunk.append(dst);
        chunk.append(addr);
    },
    Load32(dst: u8, addr: u8)        = 42,
    @ IData::LoadNoOffset { ty, addr } if bits == 32 => |results, chunk| {
        let addr = self.load_value(chunk, *addr);
        let result_val = results.unwrap()[0];
        self.emit_inst_with_result(chunk, result_val, |_, chunk, dst| {
            chunk.append(Opcode::Load32);
            chunk.append(dst);
            chunk.append(addr);
        });
    },
    Load64(dst: u8, addr: u8)        = 43,
    @ IData::LoadNoOffset { ty, addr } if bits == 64 => |results, chunk| {
        let addr = self.load_value(chunk, *addr);
        let result_val = results.unwrap()[0];
        self.emit_inst_with_result(chunk, result_val, |_, chunk, dst| {
            chunk.append(Opcode::Load64);
            chunk.append(dst);
            chunk.append(addr);
        });
    },

    Store8(addr: u8, val: u8) = 44,
    @ IData::StoreNoOffset { args } if bits == 8 => |_results, chunk| {
        let addr = self.load_value(chunk, args[0]);
        let val = self.load_value(chunk, args[1]);
        let opcode = Opcode::Store8;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    Store16(addr: u8, val: u8) = 45,
    @ IData::StoreNoOffset { args } if bits == 16 => |_results, chunk| {
        let addr = self.load_value(chunk, args[0]);
        let val = self.load_value(chunk, args[1]);
        let opcode = Opcode::Store16;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    Store32(addr: u8, val: u8) = 47,
    @ IData::StoreNoOffset { args } if bits == 32 => |_results, chunk| {
        let addr = self.load_value(chunk, args[0]);
        let val = self.load_value(chunk, args[1]);
        let opcode = Opcode::Store32;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    Store64(addr: u8, val: u8) = 47,
    @ IData::StoreNoOffset { args } if bits == 64 => |_results, chunk| {
        let addr = self.load_value(chunk, args[0]);
        let val = self.load_value(chunk, args[1]);
        let opcode = Opcode::Store64;
        chunk.append(opcode);
        chunk.append(addr);
        chunk.append(val);
    },

    // Stack operations
    Mov(dst: u8, src: u8)           = 50,

    // Stack frame management
    FrameSetup(size: u32)    = 60,
    FrameTeardown() = 61,

    // Direct stack pointer operations
    SpAdd(offset: u32)         = 62,
    SpSub(offset: u32)         = 63,

    // Frame pointer relative operations
    FpLoad8(dst: u8, offset: i32)       = 70,
    @ IData::StackLoad { slot, .. } if bits == 8 => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad8;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpLoad16(dst: u8, offset: i32)      = 71,
    @ IData::StackLoad { slot, .. } if bits == 16 => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad16;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpLoad32(dst: u8, offset: i32)      = 72,
    @ IData::StackLoad { slot, .. } if bits == 32 => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad32;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpLoad64(dst: u8, offset: i32)      = 73,
    @ IData::StackLoad { slot, .. } if bits == 64 => |results, chunk| {
        let dst = self.ssa_to_preg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad64;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    FpStore8(offset: i32, src: u8)      = 74,
    @ IData::StackStore { slot, arg, .. } if bits == 8 => |_results, chunk| {
        let src = self.load_value(chunk, *arg);
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore8;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    FpStore16(offset: i32, src: u8)     = 75,
    @ IData::StackStore { slot, arg, .. } if bits == 16 => |_results, chunk| {
        let src = self.load_value(chunk, *arg);
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore16;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    FpStore32(offset: i32, src: u8)     = 76,
    @ IData::StackStore { slot, arg, .. } if bits == 32 => |_results, chunk| {
        let src = self.load_value(chunk, *arg);
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore32;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    FpStore64(offset: i32, src: u8)     = 77,
    @ IData::StackStore { slot, arg, .. } if bits == 64 => |_results, chunk| {
        let src = self.load_value(chunk, *arg);
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore64;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },

    // Stack pointer relative operations
    SpLoad8(dst: u8, offset: i32)       = 80,
    SpLoad16(dst: u8, offset: i32)      = 81,
    SpLoad32(dst: u8, offset: i32)      = 82,
    SpLoad64(dst: u8, offset: i32)      = 83,
    SpStore8(offset: i32, src: u8)      = 84,
    SpStore16(offset: i32, src: u8)     = 85,
    SpStore32(offset: i32, src: u8)     = 86,
    SpStore64(offset: i32, src: u8)     = 87,

    // Address calculation
    FpAddr(dst: u8, offset: i32)        = 90,
    @ IData::StackAddr { slot, .. } => |results, chunk| {
        let result_val = results.unwrap()[0];
        self.emit_inst_with_result(chunk, result_val, |l, chunk, dst| {
            chunk.append(Opcode::FpAddr);
            chunk.append(dst);
            let allocation = &l.frame_info.slot_allocations[slot];
            chunk.append(allocation.offset);
        });
    },
    SpAddr(dst: u8, offset: i32)        = 91,

    LoadDataAddr(dst: u8, data_id: DataId) = 95,
    @ IData::DataAddr { data_id } => |results, chunk| {
        let result_val = results.unwrap()[0];
        self.emit_inst_with_result(chunk, result_val, |_, chunk, dst| {
            chunk.append(Opcode::LoadDataAddr);
            chunk.append(dst);
            chunk.append(*data_id);
        });
    },

    Nop() = 128,
    @ IData::Nop => |results, chunk| {},

    CallIntrin(intrinsic_id: u32) = 135,
    @ IData::CallIntrin { intrinsic_id, args } => |results, chunk, inst_id| {
        // 1) Move arguments to r0-r7 (up to 8 args)
        for (i, &arg) in args.iter().take(8).enumerate() {
            let arg_reg = self.load_value(chunk, arg);
            let target_reg = i as u8; // r0, r1, r2, ... r7

            // Only emit move if source != destination
            if arg_reg != target_reg {
                chunk.append(Opcode::Mov);
                chunk.append(target_reg); // dst
                chunk.append(arg_reg);    // src
            }
        }

        // TODO(#16): CallIntrin: If more than 8 args, push extras onto stack
        // For now, assume <= 8 arguments
        if args.len() > 8 {
            panic!("Functions with more than 8 arguments not yet supported");
        }

        // 2) Emit call instruction
        chunk.append(Opcode::CallIntrin);
        chunk.append(intrinsic_id.index() as u32);

        // 3) Move result(s) from r0 to destination register(s).
        if let Some(results) = results && !results.is_empty() {
            self.store_value(chunk, results[0], 0);
        }
    },

    CallExt(func_id: u32)          = 136,
    @ IData::CallExt { func_id, args, .. } => |results, chunk, inst_id| {
        // 1) Move arguments to r0-r7 (up to 8 args)
        for (i, &arg) in args.iter().take(8).enumerate() {
            let arg_reg = self.load_value(chunk, arg);
            let target_reg = i as u8; // r0, r1, r2, ... r7

            // Only emit move if source != destination
            if arg_reg != target_reg {
                chunk.append(Opcode::Mov);
                chunk.append(target_reg); // dst
                chunk.append(arg_reg);    // src
            }
        }

        // TODO(#17): CallExt: If more than 8 args, push extras onto stack
        // For now, assume <= 8 arguments
        if args.len() > 8 {
            panic!("Functions with more than 8 arguments not yet supported");
        }

        // 2) Emit call instruction
        chunk.append(Opcode::CallExt);
        chunk.append(func_id.index() as u32);
    },

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
            let align = slot_data.ty.align_bytes();

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
        frame_info.total_size = util::align_up(current_offset, 16);

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
    let mut curr_block: Option<Block> = None;
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

fn print_metadata(
    lowered: &LoweredSsaFunc,
    offset: usize,
    curr_block: &mut Option<Block>,
) {
    let offset_str = format!("{offset:05X} ");

    #[cfg(debug_assertions)]
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

    print!("{offset_str}");
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
    chunk: &BytecodeChunk,
    offset: usize,
) -> usize {
    let offset_str = format!("{offset:05X} ");

    print!("{offset_str}");

    let opcode_byte = chunk.code[offset];
    let opcode: Opcode = unsafe { std::mem::transmute(opcode_byte) };

    match opcode {
        Opcode::LoadDataAddr => {
            let dst = chunk.code[offset + 1];
            let data_id =
                u32::from_le_bytes(chunk.code[offset + 2..offset + 6].try_into().unwrap());
            print_aligned("LOAD_DATA_ADDR", &format!("v{dst}, D{data_id}"));
            offset + 6
        }
        Opcode::IConst8 => {
            let dst = chunk.code[offset + 1];
            let val =
                i8::from_le_bytes(chunk.code[offset + 2..offset + 3].try_into().unwrap());
            print_aligned("ICONST8", &format!("v{dst}, {val}_i8"));
            offset + 3
        }
        Opcode::IConst32 => {
            let dst = chunk.code[offset + 1];
            let val =
                u32::from_le_bytes(chunk.code[offset + 2..offset + 6].try_into().unwrap());
            print_aligned("ICONST32", &format!("v{dst}, {val}_i32"));
            offset + 6
        }
        Opcode::IConst64 => {
            let dst = chunk.code[offset + 1];
            let val =
                u64::from_le_bytes(chunk.code[offset + 2..offset + 10].try_into().unwrap());
            print_aligned("ICONST64", &format!("v{dst}, {val}_i64"));
            offset + 10
        }
        Opcode::FConst64 => {
            let dst = chunk.code[offset + 1];
            let val =
                f64::from_le_bytes(chunk.code[offset + 2..offset + 10].try_into().unwrap());
            print_aligned("FCONST64", &format!("v{dst}, {val}_f64"));
            offset + 10
        }
        Opcode::IAdd => {
            let dst = chunk.code[offset + 1];
            let a = chunk.code[offset + 2];
            let b = chunk.code[offset + 3];
            print_aligned("IADD", &format!("v{dst}, v{a}, v{b}"));
            offset + 4
        }
        Opcode::ISub => {
            let dst = chunk.code[offset + 1];
            let a = chunk.code[offset + 2];
            let b = chunk.code[offset + 3];
            print_aligned("ISUB", &format!("v{dst}, v{a}, v{b}"));
            offset + 4
        }
        Opcode::IMul => {
            let dst = chunk.code[offset + 1];
            let a = chunk.code[offset + 2];
            let b = chunk.code[offset + 3];
            print_aligned("IMUL", &format!("v{dst}, v{a}, v{b}"));
            offset + 4
        }
        Opcode::IDiv => {
            let dst = chunk.code[offset + 1];
            let a = chunk.code[offset + 2];
            let b = chunk.code[offset + 3];
            print_aligned("IDIV", &format!("v{dst}, v{a}, v{b}"));
            offset + 4
        }
        Opcode::And => {
            let dst = chunk.code[offset + 1];
            let a = chunk.code[offset + 2];
            let b = chunk.code[offset + 3];
            print_aligned("AND", &format!("v{dst}, v{a}, v{b}"));
            offset + 4
        }
        Opcode::Or => {
            let dst = chunk.code[offset + 1];
            let a = chunk.code[offset + 2];
            let b = chunk.code[offset + 3];
            print_aligned("OR", &format!("v{dst}, v{a}, v{b}"));
            offset + 4
        }
        Opcode::Xor => {
            let dst = chunk.code[offset + 1];
            let a = chunk.code[offset + 2];
            let b = chunk.code[offset + 3];
            print_aligned("XOR", &format!("v{dst}, v{a}, v{b}"));
            offset + 4
        }
        Opcode::IEq | Opcode::INe | Opcode::ISGt | Opcode::ISGe | Opcode::ISLt | Opcode::ISLe | Opcode::IUGt | Opcode::IUGe | Opcode::IULt | Opcode::IULe => {
            let dst = chunk.code[offset + 1];
            let a = chunk.code[offset + 2];
            let b = chunk.code[offset + 3];
            let name = match opcode {
                Opcode::IEq => "IEQ",
                Opcode::INe => "INE",
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
            offset + 4
        }
        Opcode::FAdd | Opcode::FSub | Opcode::FMul | Opcode::FDiv => {
            let dst = chunk.code[offset + 1];
            let a = chunk.code[offset + 2];
            let b = chunk.code[offset + 3];
            let op_name = match opcode {
                Opcode::FAdd => "FADD",
                Opcode::FSub => "FSUB",
                Opcode::FMul => "FMUL",
                Opcode::FDiv => "FDIV",
                _ => unreachable!(),
            };
            print_aligned(op_name, &format!("v{dst}, v{a}, v{b}"));
            offset + 4
        }
        Opcode::Load32 => {
            let dst = chunk.code[offset + 1];
            let addr = chunk.code[offset + 2];
            print_aligned("LOAD32", &format!("v{dst}, v{addr}"));
            offset + 3
        }
        Opcode::Load64 => {
            let dst = chunk.code[offset + 1];
            let addr = chunk.code[offset + 2];
            print_aligned("LOAD64", &format!("v{dst}, v{addr}"));
            offset + 3
        }
        Opcode::Store8 => {
            let addr = chunk.code[offset + 1];
            let val = chunk.code[offset + 2];
            print_aligned("STORE8", &format!("v{addr}, v{val}"));
            offset + 3
        }
        Opcode::Store32 => {
            let addr = chunk.code[offset + 1];
            let val = chunk.code[offset + 2];
            print_aligned("STORE32", &format!("v{addr}, v{val}"));
            offset + 3
        }
        Opcode::Store64 => {
            let addr = chunk.code[offset + 1];
            let val = chunk.code[offset + 2];
            print_aligned("STORE64", &format!("v{addr}, v{val}"));
            offset + 3
        }
        Opcode::Jump16 => {
            let jmp =
                i16::from_le_bytes(chunk.code[offset + 1..offset + 3].try_into().unwrap());
            let sign = if jmp < 0 { "-" } else { "+" };
            let target_addr = offset as i16 + 3 + jmp;
            print_aligned(
                "JUMP16",
                &format!("{target_addr:04X} ({sign}0x{jmp:X})"),
            );
            offset + 3
        }
        Opcode::BranchIf16 => {
            let cond = chunk.code[offset + 1];
            let jmp =
                i16::from_le_bytes(chunk.code[offset + 2..offset + 4].try_into().unwrap());
            let target_addr = offset as i16 + 4 + jmp;
            let sign = if jmp < 0 { "-" } else { "+" };
            print_aligned(
                "BRANCH_IF16",
                &format!("v{cond}, {target_addr:04X} ({sign}0x{jmp:X})"),
            );
            offset + 4
        }
        Opcode::Call => {
            let func_id =
                u32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            print_aligned("CALL", &format!("FUNC_{func_id}"));
            offset + 5
        }
        Opcode::CallExt => {
            let func_id =
                u32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            print_aligned("CALL_EXT", &format!("EXT_{func_id}"));
            offset + 5
        }
        Opcode::CallIntrin => {
            let intrinsic_id =
                u32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            print_aligned("CALL_INTRIN", &format!("INTRIN_{intrinsic_id}"));
            offset + 5
        }
        Opcode::Bor => {
            let dst = chunk.code[offset + 1];
            let src1 = chunk.code[offset + 2];
            let src2 = chunk.code[offset + 3];
            print_aligned("BOR", &format!("v{dst}, v{src1}, v{src2}"));
            offset + 4
        }
        Opcode::Ireduce => {
            let dst = chunk.code[offset + 1];
            let src = chunk.code[offset + 2];
            let bits = chunk.code[offset + 3];
            print_aligned("IREDUCE", &format!("v{dst}, v{src}, {bits}"));
            offset + 4
        }
        Opcode::Uextend => {
            let dst = chunk.code[offset + 1];
            let src = chunk.code[offset + 2];
            let from_bits = chunk.code[offset + 3];
            let to_bits = chunk.code[offset + 4];
            print_aligned("UEXTEND", &format!("v{dst}, v{src}, {from_bits}, {to_bits}"));
            offset + 5
        }
        Opcode::Mov => {
            let dst = chunk.code[offset + 1];
            let src = chunk.code[offset + 2];
            print_aligned("MOV", &format!("v{dst}, v{src}"));
            offset + 3
        }
        Opcode::Return => {
            print_aligned("RETURN", "");
            offset + 1
        }

        // New stack frame operations
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

        // Frame pointer relative operations
        Opcode::FpLoad8 => {
            let dst = chunk.code[offset + 1];
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 2..offset + 6].try_into().unwrap());
            print_aligned("FP_LOAD8", &format!("v{dst}, FP{fp_offset:+}"));
            offset + 6
        }
        Opcode::FpLoad16 => {
            let dst = chunk.code[offset + 1];
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 2..offset + 6].try_into().unwrap());
            print_aligned("FP_LOAD16", &format!("v{dst}, FP{fp_offset:+}"));
            offset + 6
        }
        Opcode::FpLoad32 => {
            let dst = chunk.code[offset + 1];
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 2..offset + 6].try_into().unwrap());
            print_aligned("FP_LOAD32", &format!("v{dst}, FP{fp_offset:+}"));
            offset + 6
        }
        Opcode::FpLoad64 => {
            let dst = chunk.code[offset + 1];
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 2..offset + 6].try_into().unwrap());
            print_aligned("FP_LOAD64", &format!("v{dst}, FP{fp_offset:+}"));
            offset + 6
        }
        Opcode::FpStore8 => {
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = chunk.code[offset + 5];
            print_aligned("FP_STORE8", &format!("FP{fp_offset:+}, v{src}"));
            offset + 6
        }
        Opcode::FpStore16 => {
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = chunk.code[offset + 5];
            print_aligned("FP_STORE16", &format!("FP{fp_offset:+}, v{src}"));
            offset + 6
        }
        Opcode::FpStore32 => {
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = chunk.code[offset + 5];
            print_aligned("FP_STORE32", &format!("FP{fp_offset:+}, v{src}"));
            offset + 6
        }
        Opcode::FpStore64 => {
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = chunk.code[offset + 5];
            print_aligned("FP_STORE64", &format!("FP{fp_offset:+}, v{src}"));
            offset + 6
        }
        Opcode::FpAddr => {
            let dst = chunk.code[offset + 1];
            let fp_offset =
                i32::from_le_bytes(chunk.code[offset + 2..offset + 6].try_into().unwrap());
            print_aligned("FP_ADDR", &format!("v{dst}, FP{fp_offset:+}"));
            offset + 6
        }

        // Stack pointer operations
        Opcode::SpAdd => {
            let sp_offset =
                u32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            print_aligned("SP_ADD", &format!("{sp_offset}"));
            offset + 5
        }
        Opcode::SpSub => {
            let sp_offset =
                u32::from_le_bytes(chunk.code[offset + 1..offset + 5].try_into().unwrap());
            print_aligned("SP_SUB", &format!("{sp_offset}"));
            offset + 5
        }
        Opcode::SpAddr => {
            let dst = chunk.code[offset + 1];
            let sp_offset =
                i32::from_le_bytes(chunk.code[offset + 2..offset + 6].try_into().unwrap());
            print_aligned("SP_ADDR", &format!("v{dst}, SP{sp_offset:+}"));
            offset + 6
        }
        Opcode::Halt => {
            print_aligned("HALT", "");
            offset + 1
        }

        _ => {
            unimplemented!("not implemented print: {opcode:?}");
        }
    }
}
