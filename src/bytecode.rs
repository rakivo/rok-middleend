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
    Add(dst: u32, a: u32, b: u32)           = 10,
    @ IData::Binary { opcode: BinaryOp::IAdd, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::Add);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    Sub(dst: u32, a: u32, b: u32)           = 11,
    @ IData::Binary { opcode: BinaryOp::ISub, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::Sub);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    Mul(dst: u32, a: u32, b: u32)           = 12,
    @ IData::Binary { opcode: BinaryOp::IMul, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::Mul);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    Lt(dst: u32, a: u32, b: u32)            = 13,
    @ IData::Binary { opcode: BinaryOp::ILt, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::Lt);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FAdd(dst: u32, a: u32, b: u32)          = 14,
    @ IData::Binary { opcode: BinaryOp::FAdd, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::FAdd);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FSub(dst: u32, a: u32, b: u32)          = 15,
    @ IData::Binary { opcode: BinaryOp::FSub, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::FSub);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FMul(dst: u32, a: u32, b: u32)          = 16,
    @ IData::Binary { opcode: BinaryOp::FMul, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::FMul);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },
    FDiv(dst: u32, a: u32, b: u32)          = 17,
    @ IData::Binary { opcode: BinaryOp::FDiv, args } => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let a = self.ssa_to_reg[&args[0]];
        let b = self.ssa_to_reg[&args[1]];
        chunk.append(Opcode::FDiv);
        chunk.append(dst);
        chunk.append(a);
        chunk.append(b);
    },

    Jump16(offset: i32)        = 21,
    @ IData::Jump { destination, .. } => |_results, chunk| {
        chunk.append(Opcode::Jump16);
        self.append_jump_placeholder::<i16>(chunk, *destination);
    },
    BranchIf16(cond: u32, offset: i32)    = 23,
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

    Return()        = 24,
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

    Call(func_id: u32)          = 25,
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

    // Memory
    Load8(dst: u32, addr: u32)         = 40,
    @ IData::StackLoad { slot, .. } if bits == 8 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad8;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    Load16(dst: u32, addr: u32)        = 41,
    @ IData::StackLoad { slot, .. } if bits == 16 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad16;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    Load32(dst: u32, addr: u32)        = 42,
    @ IData::StackLoad { slot, .. } if bits == 32 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad32;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    Load64(dst: u32, addr: u32)        = 43,
    @ IData::StackLoad { slot, .. } if bits == 64 => |results, chunk| {
        let dst = self.ssa_to_reg[&results.unwrap()[0]];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpLoad64;
        chunk.append(opcode);
        chunk.append(dst);
        chunk.append(allocation.offset);
    },
    Store8(addr: u32, val: u32)        = 44,
    @ IData::StackStore { slot, arg, .. } if bits == 8 => |_results, chunk| {
        let src = self.ssa_to_reg[arg];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore8;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    Store16(addr: u32, val: u32)       = 45,
    @ IData::StackStore { slot, arg, .. } if bits == 16 => |_results, chunk| {
        let src = self.ssa_to_reg[arg];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore16;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    Store32(addr: u32, val: u32)       = 46,
    @ IData::StackStore { slot, arg, .. } if bits == 32 => |_results, chunk| {
        let src = self.ssa_to_reg[arg];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore32;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
    },
    Store64(addr: u32, val: u32)       = 47,
    @ IData::StackStore { slot, arg, .. } if bits == 64 => |_results, chunk| {
        let src = self.ssa_to_reg[arg];
        let allocation = &self.frame_info.slot_allocations[slot];
        let opcode = Opcode::FpStore64;
        chunk.append(opcode);
        chunk.append(allocation.offset);
        chunk.append(src);
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

    Nop() = 128,
    @ IData::Nop => |results, chunk| {
        chunk.append(Opcode::Nop);
    },

    // VM control
    Halt()          = 255
}

impl Opcode {
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
    pub offset: i32,    // Offset from frame pointer (negative for locals)
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
        let mut current_offset = 0i32;

        // Allocate stack slots (growing downward from frame pointer)
        for (slot_idx, slot_data) in func.stack_slots.iter().enumerate() {
            let slot = StackSlot::from_u32(slot_idx as _);
            let size = slot_data.size;

            let align = slot_data.ty.align_bytes() as i32;
            current_offset = util::align_down(current_offset - size as i32, align);

            frame_info.slot_allocations.insert(slot, StackSlotAllocation {
                offset: current_offset,
                size,
                ty: slot_data.ty,
            });
        }

        // Total frame size (make it 16-byte aligned for calling convention)
        frame_info.total_size = util::align_up((-current_offset) as u32, 16);

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
    }
}

#[must_use]
#[cfg_attr(not(debug_assertions), allow(unused, dead_code))]
pub fn disassemble_instruction(
    lowered: &LoweredSsaFunc,
    offset: usize,
    current_block: &mut Option<Block>,
    print_metadata: bool
) -> usize {
    let offset_str = format!("{offset:05X} ");

    #[cfg(debug_assertions)]
    if print_metadata {
        if let Some(crate::lower::InstMeta {
            pc, inst, size
        }) = lowered.context.pc_to_inst_meta.get(&offset) {
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
        Opcode::IConst64 => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = u64::from_le_bytes(lowered.chunk.code[offset + 5..offset + 13].try_into().unwrap());
            println!("ICONST64    v{dst}, {val}_i64");
            offset + 13
        }
        Opcode::FConst64 => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = f64::from_le_bytes(lowered.chunk.code[offset + 5..offset + 13].try_into().unwrap());
            println!("FCONST64    v{dst}, {val}_f64");
            offset + 13
        }
        Opcode::Add => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("ADD         v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Sub => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("SUB         v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Mul => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("MUL         v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Lt => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            println!("LT          v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::FAdd | Opcode::FSub | Opcode::FMul | Opcode::FDiv => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let a = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            let b = u32::from_le_bytes(lowered.chunk.code[offset + 9..offset + 13].try_into().unwrap());
            let op_name = match opcode {
                Opcode::FAdd => "FADD",
                Opcode::FSub => "FSUB",
                Opcode::FMul => "FMUL",
                Opcode::FDiv => "FDIV",
                _ => unreachable!(),
            };
            println!("{op_name}        v{dst}, v{a}, v{b}");
            offset + 13
        }
        Opcode::Load64 => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let addr = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("LOAD64      v{dst}, v{addr}");
            offset + 9
        }
        Opcode::Store64 => {
            let addr = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let val = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("STORE64     v{addr}, v{val}");
            offset + 9
        }
        Opcode::Jump16 => {
            let jmp = i16::from_le_bytes(lowered.chunk.code[offset + 1..offset + 3].try_into().unwrap());
            let sign = if jmp < 0 { "-" } else { "+" };
            let target_addr = offset as i16 + 3 + jmp;
            println!("JUMP16      {target_addr:04X} ({sign}0x{jmp:X})");
            offset + 3
        }
        Opcode::BranchIf16 => {
            let cond = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let jmp = i16::from_le_bytes(lowered.chunk.code[offset + 5..offset + 7].try_into().unwrap());
            let target_addr = offset as i16 + 7 + jmp;
            let sign = if jmp < 0 { "-" } else { "+" };
            println!("BRANCH_IF16 v{cond}, {target_addr:04X} ({sign}0x{jmp:X})");
            offset + 7
        }
        Opcode::Call => {
            let func_id = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("CALL        F{func_id}");
            offset + 5
        }
        Opcode::Mov => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("MOV         v{dst}, v{src}");
            offset + 9
        }
        Opcode::Return => {
            println!("RETURN");
            offset + 1
        }

        // New stack frame operations
        Opcode::FrameSetup => {
            let size = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("FRAME_SETUP {size}");
            offset + 5
        }
        Opcode::FrameTeardown => {
            println!("FRAME_TEARDOWN");
            offset + 1
        }

        // Frame pointer relative operations
        Opcode::FpLoad32 => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_LOAD32   v{dst}, FP{fp_offset:+}");
            offset + 9
        }
        Opcode::FpLoad64 => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_LOAD64   v{dst}, FP{fp_offset:+}");
            offset + 9
        }
        Opcode::FpStore32 => {
            let fp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_STORE32  FP{fp_offset:+}, v{src}");
            offset + 9
        }
        Opcode::FpStore64 => {
            let fp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let src = u32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_STORE64  FP{fp_offset:+}, v{src}");
            offset + 9
        }
        Opcode::FpAddr => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let fp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("FP_ADDR     v{dst}, FP{fp_offset:+}");
            offset + 9
        }

        // Stack pointer operations
        Opcode::SpAdd => {
            let sp_offset = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("SP_ADD      {sp_offset}");
            offset + 5
        }
        Opcode::SpSub => {
            let sp_offset = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            println!("SP_SUB      {sp_offset}");
            offset + 5
        }
        Opcode::SpAddr => {
            let dst = u32::from_le_bytes(lowered.chunk.code[offset + 1..offset + 5].try_into().unwrap());
            let sp_offset = i32::from_le_bytes(lowered.chunk.code[offset + 5..offset + 9].try_into().unwrap());
            println!("SP_ADDR     v{dst}, SP{sp_offset:+}");
            offset + 9
        }

        _ => {
            println!("Unknown opcode: {opcode_byte}");
            offset + 1
        }
    }
}

