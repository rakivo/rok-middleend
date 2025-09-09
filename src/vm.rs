use std::{fmt, ptr};

use cfg_if::cfg_if;

use crate::bytecode::Opcode;
use crate::bytecode::BytecodeChunk;

// ============================================================================
// VM DATA STRUCTURES (OPTIMIZED)
// ============================================================================

/// VM execution errors
#[derive(Debug, Clone)]
pub enum VMError {
    EmptyCallStack,
    InvalidOpcode(u8),
    InvalidFunctionId(u32),
    StackOverflow,
    StackUnderflow,
    DivisionByZero,
    InvalidMemoryAccess(u64),
    UnalignedAccess(u64),
    InvalidInstruction(String),
    ExecutionHalted,
}

impl fmt::Display for VMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VMError::EmptyCallStack => write!(f, "Empty call stack"),
            VMError::InvalidOpcode(op) => write!(f, "Invalid opcode: {op}"),
            VMError::InvalidFunctionId(id) => write!(f, "Invalid function ID: {id}"),
            VMError::StackOverflow => write!(f, "Stack overflow"),
            VMError::StackUnderflow => write!(f, "Stack underflow"),
            VMError::DivisionByZero => write!(f, "Division by zero"),
            VMError::InvalidMemoryAccess(addr) => write!(f, "Invalid memory access at 0x{addr:x}"),
            VMError::UnalignedAccess(addr) => write!(f, "Unaligned memory access at 0x{addr:x}"),
            VMError::InvalidInstruction(msg) => write!(f, "Invalid instruction: {msg}"),
            VMError::ExecutionHalted => write!(f, "Execution halted"),
        }
    }
}

impl std::error::Error for VMError {}

// ============================================================================
// FAST INSTRUCTION DECODER
// ============================================================================

pub struct InstructionDecoder {
    ptr: *const u8,
    end: *const u8,
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
impl InstructionDecoder {
    #[inline]
    #[must_use]
    pub fn new(bytecode: &[u8]) -> Self {
        Self {
            ptr: bytecode.as_ptr(),
            end: unsafe { bytecode.as_ptr().add(bytecode.len()) },
        }
    }

    #[inline]
    pub fn set_pos(&mut self, pos: usize, base: *const u8) {
        self.ptr = unsafe { base.add(pos) };
    }

    #[inline]
    #[must_use]
    pub fn get_pos(&self, base: *const u8) -> usize {
        unsafe { self.ptr.offset_from(base) as usize }
    }

    #[inline(always)]
    pub fn read_u8(&mut self) -> u8 {
        unsafe {
            debug_assert!(self.ptr < self.end);
            let val = *self.ptr;
            self.ptr = self.ptr.add(1);
            val
        }
    }

    #[inline(always)]
    pub fn read_u16(&mut self) -> u16 {
        unsafe {
            debug_assert!(self.ptr.add(2) <= self.end);
            let val = (self.ptr).cast::<u16>().read().to_le();
            self.ptr = self.ptr.add(2);
            val
        }
    }

    #[inline(always)]
    pub fn read_u32(&mut self) -> u32 {
        unsafe {
            debug_assert!(self.ptr.add(4) <= self.end);
            let val = (self.ptr).cast::<u32>().read().to_le();
            self.ptr = self.ptr.add(4);
            val
        }
    }

    #[inline(always)]
    pub fn read_i32(&mut self) -> i32 {
        self.read_u32() as i32
    }

    #[inline(always)]
    pub fn read_u64(&mut self) -> u64 {
        unsafe {
            debug_assert!(self.ptr.add(8) <= self.end);
            let val = self.ptr.cast::<u64>().read();
            self.ptr = self.ptr.add(8);
            val.to_le()
        }
    }

    #[inline(always)]
    pub fn read_i64(&mut self) -> i64 {
        self.read_u64() as i64
    }

    #[inline(always)]
    pub fn read_f32(&mut self) -> f32 {
        f32::from_bits(self.read_u32())
    }

    #[inline(always)]
    pub fn read_f64(&mut self) -> f64 {
        f64::from_bits(self.read_u64())
    }
}

// ============================================================================
// STACK FRAME (OPTIMIZED)
// ============================================================================

#[derive(Copy, Debug, Clone)]
pub struct StackFrame {
    pub function_id: u32,
    pub return_pc: usize,
    pub frame_pointer: usize,
    pub stack_pointer: usize,
}

impl StackFrame {
    #[inline]
    #[must_use]
    pub fn new(function_id: u32, return_pc: usize, fp: usize, sp: usize) -> Self {
        StackFrame {
            function_id,
            return_pc,
            frame_pointer: fp,
            stack_pointer: sp,
        }
    }
}

// ============================================================================
// VIRTUAL MACHINE (OPTIMIZED)
// ============================================================================

pub struct VirtualMachine {
    // Function management
    functions: Vec<BytecodeChunk>,

    // Execution state
    call_stack: Vec<StackFrame>,
    pc: usize,

    // Memory regions
    stack_memory: Vec<u8>,
    stack_top: usize,

    // Working registers (for arithmetic operations)
    registers: [u64; 256], // r0-r7: return values, r8+: general purpose/args

    // Execution control
    halted: bool,
}

impl Default for VirtualMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualMachine {
    pub const STACK_SIZE: usize = 1024 * 1024;

    #[must_use]
    pub fn new() -> Self {
        let mut stack_memory = Vec::with_capacity(Self::STACK_SIZE);
        #[allow(clippy::uninit_vec)]
        unsafe {
            stack_memory.set_len(Self::STACK_SIZE);
        }

        VirtualMachine {
            functions: Vec::with_capacity(32),
            call_stack: Vec::with_capacity(32),
            pc: 0,
            stack_memory,
            stack_top: 0,
            registers: [0; 256],
            halted: false,
        }
    }

    #[inline]
    pub fn add_function(&mut self, chunk: BytecodeChunk) -> u32 {
        let id = self.functions.len() as u32;
        self.functions.push(chunk);
        id
    }

    #[inline]
    pub fn call_function(&mut self, function_id: u32, args: &[u64]) -> Result<[u64; 8], VMError> {
        if function_id as usize >= self.functions.len() {
            cfg_if! {
                if #[cfg(debug_assertions)] {
                    return Err(VMError::InvalidFunctionId(function_id));
                } else {
                    unsafe { core::hint::unreachable_unchecked() }
                }
            }
        }

        unsafe {
            // Clear return registers for new function call
            ptr::write_bytes(self.registers.as_mut_ptr(), 0, 8);

            // Set up arguments in registers r8+
            let dst = self.registers.as_mut_ptr().add(8); // start at r8
            for (i, &arg) in args.iter().enumerate().take(256 - 8) {
                ptr::write(dst.add(i), arg);
            }
        }

        // Set up initial frame
        let chunk = &self.functions[function_id as usize];
        let frame_size = chunk.frame_info.total_size as usize;
        let new_fp = self.stack_top;
        let new_sp = self.stack_top + frame_size;

        #[cfg(debug_assertions)]
        if new_sp >= self.stack_memory.len() {
            return Err(VMError::StackOverflow);
        }

        let frame = StackFrame::new(function_id, 0, new_fp, new_sp);
        self.call_stack.push(frame);
        self.stack_top = new_sp;
        self.pc = 0;
        self.halted = false;

        self.execute()?;

        // Return values are in r0-r7
        let result: [u64; 8] = self.registers[0..8].try_into().unwrap();
        Ok(result)
    }

    #[inline(always)]
    fn current_frame(&self) -> &StackFrame {
        unsafe { self.call_stack.last().unwrap_unchecked() }
    }

    pub fn execute(&mut self) -> Result<(), VMError> {
        let mut frame = *self.current_frame();

        let regs_ptr = self.registers.as_mut_ptr();
        let funcs_ptr = self.functions.as_ptr();

        while !self.halted && !self.call_stack.is_empty() {
            let function_id = frame.function_id;
            let chunk = unsafe {
                &(*ptr::from_ref(self))
                    .functions
                    .get_unchecked(function_id as usize)
            };

            let mut decoder = InstructionDecoder::new(&chunk.code);
            decoder.set_pos(self.pc, chunk.code.as_ptr());

            // Fetch opcode
            let opcode_byte = decoder.read_u8();
            let opcode;
            cfg_if::cfg_if! {
                if #[cfg(debug_assertions)] {
                    opcode = Opcode::from_u8(opcode_byte)
                        .ok_or(VMError::InvalidOpcode(opcode_byte))?
                } else {
                    opcode = unsafe { core::mem::transmute(opcode_byte) }
                }
            };

            // load function bytecode
            let chunk = unsafe { &*funcs_ptr.add(frame.function_id as usize) };

            match opcode {
                Opcode::IConst8 => {
                    let reg = decoder.read_u32();
                    let value = i64::from(decoder.read_u8() as i8) as u64;
                    unsafe { *self.registers.get_unchecked_mut(reg as usize) = value };
                }

                Opcode::IConst16 => {
                    let reg = decoder.read_u32();
                    let value = i64::from(decoder.read_u16() as i16) as u64;
                    unsafe { *self.registers.get_unchecked_mut(reg as usize) = value };
                }

                Opcode::IConst32 => {
                    let reg = decoder.read_u32();
                    let value = i64::from(decoder.read_i32()) as u64;
                    unsafe { *self.registers.get_unchecked_mut(reg as usize) = value };
                }

                Opcode::IConst64 => {
                    let reg = decoder.read_u32();
                    let value = decoder.read_i64() as u64;
                    unsafe { *self.registers.get_unchecked_mut(reg as usize) = value };
                }

                Opcode::FConst32 => {
                    let reg = decoder.read_u32();
                    let value = u64::from(decoder.read_f32().to_bits());
                    unsafe { *self.registers.get_unchecked_mut(reg as usize) = value };
                }

                Opcode::FConst64 => {
                    let reg = decoder.read_u32();
                    let value = decoder.read_f64().to_bits();
                    unsafe { *self.registers.get_unchecked_mut(reg as usize) = value };
                }

                Opcode::Add => {
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = unsafe { *self.registers.get_unchecked(src1 as usize) as i64 };
                    let val2 = unsafe { *self.registers.get_unchecked(src2 as usize) as i64 };
                    unsafe { *self.registers.get_unchecked_mut(dst as usize) = val1.wrapping_add(val2) as u64 };
                }

                Opcode::Sub => {
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = unsafe { *self.registers.get_unchecked(src1 as usize) as i64 };
                    let val2 = unsafe { *self.registers.get_unchecked(src2 as usize) as i64 };
                    unsafe { *self.registers.get_unchecked_mut(dst as usize) = val1.wrapping_sub(val2) as u64 };
                }

                Opcode::Mul => {
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = unsafe { *self.registers.get_unchecked(src1 as usize) as i64 };
                    let val2 = unsafe { *self.registers.get_unchecked(src2 as usize) as i64 };
                    unsafe { *self.registers.get_unchecked_mut(dst as usize) = val1.wrapping_mul(val2) as u64 };
                }

                Opcode::Lt => {
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = unsafe { *self.registers.get_unchecked(src1 as usize) as i64 };
                    let val2 = unsafe { *self.registers.get_unchecked(src2 as usize) as i64 };
                    unsafe { *self.registers.get_unchecked_mut(dst as usize) = u64::from(val1 < val2) };
                }

                Opcode::FAdd => {
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = unsafe { f64::from_bits(*self.registers.get_unchecked(src1 as usize)) };
                    let val2 = unsafe { f64::from_bits(*self.registers.get_unchecked(src2 as usize)) };
                    unsafe { *self.registers.get_unchecked_mut(dst as usize) = (val1 + val2).to_bits() };
                }

                Opcode::FSub => {
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = unsafe { f64::from_bits(*self.registers.get_unchecked(src1 as usize)) };
                    let val2 = unsafe { f64::from_bits(*self.registers.get_unchecked(src2 as usize)) };
                    unsafe { *self.registers.get_unchecked_mut(dst as usize) = (val1 - val2).to_bits() };
                }

                Opcode::FMul => {
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = unsafe { f64::from_bits(*self.registers.get_unchecked(src1 as usize)) };
                    let val2 = unsafe { f64::from_bits(*self.registers.get_unchecked(src2 as usize)) };
                    unsafe { *self.registers.get_unchecked_mut(dst as usize) = (val1 * val2).to_bits() };
                }

                Opcode::FDiv => {
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = unsafe { f64::from_bits(*self.registers.get_unchecked(src1 as usize)) };
                    let val2 = unsafe { f64::from_bits(*self.registers.get_unchecked(src2 as usize)) };
                    #[cfg(debug_assertions)]
                    if val2 == 0.0 {
                        return Err(VMError::DivisionByZero);
                    }
                    unsafe { *self.registers.get_unchecked_mut(dst as usize) = (val1 / val2).to_bits() };
                }

                Opcode::Jump16 => {
                    let offset = i32::from(decoder.read_u16() as i16);
                    let new_pc = (decoder.get_pos(chunk.code.as_ptr()) as i32 + offset) as usize;
                    self.pc = new_pc;
                    continue;
                }

                Opcode::Jump32 => {
                    let offset = decoder.read_i32();
                    let new_pc = (decoder.get_pos(chunk.code.as_ptr()) as i32 + offset) as usize;
                    self.pc = new_pc;
                    continue;
                }

                Opcode::BranchIf16 => {
                    let cond_reg = decoder.read_u32();
                    let offset = i32::from(decoder.read_u16() as i16);
                    let cond = unsafe { *self.registers.get_unchecked(cond_reg as usize) };
                    if cond != 0 {
                        let new_pc = (decoder.get_pos(chunk.code.as_ptr()) as i32 + offset) as usize;
                        self.pc = new_pc;
                        continue;
                    }
                }

                Opcode::BranchIf32 => {
                    let cond_reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let cond = unsafe { *self.registers.get_unchecked(cond_reg as usize) };
                    if cond != 0 {
                        let new_pc = (decoder.get_pos(chunk.code.as_ptr()) as i32 + offset) as usize;
                        self.pc = new_pc;
                        continue;
                    }
                }

                Opcode::Call => {
                    let function_id = decoder.read_u32();

                    #[cfg(debug_assertions)]
                    if function_id as usize >= self.functions.len() {
                        return Err(VMError::InvalidFunctionId(function_id));
                    }

                    // Save current register state on stack (caller-saved registers)
                    // For now, let's save all non-return registers (r8+) to stack
                    let save_start = self.stack_top;
                    let save_size = (256 - 8) * 8; // 248 registers * 8 bytes each

                    #[cfg(debug_assertions)]
                    if save_start + save_size >= self.stack_memory.len() {
                        return Err(VMError::StackOverflow);
                    }

                    // Save return PC
                    let return_pc = decoder.get_pos(chunk.code.as_ptr());

                    // Set up new frame
                    let new_chunk = unsafe { &*funcs_ptr.add(function_id as usize) };
                    let frame_size = new_chunk.frame_info.total_size as usize;
                    let new_fp = save_start + save_size; // Frame starts after saved registers
                    let new_sp = new_fp + frame_size;

                    #[cfg(debug_assertions)]
                    if new_sp >= self.stack_memory.len() {
                        return Err(VMError::StackOverflow);
                    }

                    let new_frame = StackFrame::new(function_id, return_pc, new_fp, new_sp);
                    self.call_stack.push(new_frame);
                    frame = new_frame;
                    self.stack_top = new_sp;
                    self.pc = 0;

                    continue;
                }

                Opcode::Return => {
                    if self.call_stack.is_empty() {
                        return Err(VMError::EmptyCallStack);
                    }

                    let old_frame = unsafe {
                        self.call_stack.pop().unwrap_unchecked()
                    };

                    if self.call_stack.is_empty() {
                        self.halted = true;
                        continue;
                    }

                    let save_size = (256 - 8) * 8;
                    let save_start = old_frame.frame_pointer - save_size;

                    self.stack_top = save_start;
                    self.pc = old_frame.return_pc;
                    frame = *self.current_frame();
                    continue;
                }

                Opcode::Mov => {
                    let dst = decoder.read_u32();
                    let src = decoder.read_u32();
                    unsafe { *regs_ptr.add(dst as _) = *regs_ptr.add(src as _) };
                }

                Opcode::FrameSetup => {
                    let frame_size = decoder.read_u32();
                    frame.stack_pointer += frame_size as usize;
                    if frame.stack_pointer >= self.stack_memory.len() {
                        return Err(VMError::StackOverflow);
                    }
                }

                Opcode::FrameTeardown => {
                    frame.stack_pointer = frame.frame_pointer;
                }

                Opcode::SpAdd => {
                    let offset = decoder.read_i32();
                    frame.stack_pointer = (frame.stack_pointer as i32 + offset) as usize;
                }

                Opcode::SpSub => {
                    let offset = decoder.read_i32();
                    frame.stack_pointer = (frame.stack_pointer as i32 - offset) as usize;
                }

                Opcode::FpLoad32 => {
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (frame.frame_pointer as i32 + offset) as usize;
                    let v = unsafe { ptr::read(self.stack_memory.as_ptr().add(addr).cast::<u64>()) };
                    unsafe { *regs_ptr.add(reg as _) = v };
                }

                Opcode::FpLoad64 => {
                    let reg = decoder.read_u32();
                    let offset = -decoder.read_i32();
                    let addr = (frame.frame_pointer as i32 + offset) as usize;
                    let v = unsafe { ptr::read(self.stack_memory.as_ptr().add(addr).cast::<u64>()) };
                    unsafe { *regs_ptr.add(reg as _) = v };
                }

                Opcode::FpStore32 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (frame.frame_pointer as i32 + offset) as usize;
                    let v = unsafe { *regs_ptr.add(reg as _) };
                    unsafe { ptr::write(self.stack_memory.as_mut_ptr().add(addr).cast::<u64>(), v) };
                }

                Opcode::FpStore64 => {
                    let offset = -decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (frame.frame_pointer as i32 + offset) as usize;
                    let v = unsafe { *regs_ptr.add(reg as _) };
                    unsafe { ptr::write(self.stack_memory.as_mut_ptr().add(addr).cast::<u64>(), v) };
                }

                Opcode::SpLoad32 => {
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (frame.stack_pointer as i32 + offset) as usize;
                    let v = unsafe { ptr::read(self.stack_memory.as_ptr().add(addr).cast::<u64>()) };
                    unsafe { *regs_ptr.add(reg as _) = v };
                }

                Opcode::SpLoad64 => {
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (frame.stack_pointer as i32 + offset) as usize;
                    let v = unsafe { ptr::read(self.stack_memory.as_ptr().add(addr).cast::<u64>()) };
                    unsafe { *regs_ptr.add(reg as _) = v };
                }

                Opcode::SpStore32 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (frame.stack_pointer as i32 + offset) as usize;
                    let v = unsafe { *regs_ptr.add(reg as _) };
                    unsafe { ptr::write(self.stack_memory.as_mut_ptr().add(addr).cast::<u64>(), v) };
                }

                Opcode::SpStore64 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (frame.stack_pointer as i32 + offset) as usize;
                    let v = unsafe { *regs_ptr.add(reg as _) };
                    unsafe { ptr::write(self.stack_memory.as_mut_ptr().add(addr).cast::<u64>(), v) };
                }

                Opcode::FpAddr => {
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (frame.frame_pointer as i32 + offset) as u64;
                    unsafe { *regs_ptr.add(reg as _) = addr };
                }

                Opcode::SpAddr => {
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (frame.stack_pointer as i32 + offset) as u64;
                    unsafe { *regs_ptr.add(reg as _) = addr };
                }

                Opcode::Halt => {
                    self.halted = true;
                    break;
                }

                _ => {
                    cfg_if! {
                        if #[cfg(debug_assertions)] {
                            return Err(VMError::InvalidOpcode(opcode_byte));
                        } else {
                            unsafe { core::hint::unreachable_unchecked() }
                        }
                    }
                }
            }

            // Advance PC to next instruction
            self.pc = decoder.get_pos(chunk.code.as_ptr());
        }

        Ok(())
    }
}

// ============================================================================
// BYTECODE BUILDER HELPER (OPTIMIZED)
// ============================================================================

pub struct BytecodeBuilder {
    bytes: Vec<u8>,
}

impl Default for BytecodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BytecodeBuilder {
    #[must_use]
    pub fn new() -> Self {
        BytecodeBuilder { bytes: Vec::new() }
    }

    #[inline]
    pub fn opcode(&mut self, op: Opcode) -> &mut Self {
        self.bytes.push(op as u8);
        self
    }

    #[inline]
    pub fn u8(&mut self, val: u8) -> &mut Self {
        self.bytes.push(val);
        self
    }

    #[inline]
    pub fn u16(&mut self, val: u16) -> &mut Self {
        self.bytes.extend_from_slice(&val.to_le_bytes());
        self
    }

    #[inline]
    pub fn u32(&mut self, val: u32) -> &mut Self {
        self.bytes.extend_from_slice(&val.to_le_bytes());
        self
    }

    #[inline]
    pub fn i32(&mut self, val: i32) -> &mut Self {
        self.bytes.extend_from_slice(&val.to_le_bytes());
        self
    }

    #[inline]
    pub fn i64(&mut self, val: i64) -> &mut Self {
        self.bytes.extend_from_slice(&val.to_le_bytes());
        self
    }

    #[inline]
    pub fn f32(&mut self, val: f32) -> &mut Self {
        self.bytes.extend_from_slice(&val.to_bits().to_le_bytes());
        self
    }

    #[inline]
    pub fn f64(&mut self, val: f64) -> &mut Self {
        self.bytes.extend_from_slice(&val.to_bits().to_le_bytes());
        self
    }

    #[must_use]
    pub fn build(self) -> Vec<u8> {
        self.bytes
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
