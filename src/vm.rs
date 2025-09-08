use std::fmt;

use crate::bytecode::Opcode;
use crate::bytecode::BytecodeChunk;

// ============================================================================
// VM DATA STRUCTURES (OPTIMIZED)
// ============================================================================

/// VM execution errors
#[derive(Debug, Clone)]
pub enum VMError {
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
    #[must_use] pub fn get_pos(&self, base: *const u8) -> usize {
        unsafe { self.ptr.offset_from(base) as usize }
    }

    #[inline]
    pub fn read_u8(&mut self) -> u8 {
        unsafe {
            debug_assert!(self.ptr < self.end);
            let val = *self.ptr;
            self.ptr = self.ptr.add(1);
            val
        }
    }

    #[inline]
    pub fn read_u16(&mut self) -> u16 {
        unsafe {
            debug_assert!(self.ptr.add(2) <= self.end);
            let val = self.ptr.cast::<u16>().read_unaligned();
            self.ptr = self.ptr.add(2);
            val.to_le()
        }
    }

    #[inline]
    pub fn read_u32(&mut self) -> u32 {
        unsafe {
            debug_assert!(self.ptr.add(4) <= self.end);
            let val = self.ptr.cast::<u32>().read_unaligned();
            self.ptr = self.ptr.add(4);
            val.to_le()
        }
    }

    #[inline]
    pub fn read_i32(&mut self) -> i32 {
        self.read_u32() as i32
    }

    #[inline]
    pub fn read_u64(&mut self) -> u64 {
        unsafe {
            debug_assert!(self.ptr.add(8) <= self.end);
            let val = self.ptr.cast::<u64>().read_unaligned();
            self.ptr = self.ptr.add(8);
            val.to_le()
        }
    }

    #[inline]
    pub fn read_i64(&mut self) -> i64 {
        self.read_u64() as i64
    }

    #[inline]
    pub fn read_f32(&mut self) -> f32 {
        f32::from_bits(self.read_u32())
    }

    #[inline]
    pub fn read_f64(&mut self) -> f64 {
        f64::from_bits(self.read_u64())
    }
}

// ============================================================================
// STACK FRAME (OPTIMIZED)
// ============================================================================

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub function_id: u32,
    pub return_pc: usize,
    pub frame_pointer: usize,
    pub stack_pointer: usize,
    pub registers: [u64; 8], // v0..v7 return registers
}

impl StackFrame {
    #[inline]
    #[must_use] pub fn new(function_id: u32, return_pc: usize, fp: usize, sp: usize) -> Self {
        StackFrame {
            function_id,
            return_pc,
            frame_pointer: fp,
            stack_pointer: sp,
            registers: [0; 8],
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
    registers: [u64; 256], // Temporary registers for operations

    // Execution control
    halted: bool,
}

impl Default for VirtualMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualMachine {
    #[must_use]
    #[allow(clippy::uninit_vec)]
    pub fn new() -> Self {
        let mut stack_memory = Vec::with_capacity(1024 * 1024);
        unsafe {
            stack_memory.set_len(1024 * 1024); // Don't zero-initialize
        }

        VirtualMachine {
            functions: Vec::new(),
            call_stack: Vec::new(),
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
            return Err(VMError::InvalidFunctionId(function_id));
        }

        // Set up arguments in registers
        for (i, &arg) in args.iter().enumerate().take(8) {
            self.registers[i + 8] = arg;
        }

        // Set up initial frame
        let frame_size = self.functions[function_id as usize].frame_info.total_size as usize;
        let new_fp = self.stack_top;
        let new_sp = self.stack_top + frame_size;

        if new_sp >= self.stack_memory.len() {
            return Err(VMError::StackOverflow);
        }

        let frame = StackFrame::new(function_id, 0, new_fp, new_sp);
        self.call_stack.push(frame);
        self.stack_top = new_sp;
        self.pc = 0;
        self.halted = false;

        self.execute()?;

        let result = self.call_stack.last().map_or([0; 8], |f| f.registers);
        Ok(result)
    }

    #[inline]
    fn current_frame_mut(&mut self) -> &mut StackFrame {
        unsafe { self.call_stack.last_mut().unwrap_unchecked() }
    }

    #[inline]
    fn current_frame(&self) -> &StackFrame {
        unsafe { self.call_stack.last().unwrap_unchecked() }
    }

    #[inline]
    fn stack_load<T>(&self, addr: usize) -> T
    where
        T: Copy
    {
        debug_assert!(addr + std::mem::size_of::<T>() <= self.stack_memory.len());
        unsafe { self.stack_memory.as_ptr().add(addr).cast::<T>().read_unaligned() }
    }

    #[inline]
    fn stack_store<T>(&mut self, addr: usize, value: T)
    where
        T: Copy
    {
        println!("{addr}");
        debug_assert!(addr + std::mem::size_of::<T>() <= self.stack_memory.len(), "addr: {addr}");
        unsafe { self.stack_memory.as_mut_ptr().add(addr).cast::<T>().write_unaligned(value); }
    }

    pub fn execute(&mut self) -> Result<(), VMError> {
        while !self.halted && !self.call_stack.is_empty() {
            let frame = self.current_frame();
            let function_id = frame.function_id;
            let chunk = unsafe { &(*std::ptr::from_ref::<Self>(self)).functions.get_unchecked(function_id as usize) };

            let mut decoder = InstructionDecoder::new(&chunk.code);
            decoder.set_pos(self.pc, chunk.code.as_ptr());

            // Fetch opcode
            let opcode_byte = decoder.read_u8();

            match opcode_byte {
                0 => { // IConst8
                    let reg = decoder.read_u32();
                    let value = i64::from(decoder.read_u8() as i8) as u64;
                    self.registers[reg as usize] = value;
                }

                1 => { // IConst16
                    let reg = decoder.read_u32();
                    let value = i64::from(decoder.read_u16() as i16) as u64;
                    self.registers[reg as usize] = value;
                }

                2 => { // IConst32
                    let reg = decoder.read_u32();
                    let value = i64::from(decoder.read_i32()) as u64;
                    self.registers[reg as usize] = value;
                }

                3 => { // IConst64
                    let reg = decoder.read_u32();
                    let value = decoder.read_i64() as u64;
                    self.registers[reg as usize] = value;
                }

                4 => { // FConst32
                    let reg = decoder.read_u32();
                    let value = u64::from(decoder.read_f32().to_bits());
                    self.registers[reg as usize] = value;
                }

                5 => { // FConst64
                    let reg = decoder.read_u32();
                    let value = decoder.read_f64().to_bits();
                    self.registers[reg as usize] = value;
                }

                10 => { // Add
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = self.registers[src1 as usize] as i64;
                    let val2 = self.registers[src2 as usize] as i64;
                    self.registers[dst as usize] = val1.wrapping_add(val2) as u64;
                }

                11 => { // Sub
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = self.registers[src1 as usize] as i64;
                    let val2 = self.registers[src2 as usize] as i64;
                    self.registers[dst as usize] = val1.wrapping_sub(val2) as u64;
                }

                12 => { // Mul
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = self.registers[src1 as usize] as i64;
                    let val2 = self.registers[src2 as usize] as i64;
                    self.registers[dst as usize] = val1.wrapping_mul(val2) as u64;
                }

                13 => { // Lt
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = self.registers[src1 as usize] as i64;
                    let val2 = self.registers[src2 as usize] as i64;
                    self.registers[dst as usize] = u64::from(val1 < val2);
                }

                14 => { // FAdd
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = f64::from_bits(self.registers[src1 as usize]);
                    let val2 = f64::from_bits(self.registers[src2 as usize]);
                    self.registers[dst as usize] = (val1 + val2).to_bits();
                }

                15 => { // FSub
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = f64::from_bits(self.registers[src1 as usize]);
                    let val2 = f64::from_bits(self.registers[src2 as usize]);
                    self.registers[dst as usize] = (val1 - val2).to_bits();
                }

                16 => { // FMul
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = f64::from_bits(self.registers[src1 as usize]);
                    let val2 = f64::from_bits(self.registers[src2 as usize]);
                    self.registers[dst as usize] = (val1 * val2).to_bits();
                }

                17 => { // FDiv
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
                    let val1 = f64::from_bits(self.registers[src1 as usize]);
                    let val2 = f64::from_bits(self.registers[src2 as usize]);
                    if val2 == 0.0 {
                        return Err(VMError::DivisionByZero);
                    }
                    self.registers[dst as usize] = (val1 / val2).to_bits();
                }

                20 => { // Jump16
                    let offset = i32::from(decoder.read_u16() as i16);
                    let new_pc = (decoder.get_pos(chunk.code.as_ptr()) as i32 + offset) as usize;
                    self.pc = new_pc;
                    continue;
                }

                21 => { // Jump32
                    let offset = decoder.read_i32();
                    let new_pc = (decoder.get_pos(chunk.code.as_ptr()) as i32 + offset) as usize;
                    self.pc = new_pc;
                    continue;
                }

                22 => { // BranchIf16
                    let cond_reg = decoder.read_u32();
                    let offset = i32::from(decoder.read_u16() as i16);
                    let cond = self.registers[cond_reg as usize];
                    if cond != 0 {
                        let new_pc = (decoder.get_pos(chunk.code.as_ptr()) as i32 + offset) as usize;
                        self.pc = new_pc;
                        continue;
                    }
                }

                23 => { // BranchIf32
                    let cond_reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let cond = self.registers[cond_reg as usize];
                    if cond != 0 {
                        let new_pc = (decoder.get_pos(chunk.code.as_ptr()) as i32 + offset) as usize;
                        self.pc = new_pc;
                        continue;
                    }
                }

                30 => { // Call
                    let function_id = decoder.read_u32();

                    if function_id as usize >= self.functions.len() {
                        return Err(VMError::InvalidFunctionId(function_id));
                    }

                    // Save return PC
                    let return_pc = decoder.get_pos(chunk.code.as_ptr());
                    self.current_frame_mut().return_pc = return_pc;

                    // Set up new frame
                    let new_chunk = unsafe { self.functions.get_unchecked(function_id as usize) };
                    let frame_size = new_chunk.frame_info.total_size as usize;
                    let new_fp = self.stack_top;
                    let new_sp = self.stack_top + frame_size;

                    if new_sp >= self.stack_memory.len() {
                        return Err(VMError::StackOverflow);
                    }

                    let mut new_frame = StackFrame::new(function_id, 0, new_fp, new_sp);

                    // Copy v0..v7 from registers to new frame
                    for i in 0..8 {
                        new_frame.registers[i] = self.registers[i];
                    }

                    self.call_stack.push(new_frame);
                    self.stack_top = new_sp;
                    self.pc = 0;
                    continue;
                }

                31 => { // Return
                    // Copy return values to current frame
                    for i in 0..8 {
                        self.current_frame_mut().registers[i] = self.registers[i];
                    }

                    // Pop current frame
                    let old_frame = self.call_stack.pop().unwrap();
                    self.stack_top = old_frame.frame_pointer;

                    if self.call_stack.is_empty() {
                        self.halted = true;
                    } else {
                        // Copy return values to registers and restore PC
                        for i in 0..8 {
                            self.registers[i] = old_frame.registers[i];
                        }
                        self.pc = self.current_frame().return_pc;
                    }
                    continue;
                }

                50 => { // Mov
                    let dst = decoder.read_u32();
                    let src = decoder.read_u32();
                    self.registers[dst as usize] = self.registers[src as usize];
                }

                60 => { // FrameSetup
                    let frame_size = decoder.read_u32();
                    let frame = self.current_frame_mut();
                    frame.stack_pointer += frame_size as usize;
                    if frame.stack_pointer >= self.stack_memory.len() {
                        return Err(VMError::StackOverflow);
                    }
                }

                61 => { // FrameTeardown
                    let frame = self.current_frame_mut();
                    frame.stack_pointer = frame.frame_pointer;
                }

                62 => { // SpAdd
                    let offset = decoder.read_i32();
                    self.current_frame_mut().stack_pointer =
                        (self.current_frame().stack_pointer as i32 + offset) as usize;
                }

                63 => { // SpSub
                    let offset = decoder.read_i32();
                    self.current_frame_mut().stack_pointer =
                        (self.current_frame().stack_pointer as i32 - offset) as usize;
                }

                // Frame pointer loads
                72 => { // FpLoad32
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (self.current_frame().frame_pointer as i32 + offset) as usize;
                    self.registers[reg as usize] = u64::from(self.stack_load::<u32>(addr));
                }

                73 => { // FpLoad64
                    let reg = decoder.read_u32();
                    let offset = -decoder.read_i32();
                    let addr = (self.current_frame().frame_pointer as i32 + offset) as usize;
                    self.registers[reg as usize] = self.stack_load::<u64>(addr);
                }

                // Frame pointer stores
                76 => { // FpStore32
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (self.current_frame().frame_pointer as i32 + offset) as usize;
                    let value = self.registers[reg as usize] as u32;
                    self.stack_store(addr, value);
                }

                77 => { // FpStore64
                    let offset = -decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (self.current_frame().frame_pointer as i32 + offset) as usize;
                    let value = self.registers[reg as usize];
                    self.stack_store(addr, value);
                }

                // Stack pointer loads
                82 => { // SpLoad32
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (self.current_frame().stack_pointer as i32 + offset) as usize;
                    self.registers[reg as usize] = u64::from(self.stack_load::<u32>(addr));
                }

                83 => { // SpLoad64
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (self.current_frame().stack_pointer as i32 + offset) as usize;
                    self.registers[reg as usize] = self.stack_load::<u64>(addr);
                }

                // Stack pointer stores
                86 => { // SpStore32
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (self.current_frame().stack_pointer as i32 + offset) as usize;
                    let value = self.registers[reg as usize] as u32;
                    self.stack_store(addr, value);
                }

                87 => { // SpStore64
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (self.current_frame().stack_pointer as i32 + offset) as usize;
                    let value = self.registers[reg as usize];
                    self.stack_store(addr, value);
                }

                // Address calculation
                90 => { // FpAddr
                    let dst = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (self.current_frame().frame_pointer as i32 + offset) as u64;
                    self.registers[dst as usize] = addr;
                }

                91 => { // SpAddr
                    let dst = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (self.current_frame().stack_pointer as i32 + offset) as u64;
                    self.registers[dst as usize] = addr;
                }

                255 => { // Halt
                    self.halted = true;
                    break;
                }

                _ => {
                    return Err(VMError::InvalidOpcode(opcode_byte));
                }
            }

            // Advance PC to next instruction
            self.pc = decoder.get_pos(chunk.code.as_ptr());
        }

        Ok(())
    }

    // Helper method to get return values
    #[must_use] pub fn get_return_values(&self) -> [u64; 8] {
        if let Some(frame) = self.call_stack.last() {
            frame.registers
        } else {
            [0; 8]
        }
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
    #[must_use] pub fn new() -> Self {
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

