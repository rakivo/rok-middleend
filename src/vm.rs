use crate::ssa::ExtFuncId;
use crate::ssa::IntrinsicId;
use crate::entity::EntityRef;
use crate::ssa::Datas;
use crate::ssa::Intrinsics;
use crate::ssa::Signature;
use crate::ssa::Type;
use crate::util;
use crate::bytecode::Opcode;
use crate::bytecode::BytecodeChunk;
use crate::primary::PrimaryMap;
use crate::ssa::DataId;
use crate::ssa::FuncId;

use std::sync::Arc;
use std::{fmt, ptr};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use smallvec::SmallVec;

// ============================================================================
// VM DATA STRUCTURES (OPTIMIZED)
// ============================================================================

pub type VMCallback = Arc<dyn Fn(
    &mut VirtualMachine,
    &mut InstructionDecoder,
    &BytecodeChunk
)>;

/// VM execution errors
#[derive(Debug, Clone)]
pub enum VMError {
    EmptyCallStack,
    InvalidOpcode(u8),
    InvalidDataId(u32),
    InvalidFuncId(u32),
    InvalidIntrinId(u32),
    StackOverflow,
    StackUnderflow,
    DivisionByZero,
    InvalidMemoryAccess(u64),
    UnalignedAccess(u64),
    InvalidInstruction(String),
    ExecutionHalted,
    InterpreterPanic(String)
}

impl fmt::Display for VMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VMError::EmptyCallStack => write!(f, "Empty call stack"),
            VMError::InvalidOpcode(op) => write!(f, "Invalid opcode: {op}"),
            VMError::InvalidDataId(id) => write!(f, "Invalid data ID: {id}"),
            VMError::InvalidFuncId(id) => write!(f, "Invalid function ID: {id}"),
            VMError::InvalidIntrinId(id) => write!(f, "Invalid intrinsic ID: {id}"),
            VMError::StackOverflow => write!(f, "Stack overflow"),
            VMError::StackUnderflow => write!(f, "Stack underflow"),
            VMError::DivisionByZero => write!(f, "Division by zero"),
            VMError::InvalidMemoryAccess(addr) => write!(f, "Invalid memory access at 0x{addr:x}"),
            VMError::UnalignedAccess(addr) => write!(f, "Unaligned memory access at 0x{addr:x}"),
            VMError::InvalidInstruction(msg) => write!(f, "Invalid instruction: {msg}"),
            VMError::ExecutionHalted => write!(f, "Execution halted"),
            VMError::InterpreterPanic(msg) => write!(f, "Execution panicked: {msg}"),
        }
    }
}

impl std::error::Error for VMError {}

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

#[derive(Copy, Debug, Clone)]
pub struct StackFrame {
    pub func_id: FuncId,
    pub ret_pc: usize,
    pub fp: usize,
    pub sp: usize,
}

impl StackFrame {
    #[inline]
    #[must_use]
    pub const fn new(func_id: FuncId, ret_pc: usize, fp: usize, sp: usize) -> Self {
        StackFrame { func_id, ret_pc, fp, sp }
    }
}

#[derive(Clone)]
pub struct ExtFunc {
    pub signature: Signature,
    pub addr: *const ()
}

pub struct VirtualMachine<'a> {
    funcs: HashMap<FuncId, &'a BytecodeChunk>,
    ext_funcs: HashMap<ExtFuncId, ExtFunc>,

    call_stack: Vec<StackFrame>,
    pc: usize,

    stack_memory: Vec<u8>,
    stack_top: usize,

    intrinsics: Intrinsics,

    data_memory: Vec<u8>,
    data_offsets: HashMap<DataId, u32>,

    registers: [u64; 256], // r0-r7: return values, r8+: general purpose/args

    halted: bool,
}

macro_rules! def_op_binary {
    ($self:expr, $decoder:expr, $op:ident) => {
        let dst = $decoder.read_u32();
        let src1 = $decoder.read_u32();
        let src2 = $decoder.read_u32();
        let val1 = $self.reg_read(src1 as _);
        let val2 = $self.reg_read(src2 as _);
        $self.reg_write(dst as _, val1.$op(val2) as u64);
    };
}

macro_rules! def_op_binary_f {
    ($self:expr, $decoder:expr, $op:tt) => {
        let dst = $decoder.read_u32();
        let src1 = $decoder.read_u32();
        let src2 = $decoder.read_u32();
        let val1 = f64::from_bits($self.reg_read(src1 as _));
        let val2 = f64::from_bits($self.reg_read(src2 as _));
        $self.reg_write(dst as _, (val1 $op val2).to_bits());
    };
}

macro_rules! def_op_icmp {
    ($self:expr, $decoder:expr, $op:tt, $ty:ty) => {
        let dst = $decoder.read_u32();
        let src1 = $decoder.read_u32();
        let src2 = $decoder.read_u32();
        let val1 = $self.reg_read(src1 as _) as $ty;
        let val2 = $self.reg_read(src2 as _) as $ty;
        $self.reg_write(dst as _, (val1 $op val2) as u64);
    };
}

impl<'a> VirtualMachine<'a> {
    pub const STACK_SIZE: usize = 1024 * 1024;

    #[must_use]
    pub fn new() -> Self {
        let mut stack_memory = Vec::with_capacity(Self::STACK_SIZE);
        #[allow(clippy::uninit_vec)]
        unsafe {
            stack_memory.set_len(Self::STACK_SIZE);
        }

        VirtualMachine {
            intrinsics: PrimaryMap::new(),
            data_memory: Vec::new(),
            data_offsets: HashMap::new(),
            funcs: HashMap::new(),
            ext_funcs: HashMap::new(),
            call_stack: Vec::with_capacity(32),
            pc: 0,
            stack_memory,
            stack_top: 0,
            registers: [0; 256],
            halted: false,
        }
    }

    pub fn reset(&mut self) {
        self.call_stack.clear();
        self.pc = 0;
        // don't care about the memory
        // self.stack_memory.clear();
        self.stack_top = 0;
        self.registers = [0; 256];
        self.halted = false;
    }

    pub fn load_intrinsics(&mut self, intrinsics: Intrinsics) {
        self.intrinsics = intrinsics;
    }

    pub fn load_ext_funcs(&mut self, ext_funcs: HashMap<ExtFuncId, ExtFunc>) {
        self.ext_funcs = ext_funcs;
    }

    pub fn load_module_data(&mut self, datas: &Datas) {
        let mut current_offset = 0;

        let total_size = datas.values().map(|desc| {
            desc.contents.len()
        }).sum();

        self.data_memory.reserve(total_size);
        self.data_offsets.reserve(datas.len());

        for (data_id, data_desc) in datas.iter() {
            if !data_desc.is_external() {
                // Align data appropriately (e.g., 8-byte alignment)
                current_offset = util::align_up(current_offset, 8);

                // Record where this data starts
                self.data_offsets.insert(data_id, current_offset);

                // Append the data contents
                self.data_memory.extend_from_slice(&data_desc.contents.read());
                current_offset += data_desc.contents.len() as u32;
            }
        }
    }

    #[inline]
    pub fn add_function(&mut self, func_id: FuncId, chunk: &'a BytecodeChunk) {
        self.funcs.insert(func_id, chunk);
    }

    #[inline]
    pub fn add_external_function(
        &mut self,
        func_id: ExtFuncId,
        signature: Signature,
        addr: *const (),
    ) {
        self.ext_funcs.insert(func_id, ExtFunc { addr, signature });
    }

    #[inline]
    #[track_caller]
    pub fn get_args(&self, count: usize) -> SmallVec<[u64; 8]> {
        let mut ret = SmallVec::with_capacity(count);
        for reg in 8..count+8 {
            ret.push(self.reg_read(reg));
        }

        ret
    }

    #[inline]
    pub fn call_function(&mut self, func_id: FuncId, args: &[u64]) -> Result<[u64; 8], VMError> {
        Self::try_run(|| self.call_function_(func_id, args))
    }

    fn call_function_(&mut self, func_id: FuncId, args: &[u64]) -> Result<[u64; 8], VMError> {
        // Set up initial frame
        let chunk = self.funcs.get(&func_id).unwrap();

        unsafe {
            // Clear return registers for new function call
            ptr::write_bytes(self.registers.as_mut_ptr(), 0, 8);

            // Set up arguments in registers r8+
            let dst = self.registers.as_mut_ptr().add(8); // start at r8
            for (i, &arg) in args.iter().enumerate().take(256 - 8) {
                ptr::write(dst.add(i), arg);
            }
        }

        let frame_size = chunk.frame_info.total_size as usize;
        let new_fp = self.stack_top;
        let new_sp = self.stack_top + frame_size;

        #[cfg(debug_assertions)]
        if new_sp >= self.stack_memory.len() {
            return Err(VMError::StackOverflow);
        }

        let frame = StackFrame::new(func_id, 0, new_fp, new_sp);
        self.call_stack.push(frame);
        self.stack_top = new_sp;
        self.pc = 0;
        self.halted = false;

        self.execute()?;

        // Return values are in r0-r7
        let result = self.registers[0..8].try_into().unwrap();
        Ok(result)
    }

    #[inline]
    pub fn execute(&mut self) -> Result<(), VMError> {
        Self::try_run(|| self.execute_())
    }

    fn execute_(&mut self) -> Result<(), VMError> {
        let mut frame = *self.current_frame();

        while !self.halted && !self.call_stack.is_empty() {
            let func_id = frame.func_id;
            let chunk = self.get_chunk(func_id);
            let mut decoder = InstructionDecoder::new(&chunk.code);
            decoder.set_pos(self.pc, chunk.code.as_ptr());

            let opcode_byte = decoder.read_u8();
            let opcode = unsafe { std::mem::transmute(opcode_byte) };

            match opcode {
                Opcode::IConst8 => {
                    let reg = decoder.read_u32();
                    let value = i64::from(decoder.read_u8() as i8) as u64;
                    self.reg_write(reg as _, value);
                }

                Opcode::IConst16 => {
                    let reg = decoder.read_u32();
                    let value = i64::from(decoder.read_u16() as i16) as u64;
                    self.reg_write(reg as _, value);
                }

                Opcode::IConst32 => {
                    let reg = decoder.read_u32();
                    let value = i64::from(decoder.read_i32()) as u64;
                    self.reg_write(reg as _, value);
                }

                Opcode::IConst64 => {
                    let reg = decoder.read_u32();
                    let value = decoder.read_i64() as u64;
                    self.reg_write(reg as _, value);
                }

                Opcode::FConst32 => {
                    let reg = decoder.read_u32();
                    let value = u64::from(decoder.read_f32().to_bits());
                    self.reg_write(reg as _, value);
                }

                Opcode::FConst64 => {
                    let reg = decoder.read_u32();
                    let value = decoder.read_f64().to_bits();
                    self.reg_write(reg as _, value);
                }

                Opcode::IAdd => {
                    def_op_binary!(self, decoder, wrapping_add);
                }

                Opcode::ISub => {
                    def_op_binary!(self, decoder, wrapping_sub);
                }

                Opcode::IMul => {
                    def_op_binary!(self, decoder, wrapping_mul);
                }

                Opcode::IEq => {
                    def_op_icmp!(self, decoder, ==, u64);
                }
                Opcode::INe => {
                    def_op_icmp!(self, decoder, !=, u64);
                }
                Opcode::ISGt => {
                    def_op_icmp!(self, decoder, >, i64);
                }
                Opcode::ISGe => {
                    def_op_icmp!(self, decoder, >=, i64);
                }
                Opcode::ISLt => {
                    def_op_icmp!(self, decoder, <, i64);
                }
                Opcode::ISLe => {
                    def_op_icmp!(self, decoder, <=, i64);
                }
                Opcode::IUGt => {
                    def_op_icmp!(self, decoder, >, u64);
                }
                Opcode::IUGe => {
                    def_op_icmp!(self, decoder, >=, u64);
                }
                Opcode::IULt => {
                    def_op_icmp!(self, decoder, <, u64);
                }
                Opcode::IULe => {
                    def_op_icmp!(self, decoder, <=, u64);
                }

                Opcode::FAdd => {
                    def_op_binary_f!(self, decoder, +);
                }

                Opcode::FSub => {
                    def_op_binary_f!(self, decoder, -);
                }

                Opcode::FMul => {
                    def_op_binary_f!(self, decoder, *);
                }

                Opcode::FDiv => {
                    def_op_binary_f!(self, decoder, /);
                }

                Opcode::Jump16 => {
                    let offset = i32::from(decoder.read_u16() as i16);
                    let new_pc = (decoder.get_pos(chunk.code.as_ptr()) as i32 + offset) as usize;
                    self.pc = new_pc;
                    continue;
                }

                Opcode::BranchIf16 => {
                    let cond_reg = decoder.read_u32();
                    let offset = i32::from(decoder.read_u16() as i16);
                    let cond = self.reg_read(cond_reg as _);
                    if cond != 0 {
                        let new_pc = (decoder.get_pos(chunk.code.as_ptr()) as i32 + offset) as usize;
                        self.pc = new_pc;
                        continue;
                    }
                }

                Opcode::CallIntrin => {
                    let intrinsic_id = IntrinsicId::from_u32(decoder.read_u32());

                    #[cfg(debug_assertions)]
                    if intrinsic_id.index() >= self.intrinsics.len() {
                        return Err(VMError::InvalidIntrinId(intrinsic_id.as_u32()));
                    }

                    let callback = unsafe { util::reborrow(&self.intrinsics[intrinsic_id].vm_callback) };
                    let chunk = unsafe { util::reborrow(chunk) };
                    (callback)(self, &mut decoder, chunk);
                }

                Opcode::Call => {
                    let func_id = FuncId::from_u32(decoder.read_u32());

                    #[cfg(debug_assertions)]
                    if func_id.index() >= self.funcs.len() {
                        return Err(VMError::InvalidFuncId(func_id.as_u32()));
                    }

                    let save_start = self.stack_top;
                    let save_size = (256 - 8) * 8; // 248 registers * 8 bytes each

                    #[cfg(debug_assertions)]
                    if save_start + save_size >= self.stack_memory.len() {
                        return Err(VMError::StackOverflow);
                    }

                    let ret_pc = decoder.get_pos(chunk.code.as_ptr());

                    // Set up initial frame
                    let new_chunk = self.get_chunk(func_id);
                    let frame_size = new_chunk.frame_info.total_size as usize;
                    let new_fp = save_start + save_size; // Frame starts after saved registers
                    let new_sp = new_fp + frame_size;

                    #[cfg(debug_assertions)]
                    if new_sp >= self.stack_memory.len() {
                        return Err(VMError::StackOverflow);
                    }

                    let new_frame = StackFrame::new(
                        func_id,
                        ret_pc,
                        new_fp,
                        new_sp
                    );
                    self.call_stack.push(new_frame);
                    frame = new_frame;
                    self.stack_top = new_sp;
                    self.pc = 0;

                    continue;
                }

                Opcode::CallExt => {
                    let ext_func_id = ExtFuncId::from_u32(decoder.read_u32());

                    #[cfg(debug_assertions)]
                    if ext_func_id.index() >= self.ext_funcs.len() {
                        return Err(VMError::InvalidFuncId(ext_func_id.as_u32()));
                    }

                    use libffi::middle::Arg;
                    use libffi::middle::Cif;
                    use libffi::middle::Type as FFIType;
                    use std::os::raw::c_void;

                    fn ty_to_ffi(ty: Type) -> FFIType {
                        match ty {
                            Type::Ptr => FFIType::pointer(),
                            Type::I32 => FFIType::c_int(),
                            Type::I64 => FFIType::c_longlong(),
                            // C ABI promotion rules: smaller types promoted to int/unsigned int
                            Type::I8 => FFIType::c_int(),  // promoted to int
                            Type::I16 => FFIType::c_int(), // promoted to int
                            Type::U8 => FFIType::c_uint(), // promoted to unsigned int
                            Type::U16 => FFIType::c_uint(), // promoted to unsigned int
                            Type::U32 => FFIType::c_uint(),
                            Type::U64 => FFIType::c_ulonglong(),
                            _ => todo!()
                        }
                    }

                    let ExtFunc { ref signature, addr } = self.ext_funcs[&ext_func_id];

                    let rety = signature.returns.first();
                    let args = &signature.params;

                    let mut ffi_types = Vec::with_capacity(args.len());
                    let mut ffi_args = Vec::with_capacity(args.len());
                    let mut arg_storage: Vec<Box<dyn std::any::Any>> = Vec::new();

                    if ext_func_id.as_u32() == 3 {
                        let ptr = self.registers[8] as *const [u8; 5];
                        let bytes = unsafe { ptr.read() };
                        let s = unsafe {
                            std::str::from_utf8_unchecked(&bytes)
                        };
                        println!("{s}")
                    }

                    for (i, &ty) in args.iter().enumerate() {
                        match ty {
                            Type::I8 => {
                                // C ABI: i8 promoted to int
                                let val = self.registers[8 + i] as i8 as i32; // sign-extend to int
                                arg_storage.push(Box::new(val));
                                ffi_types.push(FFIType::c_int());
                                ffi_args.push(Arg::new(arg_storage.last().unwrap().downcast_ref::<i32>().unwrap()));
                            }
                            Type::I16 => {
                                // C ABI: i16 promoted to int
                                let val = self.registers[8 + i] as i16 as i32; // sign-extend to int
                                arg_storage.push(Box::new(val));
                                ffi_types.push(FFIType::c_int());
                                ffi_args.push(Arg::new(arg_storage.last().unwrap().downcast_ref::<i32>().unwrap()));
                            }
                            Type::I32 => {
                                // C ABI: i32 stays as i32 (no promotion needed)
                                let val = self.registers[8 + i] as i32;
                                arg_storage.push(Box::new(val));
                                ffi_types.push(FFIType::c_int());
                                ffi_args.push(Arg::new(arg_storage.last().unwrap().downcast_ref::<i32>().unwrap()));
                            }
                            Type::I64 => {
                                let val = self.registers[8 + i] as i64;
                                arg_storage.push(Box::new(val));
                                ffi_types.push(FFIType::c_longlong());
                                ffi_args.push(Arg::new(arg_storage.last().unwrap().downcast_ref::<i64>().unwrap()));
                            }
                            Type::U8 => {
                                // C ABI: u8 promoted to unsigned int
                                let val = self.registers[8 + i] as u64 as u8 as u32; // proper zero extension
                                arg_storage.push(Box::new(val));
                                ffi_types.push(FFIType::c_uint());
                                ffi_args.push(Arg::new(arg_storage.last().unwrap().downcast_ref::<u32>().unwrap()));
                            }
                            Type::U16 => {
                                // C ABI: u16 promoted to unsigned int
                                let val = self.registers[8 + i] as u64 as u16 as u32; // proper zero extension
                                arg_storage.push(Box::new(val));
                                ffi_types.push(FFIType::c_uint());
                                ffi_args.push(Arg::new(arg_storage.last().unwrap().downcast_ref::<u32>().unwrap()));
                            }
                            Type::U32 => {
                                let val = self.registers[8 + i] as u64 as u32;
                                arg_storage.push(Box::new(val));
                                ffi_types.push(FFIType::c_uint());
                                ffi_args.push(Arg::new(arg_storage.last().unwrap().downcast_ref::<u32>().unwrap()));
                            }
                            Type::U64 => {
                                let val = self.registers[8 + i] as u64;
                                arg_storage.push(Box::new(val));
                                ffi_types.push(FFIType::c_ulonglong());
                                ffi_args.push(Arg::new(arg_storage.last().unwrap().downcast_ref::<u64>().unwrap()));
                            }
                            Type::Ptr => {
                                let val = self.registers[8 + i] as *mut std::ffi::c_void;
                                arg_storage.push(Box::new(val));
                                ffi_types.push(FFIType::pointer());
                                ffi_args.push(Arg::new(arg_storage.last().unwrap().downcast_ref::<*mut c_void>().unwrap()));
                            }
                            _ => todo!(),
                        }
                    }

                    let rety = rety.copied().map_or(FFIType::void(), ty_to_ffi);
                    let cif = Cif::new(ffi_types, rety);
                    let result: u64 = unsafe { cif.call(std::mem::transmute(addr), &mut ffi_args) };
                    self.reg_write(0, result);
                }

                Opcode::Nop => {}

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
                    let save_start = old_frame.fp - save_size;

                    self.stack_top = save_start;
                    self.pc = old_frame.ret_pc;
                    frame = *self.current_frame();
                    continue;
                }

                Opcode::LoadDataAddr => {
                    let dst = decoder.read_u32() as usize;
                    let data_id = DataId::from_u32(decoder.read_u32());

                    if let Some(&offset) = self.data_offsets.get(&data_id) {
                        // Store the absolute address of the data in the register
                        // In a real VM, this might be a virtual address
                        let data_ptr = self.data_memory.as_ptr() as u64 + offset as u64;
                        self.registers[dst] = data_ptr;
                    } else {
                        return Err(VMError::InvalidDataId(data_id.as_u32()));
                    }
                }

                Opcode::Mov => {
                    let dst = decoder.read_u32();
                    let src = decoder.read_u32();
                    self.reg_write(dst as _, self.reg_read(src as _));
                }

                Opcode::Load32 => {
                    let dst_reg = decoder.read_u32();
                    let addr_reg = decoder.read_u32();
                    let addr = self.reg_read(addr_reg as _) as *const u32;
                    let val = unsafe { ptr::read(addr) };
                    self.reg_write(dst_reg as _, val as u64);
                }

                Opcode::Load64 => {
                    let dst_reg = decoder.read_u32();
                    let addr_reg = decoder.read_u32();
                    let addr = self.reg_read(addr_reg as _) as *const u64;
                    let val = unsafe { ptr::read(addr) };
                    self.reg_write(dst_reg as _, val);
                }

                Opcode::Store8 => {
                    let addr_reg = decoder.read_u32();
                    let val_reg = decoder.read_u32();
                    let addr = self.reg_read(addr_reg as _) as *mut u8;
                    let val = self.reg_read(val_reg as _) as u8;
                    unsafe { ptr::write(addr, val); }
                }

                Opcode::Store16 => {
                    let addr_reg = decoder.read_u32();
                    let val_reg = decoder.read_u32();
                    let addr = self.reg_read(addr_reg as _) as *mut u16;
                    let val = self.reg_read(val_reg as _) as u16;
                    unsafe { ptr::write(addr, val); }
                }

                Opcode::Store32 => {
                    let addr_reg = decoder.read_u32();
                    let val_reg = decoder.read_u32();
                    let addr = self.reg_read(addr_reg as _) as *mut u32;
                    let val = self.reg_read(val_reg as _) as u32;
                    unsafe { ptr::write(addr, val); }
                }

                Opcode::Store64 => {
                    let addr_reg = decoder.read_u32();
                    let val_reg = decoder.read_u32();
                    let addr = self.reg_read(addr_reg as _) as *mut u64;
                    let val = self.reg_read(val_reg as _);
                    unsafe { ptr::write(addr, val); }
                }

                Opcode::FrameSetup => {
                    let frame_size = decoder.read_u32();
                    frame.sp += frame_size as usize;
                    if frame.sp >= self.stack_memory.len() {
                        return Err(VMError::StackOverflow);
                    }
                }

                Opcode::FrameTeardown => {
                    frame.sp = frame.fp;
                }

                Opcode::SpAdd => {
                    let offset = decoder.read_i32();
                    frame.sp = (frame.sp as i32 + offset) as usize;
                }

                Opcode::SpSub => {
                    let offset = decoder.read_i32();
                    frame.sp = (frame.sp as i32 - offset) as usize;
                }

                Opcode::FpLoad32 => {
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let v = self.stack_read_u32(addr);
                    self.reg_write(reg as _, v as u64);
                }

                Opcode::FpLoad64 => {
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let v = self.stack_read_u64(addr);
                    self.reg_write(reg as _, v);
                }

                Opcode::FpStore32 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let v = self.reg_read(reg as _);
                    self.stack_write_u32(addr, v as u32);
                }

                Opcode::FpStore64 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let v = self.reg_read(reg as _);
                    self.stack_write_u64(addr, v);
                }

                Opcode::SpLoad32 => {
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (frame.sp as i32 + offset) as usize;
                    let v = self.stack_read_u32(addr);
                    self.reg_write(reg as _, v as u64);
                }

                Opcode::SpLoad64 => {
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (frame.sp as i32 + offset) as usize;
                    let v = self.stack_read_u64(addr);
                    self.reg_write(reg as _, v);
                }

                Opcode::SpStore32 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (frame.sp as i32 + offset) as usize;
                    let v = self.reg_read(reg as _);
                    self.stack_write_u32(addr, v as u32);
                }

                Opcode::SpStore64 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32();
                    let addr = (frame.sp as i32 + offset) as usize;
                    let v = self.reg_read(reg as _);
                    self.stack_write_u64(addr, v);
                }

                Opcode::FpAddr => {
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let addr = unsafe { self.stack_memory.as_ptr().add(addr) as _ };
                    self.reg_write(reg as _, addr);
                }

                Opcode::SpAddr => {
                    let reg = decoder.read_u32();
                    let offset = decoder.read_i32();
                    let addr = (frame.sp as i32 + offset) as u64;
                    self.reg_write(reg as _, addr);
                }

                Opcode::Halt => {
                    self.halted = true;
                    break;
                }

                _ => {
                    return Err(VMError::InvalidOpcode(opcode_byte));
                }
            }

            let chunk = self.get_chunk(func_id);
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

impl VirtualMachine<'_> {
    fn try_run<T>(f: impl FnOnce() -> Result<T, VMError>) -> Result<T, VMError> {
        let result = catch_unwind(AssertUnwindSafe(f));

        match result {
            Ok(ok) => ok,
            Err(payload) => {
                // Convert panic payload into string
                let panic_msg = if let Some(s) = payload.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.to_owned()
                } else {
                    "non-string panic".to_string()
                };
                Err(VMError::InterpreterPanic(panic_msg))
            }
        }
    }

    // ---- tiny accessor helpers ----
    #[inline(always)]
    fn reg_read(&self, index: usize) -> u64 {
        #[cfg(debug_assertions)]
        {
            if index >= self.registers.len() {
                panic!(
                    "reg_read out-of-bounds: idx={} len={} (pc={} frame={:?})",
                    index, self.registers.len(), self.pc, self.current_frame()
                );
            }
            self.registers[index]
        }
        #[cfg(not(debug_assertions))]
        {
            unsafe { *self.registers.get_unchecked(index) }
        }
    }

    #[inline(always)]
    fn reg_write(&mut self, index: usize, v: u64) {
        #[cfg(debug_assertions)]
        {
            if index >= self.registers.len() {
                panic!(
                    "reg_write out-of-bounds: idx={} len={} (pc={} frame={:?})",
                    index, self.registers.len(), self.pc, self.current_frame()
                );
            }
            self.registers[index] = v;
        }
        #[cfg(not(debug_assertions))]
        {
            unsafe { *self.registers.get_unchecked_mut(index) = v }
        }
    }

    #[inline(always)]
    fn stack_read_u64(&self, addr: usize) -> u64 {
        #[cfg(debug_assertions)]
        {
            if addr + 8 > self.stack_memory.len() {
                panic!("stack_read_u64 OOB: addr={} len={}", addr, self.stack_memory.len());
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&self.stack_memory[addr..addr + 8]);
            u64::from_le_bytes(b)
        }
        #[cfg(not(debug_assertions))]
        {
            unsafe { ptr::read_unaligned(self.stack_memory.as_ptr().add(addr).cast::<u64>()) }
        }
    }

    #[inline(always)]
    fn stack_write_u64(&mut self, addr: usize, v: u64) {
        #[cfg(debug_assertions)]
        {
            if addr + 8 > self.stack_memory.len() {
                panic!("stack_write_u64 OOB: addr={} len={}", addr, self.stack_memory.len());
            }
            let b = v.to_le_bytes();
            self.stack_memory[addr..addr + 8].copy_from_slice(&b);
        }
        #[cfg(not(debug_assertions))]
        {
            unsafe { ptr::write_unaligned(self.stack_memory.as_mut_ptr().add(addr).cast::<u64>(), v) }
        }
    }

    #[inline(always)]
    fn stack_read_u32(&self, addr: usize) -> u32 {
        #[cfg(debug_assertions)]
        {
            if addr + 4 > self.stack_memory.len() {
                panic!("stack_read_u32 OOB: addr={} len={}", addr, self.stack_memory.len());
            }
            let mut b = [0u8; 4];
            b.copy_from_slice(&self.stack_memory[addr..addr + 4]);
            u32::from_le_bytes(b)
        }
        #[cfg(not(debug_assertions))]
        {
            unsafe { ptr::read_unaligned(self.stack_memory.as_ptr().add(addr).cast::<u32>()) }
        }
    }

    #[inline(always)]
    fn stack_write_u32(&mut self, addr: usize, v: u32) {
        #[cfg(debug_assertions)]
        {
            if addr + 4 > self.stack_memory.len() {
                panic!("stack_write_u32 OOB: addr={} len={}", addr, self.stack_memory.len());
            }
            let b = v.to_le_bytes();
            self.stack_memory[addr..addr + 4].copy_from_slice(&b);
        }
        #[cfg(not(debug_assertions))]
        {
            unsafe { ptr::write_unaligned(self.stack_memory.as_mut_ptr().add(addr).cast::<u32>(), v) }
        }
    }

    // helper to get chunk pointer in a single place (safer to centralize)
    #[inline(always)]
    fn get_chunk(&self, func_id: FuncId) -> &BytecodeChunk {
        #[cfg(debug_assertions)]
        {
            self.funcs
                .get(&func_id)
                .expect("invalid function id")
        }
        #[cfg(not(debug_assertions))]
        unsafe {
            self.funcs
                .get(&func_id)
                .unwrap_unchecked()
        }
    }

    #[inline(always)]
    fn current_frame(&self) -> &StackFrame {
        #[cfg(debug_assertions)]
        {
            self.call_stack
                .last()
                .unwrap()
        }
        #[cfg(not(debug_assertions))]
        unsafe {
            self.call_stack
                .last()
                .unwrap_unchecked()
        }
    }
}
