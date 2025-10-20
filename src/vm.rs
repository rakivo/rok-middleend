#![cfg_attr(not(debug_assertions), allow(unused_imports))]

use crate::regalloc::{REG_COUNT, SCRATCH_REG};
use crate::util;
use crate::primary::PrimaryMap;
use crate::entity::EntityRef;
use crate::bytecode::{Opcode, BytecodeChunk};
use crate::ssa::{
    Type,
    DataId,
    FuncId,
    Signature,
    ExtFuncId,
    Hooks,
    HookId,
};

use std::ops::Deref;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::{fmt, ptr, mem};
use std::panic::{catch_unwind, AssertUnwindSafe};

use smallvec::SmallVec;
use rustc_hash::FxHashMap;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};

// Data management types moved from rok_middleend
#[derive(Debug)]
pub struct AtomicContents(pub RwLock<Box<[u8]>>);

impl Clone for AtomicContents {
    fn clone(&self) -> Self {
        Self(RwLock::new(self.0.read().clone()))
    }
}

impl IntoIterator for &AtomicContents {
    type Item = u8;
    type IntoIter = std::vec::IntoIter<u8>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl AtomicContents {
    #[inline(always)]
    #[must_use]
    pub fn new(contents: Box<[u8]>) -> Self {
        Self(RwLock::new(contents))
    }

    #[inline(always)]
    pub fn read(&self) -> RwLockReadGuard<'_, Box<[u8]>> {
        self.0.read()
    }

    #[inline(always)]
    pub fn write(&self) -> RwLockWriteGuard<'_, Box<[u8]>> {
        self.0.write()
    }

    // Length operations
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.read().len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.read().is_empty()
    }

    // Element access
    #[inline(always)]
    pub fn get(&self, index: usize) -> Option<u8> {
        self.0.read().get(index).copied()
    }

    #[inline(always)]
    pub fn first(&self) -> Option<u8> {
        self.0.read().first().copied()
    }

    #[inline(always)]
    pub fn last(&self) -> Option<u8> {
        self.0.read().last().copied()
    }

    // Iterator
    #[inline(always)]
    pub fn iter(&self) -> std::vec::IntoIter<u8> {
        self.0.read().iter().copied().collect::<Vec<_>>().into_iter()
    }

    // Chunked iteration
    #[inline(always)]
    pub fn chunks(&self, chunk_size: usize) -> Vec<Vec<u8>> {
        let guard = self.0.read();
        guard.chunks(chunk_size).map(<[u8]>::to_vec).collect()
    }
}

// TODO(#13): Data names in DataDescription
#[derive(Debug)]
pub struct DataDescription {
    pub size: u32,
    pub is_external: AtomicBool,
    pub contents: Box<[u8]>,
}

impl Clone for DataDescription {
    fn clone(&self) -> Self {
        Self {
            size: self.size,
            is_external: self.is_external().into(),
            contents: self.contents.clone()
        }
    }
}

impl DataDescription {
    pub fn is_external(&self) -> bool {
        self.is_external.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub struct DataDescriptionView<'a> {
    pub size: u32,
    pub is_external: bool,
    pub contents: &'a [u8]
}

pub enum DataView<'a> {
    Defined(DataDescriptionView<'a>),
    Placeholder(u32)
}

impl DataView<'_> {
    pub fn size(&self) -> u32 {
        match self {
            Self::Defined(d) => d.size,
            Self::Placeholder(p) => *p
        }
    }
}

/// A view over all data slots, holding the lock for the duration.
pub struct AllDatasView<'a> {
    pub datas: Vec<(DataId, DataView<'a>)>,
}

impl<'a> Deref for AllDatasView<'a> {
    type Target = Vec<(DataId, DataView<'a>)>;
    fn deref(&self) -> &Self::Target { &self.datas }
}

pub type VMCallback = Arc<dyn Fn(
    &mut VirtualMachine,
    &mut InstructionDecoder,
    &BytecodeChunk
)>;

/// VM execution errors
#[derive(Debug, Clone)]
pub enum VMError {
    FFIError,
    EmptyCallStack,
    InvalidOpcode(u8),
    InvalidDataId(DataId),
    InvalidFuncId(FuncId),
    InvalidExtFuncId(ExtFuncId),
    InvalidHookId(HookId),
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
            VMError::FFIError => write!(f, "FFIError"),
            VMError::EmptyCallStack => write!(f, "Empty call stack"),
            VMError::InvalidOpcode(op) => write!(f, "Invalid opcode: {op}"),
            VMError::InvalidDataId(id) => write!(f, "Invalid data ID: {id}"),
            VMError::InvalidFuncId(id) => write!(f, "Invalid function ID: {id}"),
            VMError::InvalidExtFuncId(id) => write!(f, "Invalid ext function ID: {id}"),
            VMError::InvalidHookId(id) => write!(f, "Invalid hook ID: {id}"),
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
    pub addr: *const (),
    pub name: Box<str>
}

pub type VmFuncMap = FxHashMap<FuncId, Arc<BytecodeChunk>>;
pub type VmExtFuncMap = FxHashMap<ExtFuncId, ExtFunc>;

pub struct VirtualMachine {
    funcs: VmFuncMap,
    ext_funcs: VmExtFuncMap,

    call_stack: Vec<StackFrame>,
    pc: usize,

    stack_memory: Box<[u8]>,
    stack_top: usize,

    hooks: Hooks,

    data_memory: Vec<u8>,
    data_offsets: FxHashMap<DataId, u32>,

    registers: [u64; SCRATCH_REG as usize + 1],

    halted: bool,
}

macro_rules! def_op_binary {
    ($self:expr, $decoder:expr, $op:ident) => {
        let dst = $decoder.read_u8();
        let src1 = $decoder.read_u8();
        let src2 = $decoder.read_u8();
        let val1 = $self.reg_read(src1 as _);
        let val2 = $self.reg_read(src2 as _);
        $self.reg_write(dst as _, val1.$op(val2 as _) as _);
    };
}

macro_rules! def_op_binary_f {
    ($self:expr, $decoder:expr, $op:tt) => {
        let dst = $decoder.read_u8();
        let src1 = $decoder.read_u8();
        let src2 = $decoder.read_u8();
        let val1 = f64::from_bits($self.reg_read(src1 as _));
        let val2 = f64::from_bits($self.reg_read(src2 as _));
        $self.reg_write(dst as _, (val1 $op val2).to_bits());
    };
}

macro_rules! def_op_icmp {
    ($self:expr, $decoder:expr, $op:tt, $ty:ty) => {
        let dst = $decoder.read_u8();
        let src1 = $decoder.read_u8();
        let src2 = $decoder.read_u8();
        let val1 = $self.reg_read(src1 as _) as $ty;
        let val2 = $self.reg_read(src2 as _) as $ty;
        $self.reg_write(dst as _, (val1 $op val2) as u64);
    };
}

impl VirtualMachine {
    pub const STACK_SIZE: usize = 1024 * 1024;

    #[inline]
    #[must_use]
    pub fn new() -> Self {
        let mut stack_memory = Vec::with_capacity(Self::STACK_SIZE);
        #[allow(clippy::uninit_vec)]
        unsafe {
            stack_memory.set_len(Self::STACK_SIZE);
        }
        let stack_memory = stack_memory.into_boxed_slice();

        VirtualMachine {
            hooks: PrimaryMap::new(),
            data_memory: Vec::new(),
            data_offsets: FxHashMap::default(),
            funcs: FxHashMap::default(),
            ext_funcs: FxHashMap::default(),
            call_stack: Vec::with_capacity(32),
            pc: 0,
            stack_memory,
            stack_top: 0,
            registers: [0; _],
            halted: false,
        }
    }

    #[inline]
    pub fn reset(&mut self) {
        self.call_stack.clear();
        self.pc = 0;
        // don't care about the stack memory
        // self.stack_memory.clear();
        self.stack_top = 0;
        self.registers = [0; _];
        self.halted = false;
    }

    #[inline(always)]
    pub fn load_hooks(&mut self, hooks: Hooks) {
        self.hooks = hooks;
    }

    #[inline(always)]
    pub fn load_ext_funcs(&mut self, ext_funcs: FxHashMap<ExtFuncId, ExtFunc>) {
        self.ext_funcs = ext_funcs;
    }

    pub fn initialize_module_data(&mut self, datas: AllDatasView) {
        let total_size = datas.iter().map(|(_, desc)| desc.size() as usize).sum();
        self.data_memory.reserve(total_size);
        self.data_offsets.reserve(datas.len());

        let mut total_aligned_size = 0;
        for (_, data_desc) in &*datas {
            total_aligned_size = util::align_up(total_aligned_size, 8);
            total_aligned_size += data_desc.size();
        }

        self.data_memory.resize(total_aligned_size as _, 0);

        let mut current_offset = 0;
        for (data_id, data_desc) in &*datas {
            current_offset = util::align_up(current_offset, 8);
            self.data_offsets.insert(*data_id, current_offset);

            if let DataView::Defined(data_desc) = data_desc {
                if data_desc.contents.is_empty() {
                    // leave placeholder zeroed out
                } else {
                    let contents = &data_desc.contents;
                    let curr = current_offset as usize;
                    self.data_memory[curr..curr + contents.len()].copy_from_slice(&contents);
                }
            }

            current_offset += data_desc.size();
        }
    }

    #[inline]
    pub fn patch_data(&mut self, data_id: DataId, contents: &[u8]) {
        let offset = self.data_offsets[&data_id] as usize;
        self.data_memory[
            offset..offset + contents.len()
        ].copy_from_slice(contents);
    }

    #[inline(always)]
    pub fn add_function(&mut self, func_id: FuncId, chunk: Arc<BytecodeChunk>) {
        self.funcs.insert(func_id, chunk);
    }

    #[inline]
    pub fn add_external_function(
        &mut self,
        func_id: ExtFuncId,
        signature: Signature,
        addr: *const (),
        name: impl Into<Box<str>>
    ) {
        self.ext_funcs.insert(func_id, ExtFunc {
            signature,
            addr,
            name: name.into()
        });
    }

    #[inline]
    #[track_caller]
    #[must_use]
    pub fn get_args(&self, count: usize) -> SmallVec<[u64; 8]> {
        let mut ret = SmallVec::with_capacity(count);
        for reg in 0..count {
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

            // Set up arguments in registers
            let dst = self.registers.as_mut_ptr();
            for (i, &arg) in args.iter().enumerate().take(8) {
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

    #[inline(always)]
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
            let opcode: Opcode = unsafe {
                mem::transmute(opcode_byte)
            };

            match opcode {
                Opcode::IConst8 => {
                    let reg = decoder.read_u8();
                    let value = i64::from(decoder.read_u8() as i8) as u64;
                    self.reg_write(reg as _, value);
                }

                Opcode::IConst16 => {
                    let reg = decoder.read_u8();
                    let value = i64::from(decoder.read_u16() as i16) as u64;
                    self.reg_write(reg as _, value);
                }

                Opcode::IConst32 => {
                    let reg = decoder.read_u8();
                    let value = i64::from(decoder.read_i32()) as u64;
                    self.reg_write(reg as _, value);
                }

                Opcode::IConst64 => {
                    let reg = decoder.read_u8();
                    let value = decoder.read_i64() as u64;
                    self.reg_write(reg as _, value);
                }

                Opcode::FConst32 => {
                    let reg = decoder.read_u8();
                    let value = u64::from(decoder.read_f32().to_bits());
                    self.reg_write(reg as _, value);
                }

                Opcode::FConst64 => {
                    let reg = decoder.read_u8();
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

                Opcode::Ishl => {
                    def_op_binary!(self, decoder, wrapping_shl);
                }

                Opcode::Ireduce => {
                    let dst = decoder.read_u8();
                    let src = decoder.read_u8();
                    let bits = decoder.read_u8();
                    let val = self.reg_read(src as _);
                    let mask = (1u64 << bits) - 1;
                    self.reg_write(dst as _, val & mask);
                }

                Opcode::Uextend => {
                    let dst = decoder.read_u8();
                    let src = decoder.read_u8();
                    let _from_bits = decoder.read_u8();
                    let _to_bits = decoder.read_u8();
                    let val = self.reg_read(src as _);
                    self.reg_write(dst as _, val);
                }

                Opcode::Bitcast => {
                    let dst = decoder.read_u8();
                    let src = decoder.read_u8();
                    let _ty = decoder.read_u8();
                    let val = self.reg_read(src as _);
                    self.reg_write(dst as _, val);
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

                Opcode::Bor => {
                    let dst = decoder.read_u8();
                    let src1 = decoder.read_u8();
                    let src2 = decoder.read_u8();
                    let val1 = self.reg_read(src1 as _);
                    let val2 = self.reg_read(src2 as _);
                    self.reg_write(dst as _, val1 | val2);
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
                    let cond_reg = decoder.read_u8();
                    let offset = i32::from(decoder.read_u16() as i16);
                    let cond = self.reg_read(cond_reg as _);
                    if cond != 0 {
                        let new_pc = (decoder.get_pos(chunk.code.as_ptr()) as i32 + offset) as usize;
                        self.pc = new_pc;
                        continue;
                    }
                }

                Opcode::CallHook => {
                    let hook_id = HookId::from_u32(decoder.read_u32());

                    #[cfg(debug_assertions)]
                    if hook_id.index() >= self.hooks.len() {
                        return Err(VMError::InvalidHookId(hook_id));
                    }

                    let callback = unsafe { util::reborrow(&self.hooks[hook_id].vm_callback) };
                    let chunk = unsafe { util::reborrow(chunk) };
                    (callback)(self, &mut decoder, chunk);
                }

                Opcode::Call => {
                    let func_id = FuncId::from_u32(decoder.read_u32());

                    #[cfg(debug_assertions)]
                    if func_id.index() >= self.funcs.len() {
                        return Err(VMError::InvalidFuncId(func_id));
                    }

                    let save_start = self.stack_top;
                    let save_size = (REG_COUNT as usize) * 8; // reg count registers * 8 bytes each

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
                    use libffi::middle::Arg;
                    use libffi::middle::Type as FFIType;
                    use libffi::low::prep_cif_var;
                    use libffi::raw::{
                        ffi_call,
                        ffi_cif,
                        ffi_abi_FFI_DEFAULT_ABI,
                    };

                    let ext_func_id = ExtFuncId::from_u32(
                        decoder.read_u32()
                    );

                    #[cfg(debug_assertions)]
                    if ext_func_id.index() >= self.ext_funcs.len() {
                        return Err(VMError::InvalidExtFuncId(ext_func_id));
                    }

                    #[inline]
                    fn ty_to_ffi(ty: Type) -> FFIType {
                        match ty {
                            Type::Ptr => FFIType::pointer(),
                            Type::I8  => FFIType::i8 (),
                            Type::U8  => FFIType::u8 (),
                            Type::I16 => FFIType::i16(),
                            Type::U16 => FFIType::u16(),
                            Type::I32 => FFIType::i32(),
                            Type::U32 => FFIType::u32(),
                            Type::I64 => FFIType::i64(),
                            Type::U64 => FFIType::u64(),
                            Type::F32 => FFIType::f32(),
                            Type::F64 => FFIType::f64(),
                        }
                    }

                    let ExtFunc { ref signature, addr, ref name } = self.ext_funcs[&ext_func_id];

                    let rety = signature.returns.first();
                    let args = &signature.params;

                    // Store all values directly (not boxed) - must be stack-allocated before we reference them
                    let mut arg_values = Vec::with_capacity(args.len());
                    let mut ffi_types = Vec::with_capacity(args.len());

                    let is_variadic = signature.is_var_arg.is_some();
                    let nfixedargs = signature.is_var_arg.map(|n| n as usize).unwrap_or(0);

                    for (i, &ty) in args.iter().enumerate() {
                        let actual_ty = if is_variadic && i >= nfixedargs {
                            // For variadic arguments, promote small types according to ABI
                            match ty {
                                Type::I8 | Type::U8 => Type::I32,    // Promote to I32
                                Type::I16 | Type::U16 => Type::I32,  // Promote to I32
                                _ => ty,                              // Keep larger types as-is
                            }
                        } else {
                            ty
                        };

                        ffi_types.push(ty_to_ffi(actual_ty));
                        arg_values.push(self.registers[i] as u64);
                    }

                    // Now create Arg references - these point into arg_values which is stable
                    let ffi_args = arg_values
                        .iter()
                        .map(Arg::new)
                        .collect::<Vec<_>>();

                    let mut rety = rety.copied().map_or(FFIType::void(), ty_to_ffi);

                    let mut cif: ffi_cif = unsafe { mem::zeroed() };

                    // Check if this is actually a variadic function
                    let is_variadic = signature.is_var_arg.is_some();

                    unsafe {
                        let status = if is_variadic {
                            let nfixedargs = signature.is_var_arg.unwrap() as usize;
                            // For variadic functions: nfixedargs = fixed params, ffi_args.len() = total args
                            // The fixed args must come first in ffi_types
                            prep_cif_var(
                                &mut cif,
                                ffi_abi_FFI_DEFAULT_ABI,
                                nfixedargs,          // number of fixed parameters
                                ffi_args.len(),       // total number of arguments
                                &mut rety as *mut _ as _,
                                ffi_types.as_mut_ptr() as _,
                            )
                        } else {
                            // Use regular prep_cif for non-variadic functions
                            use libffi::low::prep_cif;
                            prep_cif(
                                &mut cif,
                                ffi_abi_FFI_DEFAULT_ABI,
                                ffi_args.len(),
                                &mut rety as *mut _ as _,
                                ffi_types.as_mut_ptr() as _,
                            )
                        };

                        if let Err(e) = status {
                            panic!{
                                "\
                                    FFI call preparation failed: {e:?}\n\
                                    func: {name}:\n\
                                    signature: {signature:?}",
                            };
                        }
                    };

                    let mut result = 0u64;

                    unsafe {
                        ffi_call(
                            &mut cif,
                            mem::transmute(addr),
                            &mut result as *mut _ as _,
                            ffi_args.as_ptr() as *mut _,
                        );
                    }

                    if !signature.returns.is_empty() {
                        self.reg_write(0, result);
                    }
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

                    let save_size = (REG_COUNT as usize) * 8;
                    let save_start = old_frame.fp.saturating_sub(save_size);

                    self.stack_top = save_start;
                    self.pc = old_frame.ret_pc;
                    frame = *self.current_frame();
                    continue;
                }

                Opcode::LoadDataAddr => {
                    let dst = decoder.read_u8() as usize;
                    let data_id = DataId::from_u32(decoder.read_u32());

                    if let Some(&offset) = self.data_offsets.get(&data_id) {
                        let data_ptr = self.data_memory.as_ptr() as u64 + u64::from(offset);
                        self.registers[dst] = data_ptr;
                    } else {
                        return Err(VMError::InvalidDataId(data_id));
                    }
                }

                Opcode::Mov => {
                    let dst = decoder.read_u8();
                    let src = decoder.read_u8();
                    self.reg_write(dst as _, self.reg_read(src as _));
                }

                Opcode::Load8 => {
                    let dst_reg = decoder.read_u8();
                    let addr_reg = decoder.read_u8();
                    let addr = self.reg_read(addr_reg as _) as *const u8;
                    let val = unsafe { ptr::read(addr) };
                    self.reg_write(dst_reg as _, u64::from(val));
                }

                Opcode::Load16 => {
                    let dst_reg = decoder.read_u8();
                    let addr_reg = decoder.read_u8();
                    let addr = self.reg_read(addr_reg as _) as *const u16;
                    let val = unsafe { ptr::read(addr) };
                    self.reg_write(dst_reg as _, u64::from(val));
                }

                Opcode::Load32 => {
                    let dst_reg = decoder.read_u8();
                    let addr_reg = decoder.read_u8();
                    let addr = self.reg_read(addr_reg as _) as *const u32;
                    let val = unsafe { ptr::read(addr) };
                    self.reg_write(dst_reg as _, u64::from(val));
                }

                Opcode::Load64 => {
                    let dst_reg = decoder.read_u8();
                    let addr_reg = decoder.read_u8();
                    let addr = self.reg_read(addr_reg as _) as *const u64;
                    let val = unsafe { ptr::read(addr) };
                    self.reg_write(dst_reg as _, val);
                }

                Opcode::Store8 => {
                    let addr_reg = decoder.read_u8();
                    let val_reg = decoder.read_u8();
                    let addr = self.reg_read(addr_reg as _) as *mut u8;
                    let val = self.reg_read(val_reg as _) as u8;
                    unsafe { ptr::write(addr, val); }
                }

                Opcode::Store16 => {
                    let addr_reg = decoder.read_u8();
                    let val_reg = decoder.read_u8();
                    let addr = self.reg_read(addr_reg as _) as *mut u16;
                    let val = self.reg_read(val_reg as _) as u16;
                    unsafe { ptr::write(addr, val); }
                }

                Opcode::Store32 => {
                    let addr_reg = decoder.read_u8();
                    let val_reg = decoder.read_u8();
                    let addr = self.reg_read(addr_reg as _) as *mut u32;
                    let val = self.reg_read(val_reg as _) as u32;
                    unsafe { ptr::write(addr, val); }
                }

                Opcode::Store64 => {
                    let addr_reg = decoder.read_u8();
                    let val_reg = decoder.read_u8();
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

                Opcode::FpLoad8 => {
                    let reg = decoder.read_u8();
                    let offset = decoder.read_i32();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let v = self.stack_read_u8(addr);
                    self.reg_write(reg as _, u64::from(v));
                }

                Opcode::FpLoad32 => {
                    let reg = decoder.read_u8();
                    let offset = decoder.read_i32();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let v = self.stack_read_u32(addr);
                    self.reg_write(reg as _, u64::from(v));
                }

                Opcode::FpLoad64 => {
                    let reg = decoder.read_u8();
                    let offset = decoder.read_i32();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let v = self.stack_read_u64(addr);
                    self.reg_write(reg as _, v);
                }

                Opcode::FpStore8 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u8();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let v = self.reg_read(reg as _);
                    self.stack_write_u8(addr, v as u8);
                }

                Opcode::FpStore32 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u8();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let v = self.reg_read(reg as _);
                    self.stack_write_u32(addr, v as u32);
                }

                Opcode::FpStore64 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u8();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let v = self.reg_read(reg as _);
                    self.stack_write_u64(addr, v);
                }

                Opcode::SpLoad32 => {
                    let reg = decoder.read_u8();
                    let offset = decoder.read_i32();
                    let addr = (frame.sp as i32 + offset) as usize;
                    let v = self.stack_read_u32(addr);
                    self.reg_write(reg as _, u64::from(v));
                }

                Opcode::SpLoad64 => {
                    let reg = decoder.read_u8();
                    let offset = decoder.read_i32();
                    let addr = (frame.sp as i32 + offset) as usize;
                    let v = self.stack_read_u64(addr);
                    self.reg_write(reg as _, v);
                }

                Opcode::SpStore32 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u8();
                    let addr = (frame.sp as i32 + offset) as usize;
                    let v = self.reg_read(reg as _);
                    self.stack_write_u32(addr, v as u32);
                }

                Opcode::SpStore64 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u8();
                    let addr = (frame.sp as i32 + offset) as usize;
                    let v = self.reg_read(reg as _);
                    self.stack_write_u64(addr, v);
                }

                Opcode::FpAddr => {
                    let reg = decoder.read_u8();
                    let offset = decoder.read_i32();
                    let addr = (frame.fp as i32 + offset) as usize;
                    let addr = unsafe { self.stack_memory.as_ptr().add(addr) as _ };
                    self.reg_write(reg as _, addr);
                }

                Opcode::SpAddr => {
                    let reg = decoder.read_u8();
                    let offset = decoder.read_i32();
                    let addr = (frame.sp as i32 + offset) as u64;
                    self.reg_write(reg as _, addr);
                }

                Opcode::Halt => {
                    self.halted = true;
                    break;
                }

                other => {
                    println!("{other:#?}");
                    return Err(VMError::InvalidOpcode(opcode_byte));
                }
            }

            let chunk = self.get_chunk(func_id);
            self.pc = decoder.get_pos(chunk.code.as_ptr());
        }

        Ok(())
    }
}

impl VirtualMachine {
    fn try_run<T>(f: impl FnOnce() -> Result<T, VMError>) -> Result<T, VMError> {
        let result = catch_unwind(AssertUnwindSafe(f));

        match result {
            Ok(ok) => ok,
            Err(payload) => {
                // Convert panic payload into string
                let panic_msg = if let Some(s) = payload.downcast_ref::<&str>() {
                    (*s).to_string()
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
    #[track_caller]
    #[inline(always)]
    fn reg_read(&self, index: usize) -> u64 {
        #[cfg(debug_assertions)]
        {
            assert!((index < self.registers.len()),
                    "reg_read out-of-bounds: idx={} len={} (pc={} frame={:?})",
                    index, self.registers.len(), self.pc, self.current_frame()
                );
            self.registers[index]
        }
        #[cfg(not(debug_assertions))]
        {
            unsafe { *self.registers.get_unchecked(index) }
        }
    }

    #[track_caller]
    #[inline(always)]
    pub fn reg_write(&mut self, index: usize, v: u64) {
        #[cfg(debug_assertions)]
        {
            assert!((index < self.registers.len()),
                    "reg_write out-of-bounds: idx={} len={} (pc={} frame={:?})",
                    index, self.registers.len(), self.pc, self.current_frame()
                );
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
            assert!((addr + 8 <= self.stack_memory.len()), "stack_read_u64 OOB: addr={} len={}", addr, self.stack_memory.len());
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
            assert!((addr + 8 <= self.stack_memory.len()), "stack_write_u64 OOB: addr={} len={}", addr, self.stack_memory.len());
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
            assert!((addr + 4 <= self.stack_memory.len()), "stack_read_u32 OOB: addr={} len={}", addr, self.stack_memory.len());
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
    fn stack_read_u8(&mut self, addr: usize) -> u8 {
        #[cfg(debug_assertions)]
        {
            assert!((addr + 1 <= self.stack_memory.len()), "stack_read_u8 OOB: addr={} len={}", addr, self.stack_memory.len());
            self.stack_memory[addr]
        }
        #[cfg(not(debug_assertions))]
        {
            unsafe { ptr::read_unaligned(self.stack_memory.as_ptr().add(addr).cast::<u8>()) }
        }
    }

    #[inline(always)]
    fn stack_write_u8(&mut self, addr: usize, v: u8) {
        #[cfg(debug_assertions)]
        {
            assert!((addr + 1 <= self.stack_memory.len()), "stack_write_u8 oob: addr={} len={}", addr, self.stack_memory.len());
            let b = v.to_le_bytes();
            self.stack_memory[addr..addr + 1].copy_from_slice(&b);
        }
        #[cfg(not(debug_assertions))]
        {
            unsafe { ptr::write_unaligned(self.stack_memory.as_mut_ptr().add(addr).cast::<u8>(), v) }
        }
    }

    #[inline(always)]
    fn stack_write_u32(&mut self, addr: usize, v: u32) {
        #[cfg(debug_assertions)]
        {
            assert!((addr + 4 <= self.stack_memory.len()), "stack_write_u32 OOB: addr={} len={}", addr, self.stack_memory.len());
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
