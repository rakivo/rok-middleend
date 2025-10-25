#![cfg_attr(not(debug_assertions), allow(unused_imports))]

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
    #[must_use]
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

pub struct HookDataView<'a> {
    pub name: &'a str,
    pub signature: &'a Signature,
    pub vm_callback: VmCallback
}

pub type VmCallback = Arc<dyn Fn(
    &mut VirtualMachine,
    &[u64],
    u32
)>;

/// VM execution errors
#[derive(Debug, Clone)]
pub enum VmError {
    FFIError,
    EmptyCallStack,
    RegisterOverflow,
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

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmError::FFIError => write!(f, "FFIError"),
            VmError::RegisterOverflow => write!(f, "RegisterOverflow"),
            VmError::EmptyCallStack => write!(f, "Empty call stack"),
            VmError::InvalidOpcode(op) => write!(f, "Invalid opcode: {op}"),
            VmError::InvalidDataId(id) => write!(f, "Invalid data ID: {id}"),
            VmError::InvalidFuncId(id) => write!(f, "Invalid function ID: {id}"),
            VmError::InvalidExtFuncId(id) => write!(f, "Invalid ext function ID: {id}"),
            VmError::InvalidHookId(id) => write!(f, "Invalid hook ID: {id}"),
            VmError::StackOverflow => write!(f, "Stack overflow"),
            VmError::StackUnderflow => write!(f, "Stack underflow"),
            VmError::DivisionByZero => write!(f, "Division by zero"),
            VmError::InvalidMemoryAccess(addr) => write!(f, "Invalid memory access at 0x{addr:x}"),
            VmError::UnalignedAccess(addr) => write!(f, "Unaligned memory access at 0x{addr:x}"),
            VmError::InvalidInstruction(msg) => write!(f, "Invalid instruction: {msg}"),
            VmError::ExecutionHalted => write!(f, "Execution halted"),
            VmError::InterpreterPanic(msg) => write!(f, "Execution panicked: {msg}"),
        }
    }
}

impl std::error::Error for VmError {}

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

    #[inline]
    fn read_args(&mut self) -> (u8, SmallVec<[u32; 8]>) {
        let count = self.read_u8();
        let mut args = SmallVec::with_capacity(count as usize);
        for _ in 0..count {
            args.push(self.read_u32());
        }
        (count, args)
    }

    #[inline]
    fn read_parallel_moves(&mut self) -> (u8, SmallVec<[(u32, u32); 8]>) {
        let count = self.read_u8();
        let mut args = SmallVec::with_capacity(count as usize);
        for _ in 0..count {
            args.push((self.read_u32(), self.read_u32()));
        }
        (count, args)
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

// @Hack: I just don't wanna move Consteval map to a shared module rn..
pub trait FuncDispatcher {
    fn get_bytecode_chunk(&self, packed: u64) -> Arc<BytecodeChunk>;
    fn get_ext_func_data(&self, packed: u64) -> Arc<VmExtFunc>;
}

#[derive(Copy, Clone, Debug)]
pub struct StackFrame {
    pub packed: u64,

    pub ret_pc: u32,
    pub fp: u32,

    pub sp: u32,
    pub regs_base: u32,

    pub regs_used: u32,
    pub ret_reg: u32
}

impl StackFrame {
    pub fn new(ret_reg: u32, packed: u64, ret_pc: u32, fp: u32, sp: u32, regs_base: u32, regs_count: u32) -> Self {
        Self { ret_reg, packed, ret_pc, fp, sp, regs_base, regs_used: regs_count }
    }
}

#[derive(Clone)]
pub struct VmExtFunc {
    pub signature: Signature,
    pub addr: *const (),
    pub name: Box<str>
}

unsafe impl Send for VmExtFunc {}
unsafe impl Sync for VmExtFunc {}

pub type VmHooks<'a> = PrimaryMap<HookId, HookDataView<'a>>;
pub type VmExtFuncMap = FxHashMap<ExtFuncId, VmExtFunc>;

pub struct VirtualMachine<'a> {
    module_id: u32,

    call_stack: Vec<StackFrame>,
    pc: u32,

    stack_memory: Box<[u8]>,
    stack_top: u32,

    hooks: VmHooks<'a>,

    // @Performance: i dont like this
    dispatcher: &'a dyn FuncDispatcher,

    data_memory: Vec<u8>,
    data_offsets: FxHashMap<DataId, u32>,

    // register file: a contiguous, growable register area
    registers: Vec<u64>,
    reg_top: u32, // next free register index in `registers`

    halted: bool,
}

macro_rules! def_op_binary {
    ($self:expr, $decoder:expr, $op:ident) => {
        let dst = $decoder.read_u32();
        let src1 = $decoder.read_u32();
        let src2 = $decoder.read_u32();
        let val1 = $self.reg_read(src1 as _);
        let val2 = $self.reg_read(src2 as _);
        $self.reg_write(dst as _, val1.$op(val2 as _) as _);
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
    /// Ensure the register file has at least `min_len` entries.
    fn ensure_register_capacity(&mut self, min_len: u32) {
        let min_len = min_len as usize;
        if self.registers.len() < min_len {
            // growth strategy: double or grow to needed
            let mut new_cap = std::cmp::max(self.registers.len() * 2, 1);
            while new_cap < min_len { new_cap *= 2; }
            self.registers.resize(new_cap, 0);
        }
    }

    fn current_frame_mut(&mut self) -> &mut StackFrame {
        self.call_stack.last_mut().expect("current_frame called with empty call_stack")
    }
}

impl<'a> VirtualMachine<'a> {
    pub const STACK_SIZE: usize = 1024 * 1024;
    pub const REGS_COUNT_PREALLOCATION: usize = 256;

    #[inline]
    #[must_use]
    pub fn new(module_id: u32, dispatcher: &'a dyn FuncDispatcher) -> Self {
        let mut stack_memory = Vec::with_capacity(Self::STACK_SIZE);
        #[allow(clippy::uninit_vec)]
        unsafe {
            stack_memory.set_len(Self::STACK_SIZE);
        }
        let stack_memory = stack_memory.into_boxed_slice();

        VirtualMachine {
            module_id,
            dispatcher,
            hooks: PrimaryMap::new(),
            data_memory: Vec::new(),
            data_offsets: FxHashMap::default(),
            call_stack: Vec::with_capacity(32),
            reg_top: 0,
            pc: 0,
            stack_memory,
            stack_top: 0,
            registers: Vec::with_capacity(Self::REGS_COUNT_PREALLOCATION),
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
        self.registers.clear();
        self.reg_top = 0;
        self.halted = false;
    }

    #[inline(always)]
    pub fn load_hooks(&mut self, hooks: &'a Hooks) {
        self.hooks = VmHooks::from_iter(hooks.values().map(|hook_data| {
             HookDataView {
                name: &hook_data.name,
                signature: &hook_data.signature,
                vm_callback: Arc::clone(&hook_data.vm_callback)
            }
        }));
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
                    self.data_memory[curr..curr + contents.len()].copy_from_slice(contents);
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

    #[inline]
    pub fn call_function(&mut self, func_id: FuncId, args: &[u64]) -> Result<SmallVec<[u64; 8]>, VmError> {
        Self::try_run(|| self.call_function_(func_id, args))
    }

    fn call_function_(&mut self, func_id: FuncId, args: &[u64]) -> Result<SmallVec<[u64; 8]>, VmError> {
        // Set up initial frame
        // @Hack: We just assume that if you call a function -> it's local to a VM
        let packed = ((self.module_id as u64) << 32) | (func_id.as_u32() as u64);
        let chunk = self.get_chunk(packed);

        unsafe {
            // Clear return registers for new function call
            ptr::write_bytes(self.registers.as_mut_ptr(), 0, 8);

            // Set up arguments in registers
            let dst = self.registers.as_mut_ptr();
            for (i, &arg) in args.iter().enumerate().take(8) {
                ptr::write(dst.add(i), arg);
            }
        }

        let frame_size = chunk.frame_info.total_size;
        let new_fp = self.stack_top;
        let new_sp = self.stack_top + frame_size;

        #[cfg(debug_assertions)]
        if new_sp as usize >= self.stack_memory.len() {
            return Err(VmError::StackOverflow);
        }

        // @Incomplete: we assume regs_base is 0
        let frame = StackFrame::new(0, packed, 0, new_fp, new_sp, 0, chunk.frame_info.regs_used as _);
        self.call_stack.push(frame);
        self.stack_top = new_sp;
        self.pc = 0;
        self.halted = false;

        debug_assert_eq!(self.reg_top, 0);
        self.ensure_register_capacity(chunk.frame_info.regs_used);
        self.execute()?;

        let n = self.registers.len().min(8);
        let result = self.registers[..n].into();
        Ok(result)
    }

    #[inline(always)]
    pub fn execute(&mut self) -> Result<(), VmError> {
        Self::try_run(|| self.execute_())
    }

    fn execute_(&mut self) -> Result<(), VmError> {
        while !self.halted && !self.call_stack.is_empty() {
            let packed = self.current_frame().packed;
            let chunk = &self.get_chunk(packed);
            let mut decoder = InstructionDecoder::new(&chunk.code);
            decoder.set_pos(self.pc as _, chunk.code.as_ptr());

            let opcode_byte = decoder.read_u8();
            let opcode: Opcode = unsafe {
                mem::transmute(opcode_byte)
            };

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

                Opcode::IDiv => {
                    def_op_binary!(self, decoder, wrapping_div);
                }

                Opcode::Ishl => {
                    def_op_binary!(self, decoder, wrapping_shl);
                }

                Opcode::Ireduce => {
                    let dst = decoder.read_u32();
                    let src = decoder.read_u32();
                    let bits = decoder.read_u8();
                    let val = self.reg_read(src as _);
                    let mask = (1u64 << bits) - 1;
                    self.reg_write(dst as _, val & mask);
                }

                Opcode::Uextend => {
                    let dst = decoder.read_u32();
                    let src = decoder.read_u32();
                    let _from_bits = decoder.read_u8();
                    let _to_bits = decoder.read_u8();
                    let val = self.reg_read(src as _);
                    self.reg_write(dst as _, val);
                }

                Opcode::Bitcast => {
                    let dst = decoder.read_u32();
                    let src = decoder.read_u32();
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
                    let dst = decoder.read_u32();
                    let src1 = decoder.read_u32();
                    let src2 = decoder.read_u32();
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
                    let (_, moves) = decoder.read_parallel_moves();

                    for (dst, src) in moves {
                        self.reg_write(dst as _, self.reg_read(src as _));
                    }

                    let new_pc = decoder.get_pos(chunk.code.as_ptr()) as i32 + offset;
                    self.pc = new_pc as _;
                    continue;
                }

                Opcode::BranchIf16 => {
                    let cond_reg = decoder.read_u32();
                    let offset = i32::from(decoder.read_u16() as i16);
                    let (_, moves) = decoder.read_parallel_moves();

                    let cond = self.reg_read(cond_reg);
                    if cond != 0 {
                        for (dst, src) in moves {
                            self.reg_write(dst as _, self.reg_read(src as _));
                        }

                        let new_pc = decoder.get_pos(chunk.code.as_ptr()) as i32 + offset;
                        self.pc = new_pc as _;
                        continue;
                    }
                    // If false, fall through to the next Jump16 which has its own args
                }

                Opcode::Return => {
                    if self.call_stack.is_empty() {
                        return Err(VmError::EmptyCallStack);
                    }
                    let (_, ret_args) = decoder.read_args();

                    // Save return values (up to 8)
                    let return_value = ret_args.first().map(|&reg| {
                        self.reg_read(reg)
                    });

                    // Pop the callee frame
                    let old_frame = unsafe { self.call_stack.pop().unwrap_unchecked() };

                    let ret_reg = if old_frame.ret_reg == u32::MAX {
                        None
                    } else {
                        Some(old_frame.ret_reg)
                    };

                    // Free the callee's register window
                    self.reg_top = old_frame.regs_base;

                    if let (Some(ret_reg), Some(return_value)) = (ret_reg, return_value) {
                        if self.call_stack.is_empty() {
                            self.reg_write_nobase(ret_reg, return_value);
                        } else {
                            self.reg_write(ret_reg, return_value);
                        }
                    }

                    if self.call_stack.is_empty() {
                        self.halted = true;
                        continue;
                    }

                    // Restore caller's execution context
                    let caller_frame = *self.current_frame();
                    self.stack_top = caller_frame.sp;
                    self.pc = old_frame.ret_pc;
                    continue;
                }

                Opcode::Call => {
                    let ret = decoder.read_u32();
                    let packed = decoder.read_u64();
                    let (_, args) = decoder.read_args();

                    // Get callee chunk and its register requirement
                    let new_chunk = self.get_chunk(packed);
                    let callee_regs = new_chunk.frame_info.regs_used;
                    let frame_size = new_chunk.frame_info.total_size;

                    // Allocate registers for callee
                    let regs_base = self.reg_top;
                    let regs_needed_top = regs_base.checked_add(callee_regs).ok_or(VmError::RegisterOverflow)?;
                    self.ensure_register_capacity(regs_needed_top);

                    let mut values = SmallVec::<[_; 8]>::new();

                    // Move arguments from caller's registers to callee's r0-r7
                    for &arg_reg in args.iter().take(8) {
                        let value = self.reg_read(arg_reg);
                        values.push(value);
                    }

                    self.reg_top = regs_needed_top;

                    // Compute frame fp/sp for stack-local area
                    let save_size = 0;
                    let new_fp = self.stack_top + save_size;
                    let new_sp = new_fp + frame_size;

                    #[cfg(debug_assertions)]
                    if new_sp as usize >= self.stack_memory.len() {
                        return Err(VmError::StackOverflow);
                    }

                    let ret_pc = decoder.get_pos(chunk.code.as_ptr()) as _;

                    let new_frame = StackFrame::new(
                        ret,
                        packed,
                        ret_pc,
                        new_fp,
                        new_sp,
                        regs_base,
                        callee_regs,
                    );

                    self.call_stack.push(new_frame);
                    self.stack_top = new_sp;
                    self.pc = 0;

                    // Move arguments from caller's registers to callee's r0-r7
                    for (i, _) in args.iter().take(8).enumerate() {
                        let value = values[i];
                        self.reg_write(i as u32, value);
                    }

                    continue;
                }

                Opcode::CallHook => {
                    let ret = decoder.read_u32();
                    let hook_id = HookId::from_u32(decoder.read_u32());
                    let (_, args) = decoder.read_args();

                    #[cfg(debug_assertions)]
                    if hook_id.index() >= self.hooks.len() {
                        return Err(VmError::InvalidHookId(hook_id));
                    }

                    let mut hook_args = SmallVec::<[_; 8]>::new();

                    // Move arguments to r0-r7
                    for &arg_reg in args.iter().take(8) {
                        let value = self.reg_read(arg_reg);
                        hook_args.push(value);
                    }

                    let callback = unsafe { util::reborrow(&self.hooks[hook_id].vm_callback) };
                    (callback)(self, &hook_args, ret);
                }

                Opcode::CallExt => {
                    use libffi::middle::{Cif, Arg, Type as FFIType};

                    #[inline]
                    fn ty_to_ffi(ty: Type) -> FFIType {
                        match ty {
                            Type::Ptr => FFIType::pointer(),
                            Type::I8  => FFIType::i8(),
                            Type::U8  => FFIType::u8(),
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

                    let ret = decoder.read_u32();
                    let packed = decoder.read_u64();
                    let (arg_count, args) = decoder.read_args();

                    let ext_func = &*self.dispatcher.get_ext_func_data(packed);
                    let addr: *const () = ext_func.addr;
                    let signature = &ext_func.signature;

                    let mut arg_values = Vec::with_capacity(arg_count as usize);
                    for i in 0..arg_count as usize {
                        arg_values.push(self.reg_read(args[i]));
                    }

                    let ffi_args = arg_values.iter().map(Arg::new).collect::<Vec<_>>();

                    let arg_types = signature.params.iter()
                        .take(arg_count as usize)
                        .copied()
                        .map(ty_to_ffi)
                        .collect::<Vec<_>>();

                    let return_type = signature.returns.first()
                        .copied()
                        .map_or(FFIType::void(), ty_to_ffi);

                    let result = if signature.is_var_arg.is_some() {
                        let nfixedargs = signature.is_var_arg.unwrap() as usize;
                        let cif = Cif::new_variadic(
                            arg_types,
                            nfixedargs,
                            return_type
                        );
                        unsafe { cif.call(std::mem::transmute(addr), &ffi_args) }
                    } else {
                        let cif = Cif::new(arg_types, return_type);
                        unsafe { cif.call(std::mem::transmute(addr), &ffi_args) }
                    };

                    if ret != u32::MAX {
                        self.reg_write(ret, result);
                    }
                }

                Opcode::LoadDataAddr => {
                    let dst = decoder.read_u32() as _;
                    let data_id = DataId::from_u32(decoder.read_u32());

                    if let Some(&offset) = self.data_offsets.get(&data_id) {
                        let data_ptr = self.data_memory.as_ptr() as u64 + u64::from(offset);
                        self.reg_write(dst, data_ptr as _);
                    } else {
                        return Err(VmError::InvalidDataId(data_id));
                    }
                }

                Opcode::Mov => {
                    let dst = decoder.read_u32();
                    let src = decoder.read_u32();
                    self.reg_write(dst as _, self.reg_read(src as _));
                }

                Opcode::Load8 => {
                    let dst_reg = decoder.read_u32();
                    let addr_reg = decoder.read_u32();
                    let addr = self.reg_read(addr_reg as _) as *const u8;
                    let val = unsafe { ptr::read(addr) };
                    self.reg_write(dst_reg as _, u64::from(val));
                }

                Opcode::Load16 => {
                    let dst_reg = decoder.read_u32();
                    let addr_reg = decoder.read_u32();
                    let addr = self.reg_read(addr_reg as _) as *const u16;
                    let val = unsafe { ptr::read(addr) };
                    self.reg_write(dst_reg as _, u64::from(val));
                }

                Opcode::Load32 => {
                    let dst_reg = decoder.read_u32();
                    let addr_reg = decoder.read_u32();
                    let addr = self.reg_read(addr_reg as _) as *const u32;
                    let val = unsafe { ptr::read(addr) };
                    self.reg_write(dst_reg as _, u64::from(val));
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
                    *self.sp_mut() += frame_size;
                    if self.sp() as usize >= self.stack_memory.len() {
                        return Err(VmError::StackOverflow);
                    }
                }

                Opcode::FrameTeardown => {
                    *self.sp_mut() = self.fp();
                }

                Opcode::SpAdd => {
                    let offset = decoder.read_i32();
                    *self.sp_mut() = (self.sp() as i32 + offset) as _;
                }

                Opcode::SpSub => {
                    let offset = decoder.read_i32();
                    *self.sp_mut() = (self.sp() as i32 - offset) as _;
                }

                Opcode::FpLoad8 => {
                    let reg = decoder.read_u32() as _;
                    let offset = decoder.read_i32();
                    let addr = (self.fp() as i32 + offset) as usize;
                    let v = self.stack_read_u8(addr);
                    self.reg_write(reg, v as u64);
                }

                Opcode::FpLoad32 => {
                    let reg = decoder.read_u32() as _;
                    let offset = decoder.read_i32();
                    let addr = (self.fp() as i32 + offset) as usize;
                    let v = self.stack_read_u32(addr);
                    self.reg_write(reg, v as u64);
                }

                Opcode::FpLoad64 => {
                    let reg = decoder.read_u32() as _;
                    let offset = decoder.read_i32();
                    let addr = (self.fp() as i32 + offset) as usize;
                    let v = self.stack_read_u64(addr);
                    self.reg_write(reg, v);
                }

                Opcode::FpStore8 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32() as _;
                    let addr = (self.fp() as i32 + offset) as usize;
                    let v = self.reg_read(reg);
                    self.stack_write_u8(addr, v as u8);
                }

                Opcode::FpStore32 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32() as _;
                    let addr = (self.fp() as i32 + offset) as usize;
                    let v = self.reg_read(reg);
                    self.stack_write_u32(addr, v as u32);
                }

                Opcode::FpStore64 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32() as _;
                    let addr = (self.fp() as i32 + offset) as usize;
                    let v = self.reg_read(reg);
                    self.stack_write_u64(addr, v);
                }

                Opcode::SpLoad32 => {
                    let reg = decoder.read_u32() as _;
                    let offset = decoder.read_i32();
                    let addr = (self.sp() as i32 + offset) as usize;
                    let v = self.stack_read_u32(addr);
                    self.reg_write(reg, v as u64);
                }

                Opcode::SpLoad64 => {
                    let reg = decoder.read_u32() as _;
                    let offset = decoder.read_i32();
                    let addr = (self.sp() as i32 + offset) as usize;
                    let v = self.stack_read_u64(addr);
                    self.reg_write(reg, v);
                }

                Opcode::SpStore32 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32() as _;
                    let addr = (self.sp() as i32 + offset) as usize;
                    let v = self.reg_read(reg);
                    self.stack_write_u32(addr, v as u32);
                }

                Opcode::SpStore64 => {
                    let offset = decoder.read_i32();
                    let reg = decoder.read_u32() as _;
                    let addr = (self.sp() as i32 + offset) as usize;
                    let v = self.reg_read(reg);
                    self.stack_write_u64(addr, v);
                }

                Opcode::FpAddr => {
                    let reg = decoder.read_u32() as _;
                    let offset = decoder.read_i32();
                    let addr = (self.fp() as i32 + offset) as usize;
                    let addr = unsafe { self.stack_memory.as_ptr().add(addr) as u64 };
                    self.reg_write(reg, addr);
                }

                Opcode::SpAddr => {
                    let reg = decoder.read_u32() as _;
                    let offset = decoder.read_i32();
                    let addr = (self.sp() as i32 + offset) as u64;
                    self.reg_write(reg, addr);
                }

                Opcode::Halt => {
                    self.halted = true;
                    break;
                }

                // @Incomplete: Implement all ops handling and remove this `_` case
                other => {
                    println!("{other:#?}");
                    return Err(VmError::InvalidOpcode(opcode_byte));
                }
            }

            let chunk = self.get_chunk(packed);
            self.pc = decoder.get_pos(chunk.code.as_ptr()) as _;
        }

        Ok(())
    }
}

impl VirtualMachine<'_> {
    fn try_run<T>(f: impl FnOnce() -> Result<T, VmError>) -> Result<T, VmError> {
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
                Err(VmError::InterpreterPanic(panic_msg))
            }
        }
    }

    #[inline(always)]
    pub fn reg_read(&self, vreg: u32) -> u64 {
        let frame = self.current_frame();
        let idx = frame.regs_base + vreg;
        self.registers[idx as usize]
    }

    #[inline(always)]
    pub fn reg_write(&mut self, vreg: u32, val: u64) {
        let frame = self.current_frame();
        let idx = frame.regs_base + vreg;
        self.registers[idx as usize] = val;
    }

    #[inline(always)]
    pub fn reg_write_nobase(&mut self, vreg: u32, val: u64) {
        self.registers[vreg as usize] = val;
    }

    #[inline(always)]
    fn fp(&self) -> u32 {
        self.current_frame().fp
    }

    #[inline(always)]
    fn sp(&self) -> u32 {
        self.current_frame().sp
    }

    #[inline(always)]
    fn sp_mut(&mut self) -> &mut u32 {
        &mut self.current_frame_mut().sp
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
            assert!((addr < self.stack_memory.len()), "stack_read_u8 OOB: addr={} len={}", addr, self.stack_memory.len());
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
            assert!((addr < self.stack_memory.len()), "stack_write_u8 oob: addr={} len={}", addr, self.stack_memory.len());
            let b = v.to_le_bytes();
            self.stack_memory[addr..=addr].copy_from_slice(&b);
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
    fn get_chunk(&self, packed: u64) -> Arc<BytecodeChunk> {
        self.dispatcher.get_bytecode_chunk(packed)
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
