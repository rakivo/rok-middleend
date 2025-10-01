/// A minimal SSA-based intermediate representation.
use crate::entity::EntityRef;
use crate::primary::PrimaryMap;
use crate::vm::VMCallback;
use crate::with_comment;

use std::fmt;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{Ordering, AtomicBool};

use itertools::Itertools;
use smallvec::{smallvec, SmallVec};
use rustc_hash::{FxHashSet, FxHashMap};
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};

crate::entity_ref!(Value, "Value");
crate::entity_ref!(Inst, "Inst");
crate::entity_ref!(Block, "Block");
crate::entity_ref!(StackSlot, "StackSlot");
crate::entity_ref!(IntrinsicId, "IntrinsicId");
crate::entity_ref!(FuncId, "FuncId");
crate::entity_ref!(DataId, "DataId");
crate::entity_ref!(GlobalValue, "GlobalValue");
crate::entity_ref!(ExtFuncId, "ExternalFuncId");

/// Represents a data type in the IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    U8, U16, U32, U64,
    I8, I16, I32, I64,
    F32, F64,
    Ptr
}

impl Type {
    #[must_use]
    #[inline(always)]
    pub const fn bytes(self) -> u32 {
        match self {
            Type::I8  | Type::U8 => 1,
            Type::I16 | Type::U16 => 2,
            Type::I32 | Type::U32 | Type::F32 => 4,
            Type::U64 | Type::I64 | Type::F64 | Type::Ptr => 8,
        }
    }

    #[must_use]
    #[inline(always)]
    pub const fn bits(self) -> u32 {
        self.bytes() * 8
    }

    #[must_use]
    #[inline(always)]
    pub const fn align_bytes(self) -> u32 {
        self.bytes()
    }

    #[must_use]
    #[inline(always)]
    pub const fn align_bits(self) -> u32 {
        self.align_bytes() * 8
    }
}

/// Represents a function signature.
#[derive(Debug, Clone, Default)]
pub struct Signature {
    pub params: Vec<Type>,
    pub returns: Vec<Type>,
    // for codegen and debugging purposes only
    pub is_var_arg: bool
}

/// Represents an intrinsic
#[derive(Clone)]
pub struct IntrinData {
    pub name: Box<str>,
    pub signature: Signature,
    pub vm_callback: VMCallback
}

unsafe impl Send for IntrinData {}
unsafe impl Sync for IntrinData {}

/// Represents an external function, defined outside the module.
#[derive(Debug, Clone)]
pub struct ExtFuncData {
    pub name: Box<str>,
    pub signature: Signature,
}

/// The core data flow graph, containing all instructions and values.
#[derive(Debug, Clone, Default)]
pub struct DataFlowGraph {
    pub insts: Vec<InstructionData>,
    pub values: Vec<ValueData>,
    pub inst_results: FxHashMap<Inst, SmallVec<[Value; 2]>>,
}

impl DataFlowGraph {
    pub fn make_value(&mut self, data: ValueData) -> Value {
        let id = Value::from_u32(self.values.len() as _);
        self.values.push(data);
        id
    }

    pub fn make_inst(&mut self, data: InstructionData) -> Inst {
        let id = Inst::from_u32(self.insts.len() as _);
        self.insts.push(data);
        id
    }
}

/// The control flow graph, containing all basic blocks.
#[derive(Debug, Clone, Default)]
pub struct ControlFlowGraph {
    // TODO(#11): Make .blocks in ControlFlowGraph a PrimaryMap
    pub blocks: Vec<BasicBlockData>,
    pub predecessors: FxHashMap<Block, SmallVec<[Block; 4]>>,
}

impl ControlFlowGraph {
    pub fn add_pred(&mut self, from: Block, to: Block) {
        self.predecessors.entry(to).or_default().push(from);
    }
}

/// Represents a single basic block in the CFG.
#[derive(Debug, Clone, Default)]
pub struct BasicBlockData {
    pub insts: SmallVec<[Inst; 16]>,
    pub params: SmallVec<[Value; 4]>,
    pub is_sealed: bool,
}

/// The top-level structure for a single function's IR.
#[derive(Debug, Clone, Default)]
pub struct SsaFunc {
    pub name: Box<str>,
    pub signature: Signature,
    pub dfg: DataFlowGraph,
    pub cfg: ControlFlowGraph,
    pub layout: Layout,
    pub stack_slots: Vec<StackSlotData>,
    pub metadata: FunctionMetadata,
}

impl SsaFunc {
    #[must_use]
    #[inline(always)]
    pub fn new(name: impl AsRef<str>, signature: Signature) -> Self {
        Self {
            name: name.as_ref().into(),
            signature,
            ..Default::default()
        }
    }

    #[inline(always)]
    pub fn create_stack_slot(&mut self, ty: Type, size: u32) -> StackSlot {
        let id = StackSlot::from_u32(self.stack_slots.len() as _);
        self.stack_slots.push(StackSlotData { ty, size });
        id
    }

    #[must_use]
    pub fn value_type(&self, v: Value) -> Type {
        self.dfg.values[v.index()].ty
    }

    #[inline(always)]
    #[must_use]
    pub fn is_instruction_terminator(&self, inst: Inst) -> bool {
        self.dfg.insts[inst.index()].is_terminator()
    }

    #[inline(always)]
    #[must_use]
    pub fn is_block_terminated(&self, block: Block) -> bool {
        let last_inst = self.cfg.blocks[block.index()].insts.last().copied();
        last_inst.is_some_and(|inst| self.is_instruction_terminator(inst))
    }

    #[inline]
    #[must_use]
    pub fn instruction_data(&self, inst: Inst) -> &InstructionData {
        &self.dfg.insts[inst.index()]
    }

    #[inline]
    #[must_use]
    pub fn pretty_print_inst(&self, inst: Inst) -> String {
        let mut inst_string = String::with_capacity(128);
        self.fmt_inst(&mut inst_string, inst).unwrap();
        inst_string
    }

    #[inline]
    #[must_use]
    pub fn inst_to_block(&self, inst: Inst) -> Option<Block> {
        self.layout.inst_blocks.get(&inst).copied()
    }
}

/// Maps logical entities (Inst, Block) to their container.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    pub inst_blocks: FxHashMap<Inst, Block>,
    pub block_entry: Option<Block>,
}

/// Data associated with a stack slot.
#[derive(Debug, Clone)]
pub struct StackSlotData {
    pub ty: Type,
    pub size: u32,
}

/// Metadata for the function.
#[derive(Debug, Clone, Default)]
pub struct FunctionMetadata {
    pub is_external: bool,
    pub comments: FxHashMap<Inst, Box<str>>
}

//-////////////////////////////////////////////////////////////////////
// Instructions & Values
//

#[derive(Debug, Clone)]
pub enum InstructionData {
    CallIntrin { intrinsic_id: IntrinsicId, args: SmallVec<[Value; 8]> },
    Binary { binop: BinaryOp, args: [Value; 2] },
    Icmp { code: IntCC, args: [Value; 2] },
    Unary { unop: UnaryOp, arg: Value },
    IConst { value: i64 },
    FConst { value: f64 },
    Jump { destination: Block, args: SmallVec<[Value; 4]> },
    Branch { destinations: [Block; 2], args: SmallVec<[Value; 4]>, arg: Value },
    Call { func_id: FuncId, args: SmallVec<[Value; 8]> },
    CallExt { func_id: ExtFuncId, args: SmallVec<[Value; 8]> },
    Return { args: SmallVec<[Value; 2]> },
    StackLoad { slot: StackSlot },
    StackAddr { slot: StackSlot },
    StackStore { slot: StackSlot, arg: Value },
    LoadNoOffset { ty: Type, addr: Value },
    StoreNoOffset { args: [Value; 2] },
    DataAddr { data_id: DataId },
    // GlobalValue { global_value: GlobalValue },
    Unreachable,
    Nop,
}

impl InstructionData {
    #[must_use]
    pub fn bits(&self, inst_id: Inst, context: &SsaFunc) -> u32 {
        let vbits = |v: &Value|  context.dfg.values[v.index()].ty.bits();
        let rbits = |idx: usize| {
            let r = &context.dfg.inst_results[&inst_id];
            context.dfg.values[r[idx].index()].ty.bits()
        };

        match self {
            Self::Binary { args, .. } => vbits(&args[0]),
            Self::Icmp { args, .. } => vbits(&args[0]),
            Self::Unary { arg, .. } => vbits(arg),
            Self::IConst { .. } => rbits(0),
            Self::FConst { .. } => rbits(0),
            Self::StackLoad { .. } => rbits(0),
            Self::DataAddr { .. } => rbits(0),
            Self::StackAddr { .. } => rbits(0),
            Self::StackStore { arg, .. } => vbits(arg),
            Self::LoadNoOffset { ty, .. } => ty.bits(),
            Self::StoreNoOffset { args, .. } => vbits(&args[1]),

            Self::Jump { .. } => 32,
            Self::Branch { .. } => 32,
            Self::Call { .. } => 32,
            Self::CallExt { .. } => 32,
            Self::Return { .. } => 32,

            Self::CallIntrin { .. } |
            Self::Unreachable |
            Self::Nop => 0
        }
    }

    #[must_use]
    pub fn is_terminator(&self) -> bool {
        matches!{
            self,
            Self::Jump { .. }   |
            Self::Branch { .. } |
            Self::Return { .. } |
            Self::Unreachable
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum IntCC {
    Equal,
    NotEqual,
    SignedGreaterThan,
    SignedGreaterThanOrEqual,
    SignedLessThan,
    SignedLessThanOrEqual,
    UnsignedGreaterThan,
    UnsignedGreaterThanOrEqual,
    UnsignedLessThan,
    UnsignedLessThanOrEqual,
}

#[derive(Debug, Clone, Copy)]
pub enum BinaryOp {
    IAdd, ISub, IMul, IDiv,
    And, Or, Xor, Ushr, Ishl, Band, Bor,
    FAdd, FSub, FMul, FDiv,
}

#[derive(Debug, Clone, Copy)]
pub enum UnaryOp {
    Ireduce,
    Uextend,
    Sextend,
}

#[derive(Debug, Clone, Copy)]
pub struct ValueData {
    pub ty: Type,
    pub def: ValueDef,
}

#[derive(Debug, Clone, Copy)]
pub enum ValueDef {
    Inst { inst: Inst, result_idx: u8 },
    Param { block: Block, param_idx: u8 },
    Const(i64),
}

pub type Datas = PrimaryMap<DataId, DataDescription>;
pub type Intrinsics = PrimaryMap<IntrinsicId, IntrinData>;

#[derive(Default)]
pub struct Module {
    pub funcs: PrimaryMap<FuncId, SsaFunc>,
    pub ext_funcs: PrimaryMap<ExtFuncId, ExtFuncData>,
    pub intrinsics: Intrinsics,
    pub datas: Datas,
    pub global_values: PrimaryMap<GlobalValue, GlobalValueData>,
}

#[derive(Debug)]
pub struct AtomicContents(pub RwLock<Box<[u8]>>);

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

    // Slice operations
    #[inline(always)]
    pub fn get_slice(&self, range: std::ops::Range<usize>) -> Option<Vec<u8>> {
        self.0.read().get(range).map(<[u8]>::to_vec)
    }

    // Search operations
    #[inline(always)]
    pub fn contains(&self, needle: &u8) -> bool {
        self.0.read().contains(needle)
    }

    #[inline(always)]
    pub fn starts_with(&self, needle: &[u8]) -> bool {
        self.0.read().starts_with(needle)
    }

    #[inline(always)]
    pub fn ends_with(&self, needle: &[u8]) -> bool {
        self.0.read().ends_with(needle)
    }

    #[inline(always)]
    pub fn find(&self, needle: &[u8]) -> Option<usize> {
        let guard = self.0.read();
        guard.windows(needle.len()).position(|window| window == needle)
    }

    // Iterator-style operations (return owned data)
    #[inline(always)]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.read().to_vec()
    }

    #[inline(always)]
    pub fn iter(&self) -> std::vec::IntoIter<u8> {
        self.0.read().to_vec().into_iter()
    }

    // Closure-based operations for complex access patterns
    #[inline(always)]
    pub fn with_slice<T>(&self, f: impl FnOnce(&[u8]) -> T) -> T {
        let guard = self.0.read();
        f(&guard)
    }

    #[inline(always)]
    pub fn with_slice_mut<T>(&self, f: impl FnOnce(&mut [u8]) -> T) -> T {
        let mut guard = self.0.write();
        f(&mut guard)
    }

    // Mutation operations
    #[inline(always)]
    pub fn set_contents(&self, new_contents: Box<[u8]>) {
        *self.0.write() = new_contents;
    }

    #[inline(always)]
    pub fn clear(&self) {
        *self.0.write() = Box::new([]);
    }

    // Comparison operations
    #[inline(always)]
    pub fn eq_slice(&self, other: &[u8]) -> bool {
        &**self.0.read() == other
    }

    // Convert to different formats
    #[inline(always)]
    pub fn as_hex(&self) -> String {
        use std::fmt::Write;
        let guard = self.0.read();
        guard.iter().fold(String::new(), |mut s, b| {
            write!(&mut s, "{b:02x}").unwrap();
            s
        })
    }

    // Chunking operations
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
    pub contents: AtomicContents,
    pub is_external: AtomicBool,
}

impl DataDescription {
    #[inline]
    pub fn is_external(&self) -> bool {
        self.is_external.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone)]
pub struct GlobalValueData {
    pub name: Box<str>,
    pub ty: Type,
}

impl Module {
    #[must_use]
    #[inline(always)]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline(always)]
    pub fn import_function(&mut self, data: ExtFuncData) -> ExtFuncId {
        self.ext_funcs.push(data)
    }

    #[inline(always)]
    pub fn add_intrinsic(&mut self, intrin_data: IntrinData) -> IntrinsicId {
        self.intrinsics.push(intrin_data)
    }

    #[inline]
    pub fn declare_function(&mut self, name: impl AsRef<str>, signature: Signature) -> FuncId {
        self.funcs.push(SsaFunc {
            name: name.as_ref().into(),
            signature,
            metadata: FunctionMetadata {
                is_external: true,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    #[inline]
    pub fn declare_data(&mut self, size: u32, external: bool) -> DataId {
        self.datas.push(DataDescription {
            size,
            contents: AtomicContents::new(Box::new([])),
            is_external: external.into(),
        })
    }

    #[inline] pub fn define_data(&self, id: DataId, contents: Box<[u8]>) {
        let data = &self.datas[id];
        *data.contents.write() = contents;
        data.is_external.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    #[inline(always)]
    pub fn declare_global_value(&mut self, data: GlobalValueData) -> GlobalValue {
        self.global_values.push(data)
    }

    #[inline(always)]
    pub fn define_function(&mut self, id: FuncId) {
        let func = self.get_func_mut(id);
        func.metadata.is_external = false;
    }

    #[inline(always)]
    pub fn get_func_mut(&mut self, id: FuncId) -> &mut SsaFunc {
        &mut self.funcs[id]
    }
}

//-////////////////////////////////////////////////////////////////////
// Function Builder
//

pub struct FunctionBuilder<'a> {
    pub func: &'a mut SsaFunc,
    cursor: Cursor,
}

#[derive(Debug, Clone, Copy)]
struct Cursor {
    current_block: Block,
}

impl<'a> FunctionBuilder<'a> {
    #[inline]
    pub fn new(func: &'a mut SsaFunc) -> Self {
        let entry_block = if let Some(block) = func.layout.block_entry {
            block
        } else {
            let block = Block::new(func.cfg.blocks.len());
            func.cfg.blocks.push(BasicBlockData::default());
            func.layout.block_entry = Some(block);
            block
        };
        Self { func, cursor: Cursor { current_block: entry_block } }
    }

    #[inline(always)]
    pub fn create_block(&mut self) -> Block {
        let id = Block::new(self.func.cfg.blocks.len());
        self.func.cfg.blocks.push(BasicBlockData::default());
        id
    }

    #[inline(always)]
    pub fn switch_to_block(&mut self, block: Block) {
        self.cursor.current_block = block;
    }

    #[must_use]
    #[inline(always)]
    pub fn current_block(&self) -> Block {
        self.cursor.current_block
    }

    #[inline]
    pub fn add_block_params(&mut self, types: &[Type]) -> &[Value] {
        let block = self.current_block();
        let block_data = &mut self.func.cfg.blocks[block.index()];
        let param_idx_start = block_data.params.len();
        for (i, &ty) in types.iter().enumerate() {
            let value = self.func.dfg.make_value(ValueData {
                ty,
                def: ValueDef::Param { block, param_idx: (param_idx_start + i) as u8 },
            });
            block_data.params.push(value);
        }
        &block_data.params[param_idx_start..]
    }

    // TODO(#12): Names for stack slots?
    // TODO(#10): Why do we need to take in Type in create_stack_slot
    #[inline(always)]
    pub fn create_stack_slot(&mut self, ty: Type, size: u32) -> StackSlot {
        self.func.create_stack_slot(ty, size)
    }

    #[inline(always)]
    pub fn insert_comment(
        &mut self,
        inst: Inst,
        comment: impl Into<Box<str>>
    ) {
        self.func.metadata.comments.insert(inst, comment.into());
    }

    #[inline(always)]
    pub fn ins<'short>(&'short mut self) -> InstBuilder<'short, 'a> {
        let position = self.cursor;
        InstBuilder { builder: self, position }
    }

    #[inline(always)]
    pub fn seal_block(&mut self, block: Block) {
        self.func.cfg.blocks[block.index()].is_sealed = true;
    }

    #[inline(always)]
    pub fn finalize(&mut self) {
        for i in 0..self.func.cfg.blocks.len() {
            let block = Block::new(i);
            self.seal_block(block);
        }
    }
}

pub struct InstBuilder<'short, 'long> {
    builder: &'short mut FunctionBuilder<'long>,
    position: Cursor,
}

impl<'long> Deref for InstBuilder<'_, 'long> {
    type Target = FunctionBuilder<'long>;
    fn deref(&self) -> &Self::Target { self.builder }
}

impl DerefMut for InstBuilder<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target { self.builder }
}

impl InstBuilder<'_, '_> {
    #[inline]
    fn insert_inst(&mut self, data: InstructionData) -> Inst {
        let inst = self.builder.func.dfg.make_inst(data);
        let block = self.position.current_block;
        self.builder.func.cfg.blocks[block.index()].insts.push(inst);
        self.builder.func.layout.inst_blocks.insert(inst, block);
        inst
    }

    #[inline]
    #[cfg_attr(not(debug_assertions), allow(unused))]
    fn get_last_inst(&self) -> Option<Inst> {
        let block = self.current_block();
        self.builder.func.cfg.blocks[block.index()].insts.last().copied()
    }

    #[inline]
    fn make_inst_result(&mut self, inst: Inst, ty: Type, result_idx: u8) -> Value {
        let value = self.builder.func.dfg.make_value(ValueData {
            ty,
            def: ValueDef::Inst { inst, result_idx },
        });
        self.builder.func.dfg.inst_results.entry(inst).or_default().push(value);
        value
    }

    with_comment! {
        iconst_with_comment,
        #[inline]
        pub fn iconst(&mut self, ty: Type, val: i64) -> Value {
            let inst = self.insert_inst(InstructionData::IConst { value: val });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        iadd_with_comment,
        #[inline]
        pub fn iadd(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary {
                binop: BinaryOp::IAdd, args: [lhs, rhs]
            });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        isub_with_comment,
        #[inline]
        pub fn isub(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::ISub, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        imul_with_comment,
        #[inline]
        pub fn imul(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::IMul, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        idiv_with_comment,
        #[inline]
        pub fn idiv(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::IDiv, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        unreachable_with_comment,
        #[inline]
        pub fn unreachable(&mut self) -> Value {
            let inst = self.insert_inst(InstructionData::Unreachable);
            self.make_inst_result(inst, Type::I8, 0)
        }
    }

    with_comment! {
        and_with_comment,
        #[inline]
        pub fn and(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::And, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        or_with_comment,
        #[inline]
        pub fn or(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Or, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        xor_with_comment,
        #[inline]
        pub fn xor(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Xor, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        icmp_with_comment,
        #[inline]
        pub fn icmp(&mut self, code: IntCC, lhs: Value, rhs: Value) -> Value {
            let ty = Type::I64; // Result of comparison is a boolean, but we use i64 for now
            let inst = self.insert_inst(InstructionData::Icmp { code, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    #[inline]
    pub fn iadd_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.iadd(lhs, rhs)
    }

    #[inline]
    pub fn isub_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.isub(lhs, rhs)
    }

    #[inline]
    pub fn imul_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.imul(lhs, rhs)
    }

    #[inline]
    pub fn idiv_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.idiv(lhs, rhs)
    }

    #[inline]
    pub fn and_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.and(lhs, rhs)
    }

    #[inline]
    pub fn or_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.or(lhs, rhs)
    }

    #[inline]
    pub fn xor_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.xor(lhs, rhs)
    }

    #[inline]
    pub fn icmp_imm(&mut self, code: IntCC, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.icmp(code, lhs, rhs)
    }

    with_comment! {
        ushr_with_comment,
        #[inline]
        pub fn ushr(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Ushr, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        ishl_with_comment,
        #[inline]
        pub fn ishl(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Ishl, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        band_with_comment,
        #[inline]
        pub fn band(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Band, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        bor_with_comment,
        #[inline]
        pub fn bor(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Bor, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    #[inline]
    pub fn ushr_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.ushr(lhs, rhs)
    }

    #[inline]
    pub fn ishl_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.ishl(lhs, rhs)
    }

    #[inline]
    pub fn band_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.band(lhs, rhs)
    }

    #[inline]
    pub fn bor_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.bor(lhs, rhs)
    }

    with_comment! {
        ireduce_with_comment,
        #[inline]
        pub fn ireduce(&mut self, ty: Type, arg: Value) -> Value {
            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::Ireduce, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        uextend_with_comment,
        #[inline]
        pub fn uextend(&mut self, ty: Type, arg: Value) -> Value {
            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::Uextend, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        sextend_with_comment,
        #[inline]
        pub fn sextend(&mut self, ty: Type, arg: Value) -> Value {
            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::Sextend, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fadd_with_comment,
        #[inline]
        pub fn fadd(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FAdd, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fsub_with_comment,
        #[inline]
        pub fn fsub(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FSub, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fmul_with_comment,
        #[inline]
        pub fn fmul(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FMul, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fdiv_with_comment,
        #[inline]
        pub fn fdiv(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs.index()].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FDiv, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fconst_with_comment,
        #[inline]
        pub fn fconst(&mut self, ty: Type, val: f64) -> Value {
            let inst = self.insert_inst(InstructionData::FConst { value: val });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        stack_addr_with_comment,
        #[inline]
        pub fn stack_addr(&mut self, ty: Type, slot: StackSlot) -> Value {
            let inst = self.insert_inst(InstructionData::StackAddr { slot });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        stack_load_with_comment,
        #[inline]
        pub fn stack_load(&mut self, ty: Type, slot: StackSlot) -> Value {
            let inst = self.insert_inst(InstructionData::StackLoad { slot });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        stack_store_with_comment,
        #[inline]
        pub fn stack_store(&mut self, slot: StackSlot, val: Value) {
            self.insert_inst(InstructionData::StackStore { slot, arg: val });
        }
    }

    with_comment! {
        store_with_comment,
        #[inline]
        pub fn store(&mut self, dst: Value, src: Value) {
            self.insert_inst(InstructionData::StoreNoOffset { args: [dst, src] });
        }
    }

    with_comment! {
        load_with_comment,
        #[inline]
        pub fn load(&mut self, ty: Type, addr: Value) -> Value {
            let inst = self.insert_inst(InstructionData::LoadNoOffset { ty, addr });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        data_addr_with_comment,
        #[inline]
        pub fn data_addr(&mut self, ty: Type, data_id: DataId) -> Value {
            let inst = self.insert_inst(InstructionData::DataAddr { data_id });
            self.make_inst_result(inst, ty, 0)
        }
    }

    // #[inline]
    // pub fn global_value(&mut self, ty: Type, global_value: GlobalValue) -> Value {
    //     let inst = self.insert_inst(InstructionData::GlobalValue { global_value });
    //     self.make_inst_result(inst, ty, 0)
    // }

    with_comment! {
        jump_with_comment,
        #[inline]
        pub fn jump(&mut self, dest: Block) {
            self.insert_inst(InstructionData::Jump {
                destination: dest,
                args: SmallVec::new()
            });
            let from = self.position.current_block;
            self.builder.func.cfg.add_pred(from, dest);
        }
    }

    with_comment! {
        jump_params_with_comment,
        #[inline]
        pub fn jump_params(&mut self, dest: Block, params: &[Value]) {
            self.insert_inst(InstructionData::Jump {
                destination: dest,
                args: params.into()
            });
            let from = self.position.current_block;
            self.builder.func.cfg.add_pred(from, dest);
        }
    }

    with_comment! {
        brif_params_with_comment,
        #[inline]
        pub fn brif_params(&mut self, cond: Value, true_dest: Block, false_dest: Block, args: &[Value]) {
            self.insert_inst(InstructionData::Branch {
                destinations: [true_dest, false_dest],
                arg: cond,
                args: args.into()
            });
            let from = self.position.current_block;
            self.builder.func.cfg.add_pred(from, true_dest);
            self.builder.func.cfg.add_pred(from, false_dest);
        }
    }

    with_comment! {
        brif_with_comment,
        #[inline]
        pub fn brif(&mut self, cond: Value, true_dest: Block, false_dest: Block) {
            self.insert_inst(InstructionData::Branch {
                destinations: [true_dest, false_dest],
                arg: cond,
                args: SmallVec::new()
            });
            let from = self.position.current_block;
            self.builder.func.cfg.add_pred(from, true_dest);
            self.builder.func.cfg.add_pred(from, false_dest);
        }
    }

    with_comment! {
        call_with_comment,
        #[inline]
        pub fn call(&mut self, func_id: FuncId, args: &[Value]) -> SmallVec<[Value; 2]> {
            let inst = self.insert_inst(InstructionData::Call { func_id, args: args.into() });
            let result_ty = Type::I64; // TODO(#2): Get from function signature
            let result = self.make_inst_result(inst, result_ty, 0);
            smallvec![result]
        }
    }

    with_comment! {
        call_intrin_with_comment,
        #[inline]
        pub fn call_intrin(&mut self, intrinsic_id: IntrinsicId, args: &[Value]) -> SmallVec<[Value; 2]> {
            let inst = self.insert_inst(InstructionData::CallIntrin {
                intrinsic_id, args: args.into()
            });
            let result_ty = Type::I64; // TODO(#2): Get from function signature
            let result = self.make_inst_result(inst, result_ty, 0);
            smallvec![result]
        }
    }

    with_comment! {
        call_ext_with_comment,
        #[inline]
        pub fn call_ext(&mut self, func_id: ExtFuncId, args: &[Value]) -> SmallVec<[Value; 2]> {
            let inst = self.insert_inst(InstructionData::CallExt { func_id, args: args.into() });
            let result_ty = Type::I64; // TODO(#6): Get from function signature
            let result = self.make_inst_result(inst, result_ty, 0);
            smallvec![result]
        }
    }

    with_comment! {
        call_memcpy_with_comment,
        #[inline]
        pub fn call_memcpy(
            &mut self,
            parent: &mut Module,
            dest: Value,
            src: Value,
            size: Value,
        ) {
            let libc_memcpy = parent.import_function(ExtFuncData {
                name: "memcpy".into(),
                signature: Signature {
                    params: vec![Type::Ptr, Type::Ptr, Type::I64],
                    ..Default::default()
                }
            });

            self.call_ext(libc_memcpy, &[dest, src, size]);
        }
    }

    with_comment! {
        call_memset_with_comment,
        #[inline]
        pub fn call_memset(
            &mut self,
            parent: &mut Module,
            dest: Value,
            c: Value,
            n: Value,
        ) {
            let libc_memset = parent.import_function(ExtFuncData {
                name: "memset".into(),
                signature: Signature {
                    params: vec![Type::Ptr, Type::I32, Type::I64],
                    ..Default::default()
                }
            });

            self.call_ext(libc_memset, &[dest, c, n]);
        }
    }

    with_comment! {
        call_abort_with_comment,
        #[inline]
        pub fn call_abort(&mut self, parent: &mut Module) {
            let libc_abort = parent.import_function(ExtFuncData {
                name: "abort".into(),
                signature: Signature::default()
            });

            self.call_ext(libc_abort, &[]);
        }
    }

    with_comment! {
        ret_with_comment,
        #[inline]
        pub fn ret(&mut self, vals: &[Value]) {
            let inst = self.insert_inst(InstructionData::Return {
                args: vals.into()
            });

            for (i, &val) in vals.iter().enumerate() {
                let ty = self.func.value_type(val);
                self.make_inst_result(inst, ty, i as _);
            }
        }
    }

    with_comment! {
        nop_with_comment,
        #[inline]
        pub fn nop(&mut self) {
            self.insert_inst(InstructionData::Nop);
        }
    }
}

//-////////////////////////////////////////////////////////////////////
// Analysis & Pretty Printing
//

impl SsaFunc {
    pub fn fmt_block(&self, f: &mut dyn fmt::Write, block_id: Block) -> fmt::Result {
        let block_data = &self.cfg.blocks[block_id.index()];
        write!(f, "{block_id}:")?;
        if !block_data.params.is_empty() {
            write!(f, "({})", block_data.params.iter().map(|v| self.fmt_value(*v)).collect::<Vec<_>>().join(", "))?;
        }
        if let Some(preds) = self.cfg.predecessors.get(&block_id) {
            write!(f, "  ; preds: {}", preds.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))?;
        }
        writeln!(f)?;
        for &inst_id in &block_data.insts {
            self.fmt_inst(f, inst_id)?;
            writeln!(f)?;
        }
        Ok(())
    }

    pub fn fmt_inst(&self, f: &mut dyn fmt::Write, inst_id: Inst) -> fmt::Result {
        let inst = &self.dfg.insts[inst_id.index()];

        // Print results if any
        if let Some(results) = self.dfg.inst_results.get(&inst_id)
            && !results.is_empty() {
            write!(f, "{} = ",
                results.iter()
                    .map(|r| self.fmt_value(*r))
                    .join(", ")
            )?;
        }

        match inst {
            InstructionData::Binary { binop: opcode, args } => {
                write!(f, "{:?} {}, {}", opcode, self.fmt_value(args[0]), self.fmt_value(args[1]))?;
            }
            InstructionData::Icmp { code, args } => {
                write!(f, "icmp_{:?} {}, {}", code, self.fmt_value(args[0]), self.fmt_value(args[1]))?;
            }
            InstructionData::Unary { unop, arg } => {
                write!(f, "{:?} {}", unop, self.fmt_value(*arg))?;
            }
            InstructionData::IConst { value } => write!(f, "iconst {value}")?,
            InstructionData::FConst { value } => write!(f, "fconst {value}")?,
            InstructionData::Jump { destination, args } => {
                write!(f, "jump {}({})", destination,
                    args.iter().map(|a| self.fmt_value(*a)).join(", ")
                )?;
            }
            InstructionData::Branch { destinations, arg, args } => {
                write!(f, "brif {}, {}, {}({})",
                    self.fmt_value(*arg),
                    destinations[0],
                    destinations[1],
                    args.iter().map(|a| self.fmt_value(*a)).join(", ")
                )?;
            }
            InstructionData::Call { func_id, args } => {
                write!(f, "call {} ({})", func_id,
                    args.iter().map(|a| self.fmt_value(*a)).join(", ")
                )?;
            }
            InstructionData::CallIntrin { intrinsic_id, args } => {
                write!(f, "call_intrin {} ({})", intrinsic_id,
                    args.iter().map(|a| self.fmt_value(*a)).join(", ")
                )?;
            }
            InstructionData::CallExt { func_id, args } => {
                write!(f, "call_ext {} ({})", func_id,
                    args.iter().map(|a| self.fmt_value(*a)).join(", ")
                )?;
            }
            InstructionData::Return { args } => {
                write!(f, "return {}", args.iter().map(|v| self.fmt_value(*v)).join(", "))?;
            }
            InstructionData::StackAddr { slot } => write!(f, "stack_addr {slot}")?,
            InstructionData::StackLoad { slot } => write!(f, "stack_load {slot}")?,
            InstructionData::StackStore { slot, arg } => {
                write!(f, "stack_store {}, {}", slot, self.fmt_value(*arg))?;
            }
            InstructionData::LoadNoOffset { ty, addr } => {
                write!(f, "load_no_offset {}:{:?}", self.fmt_value(*addr), ty)?;
            }
            InstructionData::StoreNoOffset { args } => {
                write!(f, "store_no_offset {}, {}", self.fmt_value(args[0]), self.fmt_value(args[1]))?;
            }
            InstructionData::DataAddr { data_id } => write!(f, "data_addr {data_id}")?,
            InstructionData::Unreachable => write!(f, "unreachable")?,
            InstructionData::Nop => write!(f, "nop")?,
        }

        // Pad to 70 chars
        write!(f, "  {:<70}", "")?;

        // Optional comment
        if let Some(comment) = self.metadata.comments.get(&inst_id) {
            write!(f, "; {comment}")?;
        }

        Ok(())
    }

    #[must_use]
    pub fn fmt_value(&self, val: Value) -> String {
        let data = &self.dfg.values[val.index()];
        format!("v{}:{:?}", val.index(), data.ty)
    }
}

impl fmt::Display for SsaFunc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "function {}({}) -> {}", self.name,
            self.signature.params.iter().map(|t| format!("{t:?}")).collect::<Vec<_>>().join(", "),
            self.signature.returns.iter().map(|t| format!("{t:?}")).collect::<Vec<_>>().join(", ")
        )?;
        for (i, slot) in self.stack_slots.iter().enumerate() {
            writeln!(f, "  stack_slot{}: {:?}, size={}", i, slot.ty, slot.size)?;
        }
        if let Some(entry) = self.layout.block_entry {
            let mut visited = FxHashSet::default();
            let mut worklist = vec![entry];
            while let Some(block_id) = worklist.pop() {
                if !visited.insert(block_id) { continue; }
                self.fmt_block(f, block_id)?;
                let block_data = &self.cfg.blocks[block_id.index()];
                if let Some(last_inst_id) = block_data.insts.last() {
                    let inst_data = &self.dfg.insts[last_inst_id.index()];
                    match inst_data {
                        InstructionData::Jump { destination, .. } => worklist.push(*destination),
                        InstructionData::Branch { destinations, .. } => {
                            worklist.push(destinations[1]);
                            worklist.push(destinations[0]);
                        },
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}
