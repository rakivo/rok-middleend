/// A minimal SSA-based intermediate representation.
use crate::with_comment;

use rok_entity::{EntityRef, PrimaryMap};

use std::fmt;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};

use smallvec::SmallVec;
use rustc_hash::{FxHashSet, FxHashMap};

rok_entity::entity_ref!(Value, "Value");
rok_entity::entity_ref!(Inst, "Inst");
rok_entity::entity_ref!(Block, "Block");
rok_entity::entity_ref!(StackSlot, "StackSlot");
rok_entity::entity_ref!(HookId, "HookId");
rok_entity::entity_ref!(FuncId, "FuncId");
rok_entity::entity_ref!(DataId, "DataId");
rok_entity::entity_ref!(GlobalValue, "GlobalValue");
rok_entity::entity_ref!(ExtFuncId, "ExternalFuncId");

impl nohash_hasher::IsEnabled for HookId {}
impl nohash_hasher::IsEnabled for DataId {}
impl nohash_hasher::IsEnabled for FuncId {}
impl nohash_hasher::IsEnabled for ExtFuncId {}

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

    #[must_use]
    #[inline(always)]
    pub const fn to_int_type(self) -> Self {
        match self {
            Self::F32 => Self::I32,

            Self::Ptr |
            Self::F64 => Self::I64,

            other => other
        }
    }
}

/// Represents a function signature.
#[derive(Debug, Clone, Default)]
pub struct Signature {
    pub params: Vec<Type>,
    pub returns: Vec<Type>,
    // for codegen and debugging purposes only
    /// The amount of fixed arguments in a var-args def
    pub is_var_arg: Option<u8>
}

impl Signature {
    #[inline]
    #[must_use]
    pub fn is_var_arg(&self) -> bool {
        self.is_var_arg.is_some()
    }
}


/// Represents an external function, defined outside the module.
#[derive(Debug, Clone)]
pub struct ExtFunc {
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
    #[inline]
    pub fn make_value(&mut self, data: ValueData) -> Value {
        let id = Value::from_u32(self.values.len() as _);
        self.values.push(data);
        id
    }

    #[inline]
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
    pub fn create_stack_slot(&mut self, ty: Type, size: u32, align: u16) -> StackSlot {
        let id = StackSlot::from_u32(self.stack_slots.len() as _);
        self.stack_slots.push(StackSlotData { ty, size, align });
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
    pub fn inst_results(&self, inst: Inst) -> &[Value] {
        if let Some(rs) = self.dfg.inst_results.get(&inst) {
            rs
        } else {
            &[]
        }
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

    #[inline]
    #[must_use]
    pub fn all_blocks_sealed(&self) -> bool {
        self.cfg.blocks.iter().all(|b| b.is_sealed)
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
    pub align: u16
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
    CallHook { hook_id: HookId, args: SmallVec<[Value; 8]> },
    Binary { binop: BinaryOp, args: [Value; 2] },
    Icmp { code: IntCC, args: [Value; 2] },
    Unary { unop: UnaryOp, arg: Value },
    IConst { value: i64 },
    FConst { value: f64 },
    Jump { destination: Block, args: SmallVec<[Value; 4]> },
    Branch { destinations: [Block; 2], args: SmallVec<[Value; 4]>, arg: Value },
    // @Hack:
    // @Performance:
    // TODO: Pack big SmallVec's into an EntityList
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

            Self::CallHook { .. } |
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

    Bitcast,

    FPromote,
    FDemote,
    FNeg,

    FloatToSInt,
    FloatToUInt,
    SIntToFloat,
    UIntToFloat
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
}

pub struct Module {
    pub funcs: PrimaryMap<FuncId, SsaFunc>,
    pub ext_funcs: PrimaryMap<ExtFuncId, ExtFunc>,
    pub global_values: PrimaryMap<GlobalValue, GlobalValueData>,
}

impl Default for Module {
    fn default() -> Self {
        Self {
            funcs: PrimaryMap::with_capacity(32),
            ext_funcs: PrimaryMap::with_capacity(32),
            global_values: PrimaryMap::with_capacity(32),
        }
    }
}

impl Module {
    #[must_use]
    #[inline(always)]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline(always)]
    pub fn import_function(&mut self, data: ExtFunc) -> ExtFuncId {
        self.ext_funcs.push(data)
    }

    #[inline]
    pub fn declare_function(
        &mut self,
        name: impl AsRef<str>,
        signature: Signature,
    ) -> FuncId {
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

    with_comment! {
        ir_builder,
        call_hook_with_comment,
        #[inline]
        pub fn call_hook(
            &self,
            hook_id: HookId,
            result_tys: &[Type],
            args: &[Value],
            ir_builder: &mut InstBuilder<'_, '_>
        ) -> Inst {
            ir_builder.ins().call_hook(result_tys, hook_id, args)
        }
    }

    with_comment! {
        ir_builder,
        call_ext_with_comment,
        #[inline]
        pub fn call_ext(
            &self,
            ext_func_id: ExtFuncId,
            args: &[Value],
            ir_builder: &mut InstBuilder<'_, '_>
        ) -> Inst {
            let func = &self.ext_funcs[ext_func_id];
            let result_ty = &func.signature.returns;
            ir_builder.ins().call_ext(result_ty, ext_func_id, args)
        }
    }

    with_comment! {
        ir_builder,
        call_with_comment,
        #[inline]
        pub fn call(
            &self,
            func_id: FuncId,
            args: &[Value],
            ir_builder: &mut InstBuilder<'_, '_>
        ) -> Inst {
            let func = &self.funcs[func_id];
            let result_tys = &func.signature.returns;
            ir_builder.ins().call(result_tys, func_id, args)
        }
    }

    with_comment! {
        ir_builder,
        call_memcpy_with_comment,
        #[inline]
        pub fn call_memcpy(
            &mut self,
            dest: Value,
            src: Value,
            size: Value,
            ir_builder: &mut InstBuilder<'_, '_>
        ) {
            let libc_memcpy = self.import_function(ExtFunc {
                name: "memcpy".into(),
                signature: Signature {
                    params: vec![Type::Ptr, Type::Ptr, Type::I64],
                    ..Default::default()
                },
            });

            ir_builder.call_ext(&[Type::Ptr], libc_memcpy, &[dest, src, size]);
        }
    }

    with_comment! {
        ir_builder,
        call_memset_with_comment,
        #[inline]
        pub fn call_memset(
            &mut self,
            dest: Value,
            c: Value,
            n: Value,
            ir_builder: &mut InstBuilder<'_, '_>
        ) {
            let libc_memset = self.import_function(ExtFunc {
                name: "memset".into(),
                signature: Signature {
                    params: vec![Type::Ptr, Type::I32, Type::I64],
                    ..Default::default()
                }
            });

            ir_builder.call_ext(&[Type::Ptr], libc_memset, &[dest, c, n]);
        }
    }

    with_comment! {
        ir_builder,
        call_abort_with_comment,
        #[inline]
        pub fn call_abort(&mut self, ir_builder: &mut InstBuilder<'_, '_>) {
            let libc_abort = self.import_function(ExtFunc {
                name: "abort".into(),
                signature: Signature::default()
            });

            ir_builder.call_ext(&[], libc_abort, &[]);
        }
    }
}

#[derive(Debug, Clone)]
pub struct GlobalValueData {
    pub name: Box<str>,
    pub ty: Type,
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
    pub fn create_stack_slot(&mut self, ty: Type, size: u32, align: u16) -> StackSlot {
        self.func.create_stack_slot(ty, size, align)
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
    #[must_use]
    pub fn get_last_inst(&self) -> Option<Inst> {
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
        fpromote_with_comment,
        #[inline]
        pub fn fpromote(&mut self, ty: Type, arg: Value) -> Value {
            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::FPromote, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fdemote_with_comment,
        #[inline]
        pub fn fdemote(&mut self, ty: Type, arg: Value) -> Value {
            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::FDemote, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        float_to_sint_with_comment,
        #[inline]
        pub fn float_to_sint(&mut self, ty: Type, arg: Value) -> Value {
            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::FloatToSInt, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        float_to_uint_with_comment,
        #[inline]
        pub fn float_to_uint(&mut self, ty: Type, arg: Value) -> Value {
            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::FloatToUInt, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        sint_to_float_with_comment,
        #[inline]
        pub fn sint_to_float(&mut self, ty: Type, arg: Value) -> Value {
            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::SIntToFloat, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        uint_to_float_with_comment,
        #[inline]
        pub fn uint_to_float(&mut self, ty: Type, arg: Value) -> Value {
            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::UIntToFloat, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fneg_with_comment,
        #[inline]
        pub fn fneg(&mut self, arg: Value) -> Value {
            let ty = self.builder.func.dfg.values[arg.index()].ty;
            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::FNeg, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        bitcast_with_comment,
        #[inline]
        #[track_caller]
        pub fn bitcast(&mut self, ty: Type, arg: Value) -> Value {
            debug_assert_eq!{
                self.func.value_type(arg).bits(),
                ty.bits(),
                "bitcasting value to a type with a different size"
            };
            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::Bitcast, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        ptrtoint_with_comment,
        #[inline]
        #[track_caller]
        pub fn ptrtoint(&mut self, ty: Type, arg: Value) -> Value {
            let val = self.bitcast(Type::I64, arg);

            if ty.bits() < Type::I64.bits() {
                self.ireduce(ty, val)
            } else {
                val
            }
        }
    }

    with_comment! {
        inttoptr_with_comment,
        #[inline]
        #[track_caller]
        pub fn inttoptr(&mut self, ty: Type, arg: Value) -> Value {
            let arg_ty = self.func.value_type(arg);

            let val = if arg_ty.bits() < Type::I64.bits() {
                self.uextend(Type::I64, arg)
            } else {
                arg
            };

            self.bitcast(ty, val)
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
        pub fn call(
            &mut self,
            result_tys: &[Type],
            func_id: FuncId,
            args: &[Value],
        ) -> Inst {
            let inst = self.insert_inst(InstructionData::Call {
                func_id,
                args: args.into(),
            });
            for (i, ty) in result_tys.iter().enumerate() {
                self.make_inst_result(inst, *ty, i as _);
            }
            inst
        }
    }

    with_comment! {
        call_hook_with_comment,
        #[inline]
        pub fn call_hook(
            &mut self,
            result_tys: &[Type],
            hook_id: HookId,
            args: &[Value]
        ) -> Inst {
            let inst = self.insert_inst(InstructionData::CallHook {
                hook_id,
                args: args.into()
            });
            for (i, ty) in result_tys.iter().enumerate() {
                self.make_inst_result(inst, *ty, i as _);
            }
            inst
        }
    }

    with_comment! {
        call_ext_with_comment,
        #[inline]
        pub fn call_ext(
            &mut self,
            result_tys: &[Type],
            func_id: ExtFuncId,
            args: &[Value],
        ) -> Inst {
            let inst = self.insert_inst(InstructionData::CallExt {
                func_id,
                args: args.into(),
            });
            for (i, ty) in result_tys.iter().enumerate() {
                self.make_inst_result(inst, *ty, i as _);
            }
            inst
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
        ) -> Value {
            let libc_memcpy = parent.import_function(ExtFunc {
                name: "memcpy".into(),
                signature: Signature {
                    params: vec![Type::Ptr, Type::Ptr, Type::I64],
                    ..Default::default()
                }
            });

            let inst = self.call_ext(&[Type::Ptr], libc_memcpy, &[dest, src, size]);
            self.func.inst_results(inst)[0]
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
        ) -> Value {
            let libc_memset = parent.import_function(ExtFunc {
                name: "memset".into(),
                signature: Signature {
                    params: vec![Type::Ptr, Type::I32, Type::I64],
                    ..Default::default()
                }
            });

            let inst = self.call_ext(&[Type::Ptr], libc_memset, &[dest, c, n]);
            self.func.inst_results(inst)[0]
        }
    }

    with_comment! {
        call_abort_with_comment,
        #[inline]
        pub fn call_abort(&mut self, parent: &mut Module) {
            let libc_abort = parent.import_function(ExtFunc {
                name: "abort".into(),
                signature: Signature::default()
            });

            self.call_ext(&[], libc_abort, &[]);
        }
    }

    with_comment! {
        ret_with_comment,
        #[inline]
        pub fn ret(&mut self, vals: &[Value]) {
            self.insert_inst(InstructionData::Return {
                args: vals.into()
            });
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
        let mut s = String::new();
        if let Some(results) = self.dfg.inst_results.get(&inst_id)
            && !results.is_empty() {
                s.push_str(&results.iter().map(|r| self.fmt_value(*r)).collect::<Vec<_>>().join(", "));
                s.push_str(" = ");
            }
        #[allow(clippy::format_push_string)]
        match inst {
            InstructionData::Binary { binop: opcode, args } => s.push_str(&format!("{:?} {}, {}", opcode, self.fmt_value(args[0]), self.fmt_value(args[1]))),
            InstructionData::Icmp { code, args } => s.push_str(&format!("icmp_{:?} {}, {}", code, self.fmt_value(args[0]), self.fmt_value(args[1]))),
            InstructionData::Unary { unop, arg } => s.push_str(&format!("{:?} {}", unop, self.fmt_value(*arg))),
            InstructionData::IConst { value } => s.push_str(&format!("iconst {value}")),
            InstructionData::FConst { value } => s.push_str(&format!("fconst {value}")),
            InstructionData::Jump { destination, args } => s.push_str(&format!("jump {}({})", destination, args.iter().map(|a| self.fmt_value(*a)).collect::<Vec<_>>().join(", "))),
            InstructionData::Branch { destinations, arg, args } => s.push_str(&format!("brif {}, {}, {}({})", self.fmt_value(*arg), destinations[0], destinations[1], args.iter().map(|a| self.fmt_value(*a)).collect::<Vec<_>>().join(", "))),
            InstructionData::Call { func_id, args, .. } => s.push_str(&format!("call {} ({})", func_id, args.iter().map(|a| self.fmt_value(*a)).collect::<Vec<_>>().join(", "))),
            InstructionData::CallHook { hook_id, args } => s.push_str(&format!("call_hook {} ({})", hook_id, args.iter().map(|a| self.fmt_value(*a)).collect::<Vec<_>>().join(", "))),
            InstructionData::CallExt { func_id, args } => s.push_str(&format!("call_ext {} ({})", func_id, args.iter().map(|a| self.fmt_value(*a)).collect::<Vec<_>>().join(", "))),
            InstructionData::Return { args } => s.push_str(&format!("return {}", args.iter().map(|v| self.fmt_value(*v)).collect::<Vec<_>>().join(", "))),
            InstructionData::StackAddr { slot } => s.push_str(&format!("stack_addr {slot}")),
            InstructionData::StackLoad { slot } => s.push_str(&format!("stack_load {slot}")),
            InstructionData::StackStore { slot, arg } => s.push_str(&format!("stack_store {}, {}", slot, self.fmt_value(*arg))),
            InstructionData::LoadNoOffset { ty, addr } => s.push_str(&format!("load_no_offset {}:{:?}", self.fmt_value(*addr), ty)),
            InstructionData::StoreNoOffset { args } => s.push_str(&format!("store_no_offset {}, {}", self.fmt_value(args[0]), self.fmt_value(args[1]))),
            InstructionData::DataAddr { data_id } => s.push_str(&format!("data_addr {data_id}")),
            // InstructionData::GlobalValue { global_value } => write!(f, "global_value {}", global_value),
            InstructionData::Unreachable => s.push_str("unreachable"),
            InstructionData::Nop => s.push_str("nop"),
        }

        write!(f, "  {s:<70}")?;

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
