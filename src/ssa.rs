use crate::with_comment;

use nohash_hasher::IntSet;
use rok_entity::packed_option::PackedOption;
use rok_entity::{EntityList, EntityRef, EntitySet, ListPool, PrimaryMap, SecondaryMap, SparseMap, sparse_pair};

use std::collections::BTreeMap;
use std::fmt;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};

use smallvec::{smallvec, SmallVec};

rok_entity::entity_ref!(Value, "Value");
rok_entity::entity_ref!(Inst, "Inst");
rok_entity::entity_ref!(SourceLoc, "SourceLoc");
rok_entity::entity_ref!(Block, "Block");
rok_entity::entity_ref!(StackSlot, "StackSlot");
rok_entity::entity_ref!(HookId, "HookId");
rok_entity::entity_ref!(FuncId, "FuncId");
rok_entity::entity_ref!(DataId, "DataId");
rok_entity::entity_ref!(Variable, "Variable");
rok_entity::entity_ref!(ExtFuncId, "ExternalFuncId");
rok_entity::entity_ref!(ValueLabel, "VL");

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// An error encountered when calling [`FunctionBuilder::try_use_var`].
pub enum UseVariableError {
    UsedBeforeDeclared(Variable),
}

impl fmt::Display for UseVariableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UseVariableError::UsedBeforeDeclared(variable) => {
                write!(
                    f,
                    "variable {} was used before it was defined",
                    variable.index()
                )?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for UseVariableError {}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// An error encountered when defining the initial value of a variable.
pub enum DefVariableError {
    /// The variable was instantiated with a value of the wrong type.
    ///
    /// note: to obtain the type of the value, you can call
    /// [`cranelift_codegen::ir::dfg::DataFlowGraph::value_type`] (using the
    /// `FunctionBuilder.func.dfg` field)
    TypeMismatch(Variable, Value),
    /// The value was defined (in a call to [`FunctionBuilder::def_var`]) before
    /// it was declared (in a call to [`FunctionBuilder::declare_var`]).
    DefinedBeforeDeclared(Variable),
}

impl fmt::Display for DefVariableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DefVariableError::TypeMismatch(variable, value) => {
                write!(
                    f,
                    "the types of variable {} and value {} are not the same.
                    The `Value` supplied to `def_var` must be of the same type as
                    the variable was declared to be of in `declare_var`.",
                    variable.index(),
                    value.as_u32()
                )?;
            }
            DefVariableError::DefinedBeforeDeclared(variable) => {
                write!(
                    f,
                    "the value of variable {} was declared before it was defined",
                    variable.index()
                )?;
            }
        }
        Ok(())
    }
}

impl SourceLoc {
    /// Is this the default source location?
    pub fn is_default(self) -> bool {
        self == Default::default()
    }

    /// Read the bits of this source location.
    pub fn bits(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Default, Eq, PartialEq)]
enum BlockStatus {
    /// No instructions have been added.
    #[default]
    Empty,
    /// Some instructions have been added, but no terminator.
    Partial,
    /// A terminator has been added; no further instructions may be added.
    Filled,
}

/// A label of a Value.
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct ValueLabelStart {
    /// Source location when it is in effect
    pub from: RelSourceLoc,

    /// The label index.
    pub label: ValueLabel,
}

/// Value label assignments: label starts or value aliases.
#[derive(Debug, Clone, PartialEq, Hash)]
pub enum ValueLabelAssignments {
    /// Original value labels assigned at transform.
    Starts(Vec<ValueLabelStart>),

    /// A value alias to original value.
    Alias {
        /// Source location when it is in effect
        from: RelSourceLoc,

        /// The label index.
        value: Value,
    },
}

/// Source location relative to another base source location.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RelSourceLoc(u32);

impl RelSourceLoc {
    /// Create a new relative source location with the given bits.
    pub fn new(bits: u32) -> Self {
        Self(bits)
    }

    /// Creates a new `RelSourceLoc` based on the given base and offset.
    pub fn from_base_offset(base: SourceLoc, offset: SourceLoc) -> Self {
        if base.is_default() || offset.is_default() {
            Self::default()
        } else {
            Self(offset.bits().wrapping_sub(base.bits()))
        }
    }

    /// Expands the relative source location into an absolute one, using the given base.
    pub fn expand(&self, base: SourceLoc) -> SourceLoc {
        if self.is_default() || base.is_default() {
            Default::default()
        } else {
            SourceLoc::from_u32(self.0.wrapping_add(base.bits()))
        }
    }

    /// Is this the default relative source location?
    pub fn is_default(self) -> bool {
        self == Default::default()
    }
}

impl Default for RelSourceLoc {
    fn default() -> Self {
        Self(!0)
    }
}

impl fmt::Display for RelSourceLoc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_default() {
            write!(f, "@-")
        } else {
            write!(f, "@+{:04x}", self.0)
        }
    }
}

/// Represents a data type in the IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    U8, U16, U32, U64,
    I8, I16, I32, I64,
    F32, F64,
    Ptr, FuncPtr
}

impl Type {
    #[must_use]
    #[inline(always)]
    pub const fn bytes(self) -> u32 {
        match self {
            Type::I8 | Type::U8 => 1,
            Type::I16 | Type::U16 => 2,
            Type::I32 | Type::U32 | Type::F32 => 4,
            Type::U64 | Type::I64 | Type::F64 | Type::Ptr | Type::FuncPtr => 8,
        }
    }

    #[must_use]
    #[inline(always)]
    pub const fn bits(self) -> u32 {
        self.bytes() * 8
    }

    #[must_use]
    #[track_caller]
    #[inline(always)]
    pub const fn int_custom_width_in_bytes(bytes: u32, signed: bool) -> Self {
        match (bytes, signed) {
            (1,  true) => Self::I8,
            (1, false) => Self::U8,

            (2,  true) => Self::I16,
            (2, false) => Self::U16,

            (4,  true) => Self::I32,
            (4, false) => Self::U32,

            (8,  true) => Self::I64,
            (8, false) => Self::U64,

            _ => unreachable!()
        }
    }

    #[must_use]
    #[track_caller]
    #[inline(always)]
    pub const fn int_custom_width_in_bits(bits: u32, signed: bool) -> Self {
        Self::int_custom_width_in_bytes(bits / 8, signed)
    }

    #[must_use]
    #[track_caller]
    #[inline(always)]
    pub const fn float_custom_width_in_bytes(bytes: u32) -> Self {
        match bytes {
            4 => Self::F32,
            8 => Self::F64,
            _ => unreachable!()
        }
    }

    #[must_use]
    #[track_caller]
    #[inline(always)]
    pub const fn float_custom_width_in_bits(bits: u32) -> Self {
        Self::float_custom_width_in_bytes(bits / 8)
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

            Self::Ptr | Self::F64 | Type::FuncPtr => Self::I64,

            other => other,
        }
    }

    #[must_use]
    #[inline(always)]
    pub const fn is_signed(self) -> bool {
        use Type::*;

        match self {
            U8 | U16 | U32 | U64 => false,
            I8 | I16 | I32 | I64 => true,
            F32 | F64 => true,
            Ptr | FuncPtr => false,
        }
    }

    #[must_use]
    #[inline(always)]
    pub const fn is_unsigned(self) -> bool {
        !self.is_signed()
    }

    #[must_use]
    #[inline(always)]
    pub const fn is_int(self) -> bool {
        use Type::*;

        match self {
            U8 | U16 | U32 | U64 => true,
            I8 | I16 | I32 | I64 => true,
            Ptr | FuncPtr => true,
            _ => false
        }
    }

    #[must_use]
    #[inline(always)]
    pub const fn is_float(self) -> bool {
        use Type::*;

        match self {
            U8 | U16 | U32 | U64 => false,
            I8 | I16 | I32 | I64 => false,
            Ptr | FuncPtr => false,
            F32 | F64 => true,
        }
    }
}

/// Represents a function signature.
#[derive(Eq, Debug, Clone, Default, PartialEq)]
pub struct Signature {
    pub params:  Vec<Type>,
    pub returns: Vec<Type>,

    /// For codegen and debugging purposes only,
    /// The amount of fixed arguments in a var-args def
    pub is_var_arg: Option<u8>,
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
    pub extra: u64,

    pub name: Box<str>,
    pub signature: Signature,
}

sparse_pair!{SparseInstResults: Inst => SmallVec<[Value; 2]>}

/// The core data flow graph, containing all instructions and values.
#[derive(Debug, Default)]
pub struct DataFlowGraph {
    pub insts: PrimaryMap<Inst, InstructionData>,
    pub values: PrimaryMap<Value, ValueData>,
    pub inst_results: SparseMap<Inst, SparseInstResults>,

    /// Saves Value labels.
    pub values_labels: Option<BTreeMap<Value, ValueLabelAssignments>>,
}

impl DataFlowGraph {
    #[inline]
    pub fn make_value(&mut self, data: ValueData) -> Value {
        self.values.push(data)
    }

    #[inline]
    pub fn make_inst(&mut self, data: InstructionData) -> Inst {
        self.insts.push(data)
    }
}

sparse_pair!{SparseBlockPred: Block => EntityList<Block>}

/// The control flow graph, containing all basic blocks.
#[derive(Debug, Default)]
pub struct ControlFlowGraph {
    pub blocks_pool: ListPool<Block>,
    pub block_insts_pool: ListPool<Inst>,
    pub blocks: PrimaryMap<Block, BasicBlockData>,
    pub predecessors: SparseMap<Block, SparseBlockPred>,
}

impl ControlFlowGraph {
    pub fn add_pred(&mut self, from: Block, to: Block) {
        if let Some(e) = self.predecessors.get_mut(to) {
            e.value.push(from, &mut self.blocks_pool);
            return
        }

        let preds = EntityList::from_slice(&[from], &mut self.blocks_pool);

        self.predecessors.insert(SparseBlockPred { key: to, value: preds });
    }
}

/// Represents a single basic block in the CFG.
#[derive(Debug, Clone, Copy, Default)]
pub struct BasicBlockData {
    pub insts: EntityList<Inst>,
    pub params: EntityList<Value>,
    pub is_sealed: bool,
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct StringRef {
    pub start: u32,  // Index into strings
    pub len:   u16
}

/// The top-level structure for a single function's IR.
#[derive(Debug, Default)]
pub struct SsaFunc {
    pub extra: u64,        // @Cleanup?

    pub is_external: bool,

    pub name: StringRef,

    pub signature: Signature,

    pub dfg: DataFlowGraph,
    pub cfg: ControlFlowGraph,

    pub layout: Layout,

    pub stack_slots: PrimaryMap<StackSlot, StackSlotData>,
    pub values_pool: ListPool<Value>,

    /// The first `SourceLoc` appearing in the function, serving as a base for every relative
    /// source loc in the function.
    pub base_srcloc: Option<SourceLoc>,

    pub srclocs: SecondaryMap<Inst, SourceLoc>,

    pub strings: String,   // @Memory: Move to Module?

    pub comments: SecondaryMap<Inst, StringRef>,
}

impl SsaFunc {
    #[must_use]
    #[inline(always)]
    pub fn new(name: impl AsRef<str>, signature: Signature, extra: u64) -> Self {
        let mut func = Self {
            extra,
            signature,
            ..Default::default()
        };

        let name = name.as_ref();
        func.name = func.push_string(name);

        func
    }

    #[inline(always)]
    pub fn name(&self) -> &str {
        self.get_string(self.name)
    }

    #[inline(always)]
    pub fn instruction_count(&self) -> usize {
        self.dfg.insts.len()
    }

    #[inline(always)]
    pub fn get_string(&self, comment: StringRef) -> &str {
        let s = comment.start as usize;
        &self.strings[s..s+comment.len as usize]
    }

    #[inline(always)]
    pub fn push_string(&mut self, string: impl AsRef<str>) -> StringRef {
        let string = string.as_ref();

        let start = self.strings.len() as u32;
        let len   = string.len() as u16;
        self.strings.push_str(string);

        StringRef { start, len }
    }

    #[inline(always)]
    pub fn create_stack_slot(&mut self, ty: Type, size: u32, align: u16) -> StackSlot {
        self.stack_slots.push(StackSlotData { ty, size: size as _, align })
    }

    /// Returns the base `SourceLoc`.
    ///
    /// If it was never explicitly set with `ensure_base_srcloc`, will return an invalid
    /// `SourceLoc`.
    pub fn base_srcloc(&self) -> SourceLoc {
        self.base_srcloc.unwrap_or_default()
    }

    /// Sets the base `SourceLoc`, if not set yet, and returns the base value.
    pub fn ensure_base_srcloc(&mut self, srcloc: SourceLoc) -> SourceLoc {
        match self.base_srcloc {
            Some(val) => val,
            None => {
                self.base_srcloc = Some(srcloc);
                srcloc
            }
        }
    }

    #[must_use]
    pub fn value_type(&self, v: Value) -> Type {
        self.dfg.values[v].ty
    }

    #[inline(always)]
    #[must_use]
    pub fn is_instruction_terminator(&self, inst: Inst) -> bool {
        self.dfg.insts[inst].is_terminator()
    }

    #[inline(always)]
    #[must_use]
    pub fn is_block_terminated(&self, block: Block) -> bool {
        let last_inst = self.cfg.blocks[block].insts.as_slice(&self.cfg.block_insts_pool).last().copied();
        last_inst.is_some_and(|inst| self.is_instruction_terminator(inst))
    }

    #[inline(always)]
    #[must_use]
    pub fn block_insts(&self, block: Block) -> &[Inst] {
        self.cfg.blocks[block].insts.as_slice(&self.cfg.block_insts_pool)
    }

    #[inline]
    #[must_use]
    pub fn instruction_data(&self, inst: Inst) -> &InstructionData {
        &self.dfg.insts[inst]
    }

    #[inline]
    #[must_use]
    pub fn inst_results(&self, inst: Inst) -> &[Value] {
        self.dfg.inst_results.get(inst).map_or(&[], |s| s.value.as_slice())
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
    pub fn inst_block(&self, inst: Inst) -> Option<Block> {
        self.layout.inst_block(inst)
    }

    #[inline]
    #[must_use]
    pub fn all_blocks_sealed(&self) -> bool {
        self.cfg.blocks.iter().all(|(_, b)| b.is_sealed)
    }

    #[inline]
    pub fn append_block_param(&mut self, block: Block, ty: Type) -> Value {
        let param_idx = self.cfg.blocks[block].params.len(&self.values_pool) as u8;
        let val = self.dfg.make_value(ValueData { ty, def: ValueDef::Param { block, param_idx } });
        self.cfg.blocks[block].params.push(val, &mut self.values_pool);
        val
    }

    #[inline]
    #[must_use]
    pub fn block_params(&self, block: Block) -> &[Value] {
        self.cfg.blocks[block].params.as_slice(&self.values_pool)
    }

    #[must_use]
    pub fn resolve_aliases(&self, mut val: Value) -> Value {
        loop {
            match self.dfg.values[val].def {
                ValueDef::Alias { original } => val = original,
                _ => return val,
            }
        }
    }

    pub fn remove_block_param(&mut self, val: Value) {
        let ValueDef::Param { block, .. } = self.dfg.values[val].def else {
            panic!("remove_block_param called on a non-param value");
        };

        let params = &mut self.cfg.blocks[block].params;
        let idx = params.as_slice(&self.values_pool)
            .iter()
            .position(|&p| p == val)
            .expect("param missing from its own block's param list");

        params.remove(idx, &mut self.values_pool);

        // Indices after idx shifted down by one, renumber so `num` stays accurate
        let remaining: Vec<Value> = params.as_slice(&self.values_pool).to_vec();
        for (i, &p) in remaining.iter().enumerate().skip(idx) {
            if let ValueDef::Param { param_idx, .. } = &mut self.dfg.values[p].def {
                *param_idx = i as u8;
            }
        }
    }

    pub fn change_to_alias(&mut self, val: Value, original: Value) {
        let ty = self.value_type(original);
        self.dfg.values[val] = ValueData { ty, def: ValueDef::Alias { original } };
    }
}

/// Maps logical entities (Inst, Block) to their container.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    pub inst_blocks: SecondaryMap<Inst, Block>,
    pub block_entry: PackedOption<Block>,
    pub block_order: Vec<Block>,
    pub block_placed: EntitySet<Block>,
}

impl Layout {
    #[inline]
    #[must_use]
    pub fn entry_block(&self) -> Option<Block> {
        self.block_entry.expand()
    }

    #[inline]
    #[must_use]
    pub fn inst_block(&self, inst: Inst) -> Option<Block> {
        self.inst_blocks.get(inst).copied()
    }

    #[inline]
    #[must_use]
    pub fn is_block_inserted(&self, block: Block) -> bool {
        self.block_placed.contains(block)
    }

    pub fn append_block(&mut self, block: Block) {
        if self.block_placed.insert(block) {
            self.block_order.push(block);
        }
        if self.block_entry.is_none() {
            self.block_entry = PackedOption::from(block);
        }
    }
}

/// Data associated with a stack slot.
#[derive(Debug, Clone)]
pub struct StackSlotData {
    pub ty: Type,
    pub size: u16,
    pub align: u16,
}

///////////////////////////////////////////////////////////////////////
// Instructions & Values
//

#[derive(Debug, Clone)]
pub enum InstructionData {
    CallHook { hook_id: HookId, args: EntityList<Value> },
    Binary { binop: BinaryOp, args: [Value; 2] },
    Unary { unop: UnaryOp, arg: Value },
    Icmp { code: IntCC, args: [Value; 2] },
    Fcmp { code: FloatCC, args: [Value; 2] },
    IConst { value: i64 },
    FConst { value: f64 },
    Jump { destination: Block, args: EntityList<Value> },
    Branch { destinations: [Block; 2], args: [EntityList<Value>; 2], arg: Value },
    Call { func_id: FuncId, args: EntityList<Value> },
    CallExt { func_id: ExtFuncId, args: EntityList<Value> },
    CallIndirect { callee: Value, args: EntityList<Value> },
    Return { args: EntityList<Value> },
    StackLoad { slot: StackSlot },
    StackAddr { slot: StackSlot },
    StackStore { slot: StackSlot, arg: Value },
    LoadNoOffset { ty: Type,  addr: Value },
    StoreNoOffset { args: [Value; 2] },
    DataAddr { data_id: DataId },
    Unreachable,
    Nop,
}

impl InstructionData {
    #[inline]
    #[must_use]
    pub fn bits(&self, inst: Inst, context: &SsaFunc) -> u32 {
        let vbits = |v: Value| context.dfg.values[v].ty.bits();
        let rbits = |idx: usize| {
            let r = unsafe { &context.dfg.inst_results.get(inst).unwrap_unchecked() };
            context.dfg.values[r[idx]].ty.bits()
        };

        match self {
            Self::Binary { args, .. } => vbits(args[0]),
            Self::Icmp { args, .. } => vbits(args[0]),
            Self::Fcmp { args, .. } => vbits(args[0]),
            Self::IConst { .. } => rbits(0),
            Self::FConst { .. } => rbits(0),
            Self::StackLoad { .. } => rbits(0),
            Self::DataAddr { .. } => rbits(0),
            Self::StackAddr { .. } => rbits(0),
            Self::StackStore { arg, .. } => vbits(*arg),
            Self::LoadNoOffset { ty, .. } => ty.bits(),
            Self::StoreNoOffset { args, .. } => vbits(args[1]),

            Self::Unary { unop, arg } => match unop {
                UnaryOp::SIntToFloat
                    | UnaryOp::UIntToFloat
                    | UnaryOp::FloatToSInt
                    | UnaryOp::FloatToUInt
                    | UnaryOp::FPromote
                    | UnaryOp::FDemote
                    | UnaryOp::Ireduce
                    | UnaryOp::Uextend
                    | UnaryOp::Sextend => rbits(0),

                _ => vbits(*arg),
            },

            Self::Jump { .. } => 32,
            Self::Branch { .. } => 32,
            Self::Call { .. } => 32,
            Self::CallExt { .. } => 32,
            Self::CallIndirect { .. } => 32,
            Self::Return { .. } => 32,

            Self::CallHook { .. } | Self::Unreachable | Self::Nop => 0,
        }
    }

    #[inline]
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        matches! {
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
pub enum FloatCC {
    Equal,
    NotEqual,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
}

#[derive(Debug, Clone, Copy)]
pub enum BinaryOp {
    IAdd,
    ISub,
    IMul,
    SDiv,
    UDiv,
    SRem,
    URem,
    And,
    Or,
    Xor,
    Ushr,
    Sshr,
    Ishl,
    Band,
    Bor,
    FAdd,
    FSub,
    FMul,
    FDiv,
    FRem,
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
    UIntToFloat,
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
    Alias { original: Value },
}

#[derive(Default)]
pub struct Module {
    pub funcs: PrimaryMap<FuncId, SsaFunc>,
    pub ext_funcs: PrimaryMap<ExtFuncId, ExtFunc>,

    pub _reused_func_ctx: FunctionBuilderContext,
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
    pub fn declare_function(&mut self, name: impl AsRef<str>, signature: Signature, extra: u64) -> FuncId {
        let mut func = SsaFunc::new(name, signature, extra);
        func.is_external = true;
        self.funcs.push(func)
    }

    #[track_caller]
    #[inline(always)]
    pub fn define_function(&mut self, id: FuncId) {
        let func = self.get_func_mut(id);
        func.is_external = false;
    }

    #[track_caller]
    #[inline(always)]
    pub fn get_func_mut(&mut self, id: FuncId) -> &mut SsaFunc {
        &mut self.funcs[id]
    }

    with_comment! {
        ir_builder,
        call_hook_with_comment,
        #[inline]
        #[track_caller]
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
        #[track_caller]
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
        #[track_caller]
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
                extra: u64::MAX,
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
                extra: u64::MAX,
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
                extra: u64::MAX,
                name: "abort".into(),
                signature: Signature::default()
            });

            ir_builder.call_ext(&[], libc_abort, &[]);
        }
    }
}


///////////////////////////////////////////////////////////////////////
// Function Builder
//

#[derive(Default)]
pub struct FunctionBuilderContext {
    status: SecondaryMap<Block, BlockStatus>,
    variables: PrimaryMap<Variable, Type>,
    stack_map_vars: EntitySet<Variable>,
    stack_map_values: EntitySet<Value>,
    pub ssa: SSABuilder,
}

impl FunctionBuilderContext {
    pub fn clear(&mut self) {
        let FunctionBuilderContext {
            ssa,
            status,
            variables,
            stack_map_vars,
            stack_map_values,
        } = self;
        ssa.clear();
        status.clear();
        variables.clear();
        stack_map_values.clear();
        stack_map_vars.clear();
    }
}

pub struct FunctionBuilder<'a> {
    pub func: &'a mut SsaFunc,
    pub cursor: Cursor,
    pub func_ctx: &'a mut FunctionBuilderContext
}

impl Deref for FunctionBuilder<'_> {
    type Target = FunctionBuilderContext;
    fn deref(&self) -> &Self::Target { &self.func_ctx }
}

impl DerefMut for FunctionBuilder<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.func_ctx }
}

#[derive(Debug, Clone, Copy)]
pub struct Cursor {
    current_block: Block,
    current_srcloc: SourceLoc,
}

impl<'a> FunctionBuilder<'a> {
    #[inline]
    pub fn new(func: &'a mut SsaFunc, func_ctx: &'a mut FunctionBuilderContext) -> Self {
        let entry_block = if let Some(block) = func.layout.block_entry.expand() {
            block
        } else {
            let block = Block::new(func.cfg.blocks.len());
            func.cfg.blocks.push(BasicBlockData::default());
            func.layout.block_entry = Some(block).into();
            block
        };
        Self {
            func,
            cursor: Cursor {
                current_block: entry_block,
                current_srcloc: Default::default(),
            },

            func_ctx,
        }
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
    pub fn at_first_insertion_point(&mut self, block: Block) -> &mut Self {
        self.cursor.current_block = block;
        self
    }

    #[inline]
    pub fn add_block_params(&mut self, types: &[Type]) -> &[Value] {
        let block = self.current_block();
        let block_data = &mut self.func.cfg.blocks[block];
        let param_idx_start = block_data.params.len(&self.func.values_pool);
        for (i, &ty) in types.iter().enumerate() {
            let value = self.func.dfg.make_value(ValueData {
                ty,
                def: ValueDef::Param {
                    block,
                    param_idx: (param_idx_start + i) as u8,
                },
            });
            block_data.params.push(value, &mut self.func.values_pool);
        }
        &block_data.params.as_slice(&self.func.values_pool)[param_idx_start..]
    }

    #[inline(always)]
    pub fn set_srcloc(&mut self, srcloc: SourceLoc) -> Option<SourceLoc> {
        self.func.ensure_base_srcloc(srcloc);

        let old = self.cursor.current_srcloc;
        self.cursor.current_srcloc = srcloc;

        if old == SourceLoc::default() {
            None
        } else {
            Some(old)
        }
    }

    #[inline(always)]
    pub fn unset_srcloc(&mut self) {
        self.cursor.current_srcloc = SourceLoc::default();
    }

    #[inline(always)]
    #[must_use]
    pub fn srcloc(&self) -> SourceLoc {
        self.cursor.current_srcloc
    }

    // TODO(#12): Names for stack slots?
    // TODO(#10): Why do we need to take in Type in create_stack_slot
    #[inline(always)]
    pub fn create_stack_slot(&mut self, ty: Type, size: u32, align: u16) -> StackSlot {
        self.func.create_stack_slot(ty, size, align)
    }

    #[inline(always)]
    pub fn insert_comment(&mut self, inst: Inst, comment: impl AsRef<str>) {
        let string = self.func.push_string(comment);
        self.func.comments.insert(inst, string);
    }

    #[inline(always)]
    pub fn ins<'short>(&'short mut self) -> InstBuilder<'short, 'a> {
        InstBuilder { builder: self }
    }

    /// Declares that all the predecessors of this block are known.
    ///
    /// Function to call with `block` as soon as the last branch instruction to `block` has been
    /// created. Forgetting to call this method on every block will cause inconsistencies in the
    /// produced functions.
    #[track_caller]
    pub fn seal_block(&mut self, block: Block) {
        let side_effects = self.func_ctx.ssa.seal_block(block, self.func);
        self.handle_ssa_side_effects(side_effects);
    }

    /// Effectively calls [seal_block](Self::seal_block) on all unsealed blocks in the function.
    ///
    /// It's more efficient to seal [`Block`]s as soon as possible, during
    /// translation, but for frontends where this is impractical to do, this
    /// function can be used at the end of translating all blocks to ensure
    /// that everything is sealed.
    pub fn seal_all_blocks(&mut self) {
        let side_effects = self.func_ctx.ssa.seal_all_blocks(self.func);
        self.handle_ssa_side_effects(side_effects);
    }

    /// Declares the type of a variable.
    ///
    /// This allows the variable to be defined and used later (by calling
    /// [`FunctionBuilder::def_var`] and [`FunctionBuilder::use_var`]
    /// respectively).
    pub fn declare_var(&mut self, ty: Type) -> Variable {
        self.variables.push(ty)
    }

    /// Declare that all uses of the given variable must be included in stack
    /// map metadata.
    ///
    /// All values that are uses of this variable will be spilled to the stack
    /// before each safepoint and their location on the stack included in stack
    /// maps. Stack maps allow the garbage collector to identify the on-stack GC
    /// roots.
    ///
    /// This does not affect any pre-existing uses of the variable.
    ///
    /// # Panics
    ///
    /// Panics if the variable's type is larger than 16 bytes or if this
    /// variable has not been declared yet.
    pub fn declare_var_needs_stack_map(&mut self, var: Variable) {
        self.stack_map_vars.insert(var);
    }

    /// Returns the Cranelift IR necessary to use a previously defined user
    /// variable, returning an error if this is not possible.
    pub fn try_use_var(&mut self, var: Variable) -> Result<Value, UseVariableError> {
        // Assert that we're about to add instructions to this block using the definition of the
        // given variable. ssa.use_var is the only part of this crate which can add block parameters
        // behind the caller's back. If we disallow calling append_block_param as soon as use_var is
        // called, then we enforce a strict separation between user parameters and SSA parameters.
        self.ensure_inserted_block();

        let (val, side_effects) = {
            let ty = *self
                .variables
                .get(var)
                .ok_or(UseVariableError::UsedBeforeDeclared(var))?;

            self.func_ctx.ssa.use_var(self.func, var, ty, self.current_block())
        };
        self.handle_ssa_side_effects(side_effects);

        Ok(val)
    }

    /// Make sure that the current block is inserted in the layout.
    pub fn ensure_inserted_block(&mut self) {
        let block = self.current_block();
        if self.is_pristine(block) {
            if !self.func.layout.is_block_inserted(block) {
                self.func.layout.append_block(block);
            }
            self.status[block] = BlockStatus::Partial;
        } else {
            debug_assert!(
                !self.is_filled(block),
                "you cannot add an instruction to a block already filled"
            );
        }
    }

    /// Returns the Cranelift IR value corresponding to the utilization at the current program
    /// position of a previously defined user variable.
    pub fn use_var(&mut self, var: Variable) -> Value {
        self.try_use_var(var).unwrap_or_else(|_| {
            panic!("variable {var:?} is used but its type has not been declared")
        })
    }

    /// Registers a new definition of a user variable. This function will return
    /// an error if the value supplied does not match the type the variable was
    /// declared to have.
    pub fn try_def_var(&mut self, var: Variable, val: Value) -> Result<(), DefVariableError> {
        let var_ty = *self
            .variables
            .get(var)
            .ok_or(DefVariableError::DefinedBeforeDeclared(var))?;
        if var_ty != self.func.value_type(val) {
            return Err(DefVariableError::TypeMismatch(var, val));
        }

        self.func_ctx.ssa.def_var(var, val, self.current_block());
        Ok(())
    }

    /// Register a new definition of a user variable. The type of the value must be
    /// the same as the type registered for the variable.
    pub fn def_var(&mut self, var: Variable, val: Value) {
        self.try_def_var(var, val)
            .unwrap_or_else(|error| match error {
                DefVariableError::TypeMismatch(var, val) => {
                    panic!("declared type of variable {var:?} doesn't match type of value {val}");
                }
                DefVariableError::DefinedBeforeDeclared(var) => {
                    panic!("variable {var:?} is used but its type has not been declared");
                }
            })
    }

    /// Set label for [`Value`]
    ///
    /// This will not do anything unless
    /// [`func.dfg.collect_debug_info`](DataFlowGraph::collect_debug_info) is called first.
    pub fn set_val_label(&mut self, val: Value, label: ValueLabel) {
        let from = RelSourceLoc::from_base_offset(self.func.base_srcloc(), self.srcloc());

        if let Some(values_labels) = self.func.dfg.values_labels.as_mut() {
            use std::collections::btree_map::Entry;

            let start = ValueLabelStart {
                from,
                label,
            };

            match values_labels.entry(val) {
                Entry::Occupied(mut e) => match e.get_mut() {
                    ValueLabelAssignments::Starts(starts) => starts.push(start),
                    _ => panic!("Unexpected ValueLabelAssignments at this stage"),
                },
                Entry::Vacant(e) => {
                    e.insert(ValueLabelAssignments::Starts(vec![start]));
                }
            }
        }
    }

    /// Declare that the given value is a GC reference that requires inclusion
    /// in a stack map when it is live across GC safepoints.
    ///
    /// At the current moment, values that need inclusion in stack maps are
    /// spilled before safepoints, but they are not reloaded afterwards. This
    /// means that moving GCs are not yet supported, however the intention is to
    /// add this support in the near future.
    ///
    /// # Panics
    ///
    /// Panics if `val` is larger than 16 bytes.
    pub fn declare_value_needs_stack_map(&mut self, val: Value) {
        // We rely on these properties in `insert_safepoint_spills`.
        let size = self.func.value_type(val).bytes();
        assert!(size <= 16);
        assert!(size.is_power_of_two());

        self.stack_map_values.insert(val);
    }

    #[inline(always)]
    #[track_caller]
    pub fn finalize(&mut self) {
        for i in 0..self.func.cfg.blocks.len() {
            let block = Block::new(i);
            self.seal_block(block);
        }
    }
}

// Helper functions
impl<'a> FunctionBuilder<'a> {
    /// A Block is 'filled' when a terminator instruction is present.
    fn fill_current_block(&mut self) {
        self.func_ctx.status[self.cursor.current_block] = BlockStatus::Filled;
    }

    /// Returns `true` if and only if the current [`Block`] is sealed and has no predecessors declared.
    ///
    /// The entry block of a function is never unreachable.
    pub fn is_unreachable(&self) -> bool {
        let is_entry = match self.func.layout.entry_block() {
            None => false,
            Some(entry) => self.current_block() == entry,
        };
        !is_entry
            && self.ssa.is_sealed(self.current_block())
            && !self
                .ssa
                .has_any_predecessors(self.current_block())
    }

    /// Returns `true` if and only if no instructions have been added since the last call to
    /// [`switch_to_block`](Self::switch_to_block).
    fn is_pristine(&self, block: Block) -> bool {
        self.status[block] == BlockStatus::Empty
    }

    /// Returns `true` if and only if a terminator instruction has been inserted since the
    /// last call to [`switch_to_block`](Self::switch_to_block).
    fn is_filled(&self, block: Block) -> bool {
        self.status[block] == BlockStatus::Filled
    }

    fn declare_successor(&mut self, dest_block: Block, jump_inst: Inst) {
        self.ssa
            .declare_block_predecessor(dest_block, jump_inst);
    }

    fn handle_ssa_side_effects(&mut self, side_effects: SideEffects) {
        let SideEffects {
            instructions_added_to_blocks,
        } = side_effects;

        for modified_block in instructions_added_to_blocks {
            if self.is_pristine(modified_block) {
                self.status[modified_block] = BlockStatus::Partial;
            }
        }
    }
}

pub struct InstBuilder<'short, 'long> {
    builder: &'short mut FunctionBuilder<'long>,
}

impl<'long> Deref for InstBuilder<'_, 'long> {
    type Target = FunctionBuilder<'long>;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.builder
    }
}

impl DerefMut for InstBuilder<'_, '_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.builder
    }
}

impl InstBuilder<'_, '_> {
    #[inline]
    fn insert_inst(&mut self, data: InstructionData) -> Inst {
        let inst = self.builder.func.dfg.make_inst(data);
        let block = self.cursor.current_block;
        let srcloc = self.cursor.current_srcloc;

        let cfg = &mut self.builder.func.cfg;
        cfg.blocks[block].insts.push(inst, &mut cfg.block_insts_pool);

        self.builder.func.srclocs.insert(inst, srcloc);
        self.builder.func.layout.inst_blocks.insert(inst, block);

        inst
    }

    #[inline]
    #[must_use]
    pub fn get_last_inst(&self) -> Option<Inst> {
        let block = self.current_block();
        self.builder.func.cfg.blocks[block]
            .insts
            .as_slice(&self.func.cfg.block_insts_pool)
            .last()
            .copied()
    }

    #[inline]
    fn make_inst_result(&mut self, inst: Inst, ty: Type, result_idx: u8) -> Value {
        let value = self.builder.func.dfg.make_value(ValueData {
            ty,
            def: ValueDef::Inst { inst, result_idx },
        });

        let results = &mut self.builder
            .func
            .dfg
            .inst_results;

        if let Some(results) = results.get_mut(inst) {
            results.push(value);
        } else {
            results.insert(SparseInstResults {
                key: inst,
                value: smallvec![value]
            });
        }

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
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary {
                binop: BinaryOp::IAdd, args: [lhs, rhs]
            });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        srem_with_comment,
        #[inline]
        pub fn srem(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary {
                binop: BinaryOp::SRem, args: [lhs, rhs]
            });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        urem_with_comment,
        #[inline]
        pub fn urem(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary {
                binop: BinaryOp::URem, args: [lhs, rhs]
            });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        frem_with_comment,
        #[inline]
        pub fn frem(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FRem, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    #[inline]
    pub fn fmod_imm(&mut self, lhs: Value, rhs: f64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.fconst(ty, rhs);
        self.frem(lhs, rhs)
    }

    with_comment! {
        isub_with_comment,
        #[inline]
        pub fn isub(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::ISub, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        imul_with_comment,
        #[inline]
        pub fn imul(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::IMul, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        sdiv_with_comment,
        #[inline]
        pub fn sdiv(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::SDiv, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        udiv_with_comment,
        #[inline]
        pub fn udiv(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::UDiv, args: [lhs, rhs] });
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
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::And, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        or_with_comment,
        #[inline]
        pub fn or(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Or, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        xor_with_comment,
        #[inline]
        pub fn xor(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Xor, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        icmp_with_comment,
        #[inline]
        pub fn icmp(&mut self, code: IntCC, lhs: Value, rhs: Value) -> Value {
            let ty = Type::U8;
            let inst = self.insert_inst(InstructionData::Icmp { code, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fcmp_with_comment,
        #[inline]
        pub fn fcmp(&mut self, code: FloatCC, lhs: Value, rhs: Value) -> Value {
            let ty = Type::U8;
            let inst = self.insert_inst(InstructionData::Fcmp { code, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    #[inline]
    pub fn iadd_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        if rhs == 0 {
            return lhs;
        }

        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.iadd(lhs, rhs)
    }

    #[inline]
    pub fn isub_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        if rhs == 0 {
            return lhs;
        }

        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.isub(lhs, rhs)
    }

    #[inline]
    pub fn imul_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        if rhs == 1 {
            return lhs;
        }

        let ty = self.builder.func.value_type(lhs);
        if rhs == 0 {
            return self.iconst(ty, 0);
        }

        // Strength reduce multiply by a power of two into a shift.
        if rhs > 0 && (rhs & (rhs - 1)) == 0 {
            let shift = rhs.trailing_zeros() as i64;
            let shift_amt = self.iconst(ty, shift);
            return self.ishl(lhs, shift_amt);
        }

        let rhs = self.iconst(ty, rhs);
        self.imul(lhs, rhs)
    }

    #[inline]
    pub fn sdiv_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        if rhs == 1 {
            return lhs;
        }
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.sdiv(lhs, rhs)
    }

    #[inline]
    pub fn udiv_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        if rhs == 1 {
            return lhs;
        }
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.udiv(lhs, rhs)
    }

    #[inline]
    pub fn and_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);

        if rhs == 0 {
            return self.iconst(ty, 0);
        }
        if rhs == -1 {
            return lhs;
        }

        let rhs = self.iconst(ty, rhs);
        self.and(lhs, rhs)
    }

    #[inline]
    pub fn or_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        if rhs == 0 {
            return lhs;
        }

        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.or(lhs, rhs)
    }

    #[inline]
    pub fn xor_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        if rhs == 0 {
            return lhs;
        }

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

    #[inline]
    pub fn fcmp_imm(&mut self, code: FloatCC, lhs: Value, rhs: f64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.fconst(ty, rhs);
        self.fcmp(code, lhs, rhs)
    }

    with_comment! {
        ushr_with_comment,
        #[inline]
        pub fn ushr(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Ushr, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        sshr_with_comment,
        #[inline]
        pub fn sshr(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Sshr, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        ishl_with_comment,
        #[inline]
        pub fn ishl(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Ishl, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        band_with_comment,
        #[inline]
        pub fn band(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Band, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        bor_with_comment,
        #[inline]
        pub fn bor(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
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
    pub fn sshr_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.builder.func.value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.sshr(lhs, rhs)
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
            if self.func.value_type(arg) == ty {
                return arg;
            }

            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::Ireduce, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        uextend_with_comment,
        #[inline]
        pub fn uextend(&mut self, ty: Type, arg: Value) -> Value {
            if self.func.value_type(arg) == ty {
                return arg;
            }

            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::Uextend, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        sextend_with_comment,
        #[inline]
        pub fn sextend(&mut self, ty: Type, arg: Value) -> Value {
            if self.func.value_type(arg) == ty {
                return arg;
            }

            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::Sextend, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fpromote_with_comment,
        #[inline]
        pub fn fpromote(&mut self, ty: Type, arg: Value) -> Value {
            if self.func.value_type(arg) == ty {
                return arg;
            }

            let inst = self.insert_inst(InstructionData::Unary { unop: UnaryOp::FPromote, arg });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fdemote_with_comment,
        #[inline]
        pub fn fdemote(&mut self, ty: Type, arg: Value) -> Value {
            if self.func.value_type(arg) == ty {
                return arg;
            }

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
            let ty = self.builder.func.dfg.values[arg].ty;
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

            if self.func.value_type(arg) == ty {
                return arg;
            }

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
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FAdd, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fsub_with_comment,
        #[inline]
        pub fn fsub(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FSub, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fmul_with_comment,
        #[inline]
        pub fn fmul(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FMul, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fdiv_with_comment,
        #[inline]
        pub fn fdiv(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.builder.func.dfg.values[lhs].ty;
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

    with_comment! {
        jump_with_comment,
        #[inline]
        pub fn jump(&mut self, dest: Block) {
            self.insert_inst(InstructionData::Jump {
                destination: dest,
                args: EntityList::new()
            });
            let from = self.cursor.current_block;
            self.builder.func.cfg.add_pred(from, dest);
        }
    }

    with_comment! {
        jump_params_with_comment,
        #[inline]
        pub fn jump_params(&mut self, dest: Block, params: &[Value]) {
            let args = EntityList::from_slice(
                params,
                &mut self.func.values_pool
            );
            self.insert_inst(InstructionData::Jump {
                destination: dest,
                args,
            });
            let from = self.cursor.current_block;
            self.builder.func.cfg.add_pred(from, dest);
        }
    }

    with_comment! {
        brif_params_with_comment,
        #[inline]
        pub fn brif_params(&mut self, cond: Value, true_dest: Block, false_dest: Block, true_args: &[Value], false_args: &[Value]) {
            let true_args = EntityList::from_slice(
                true_args,
                &mut self.func.values_pool
            );
            let false_args = EntityList::from_slice(
                false_args,
                &mut self.func.values_pool
            );
            self.insert_inst(InstructionData::Branch {
                destinations: [true_dest, false_dest],
                arg: cond,
                args: [true_args, false_args]
            });

            let from = self.cursor.current_block;
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
                args: [EntityList::new(), EntityList::new()]
            });
            let from = self.cursor.current_block;
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
            let args = EntityList::from_slice(
                args,
                &mut self.func.values_pool
            );

            let inst = self.insert_inst(InstructionData::Call {
                func_id,
                args
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
            let args = EntityList::from_slice(
                args,
                &mut self.func.values_pool
            );
            let inst = self.insert_inst(InstructionData::CallHook {
                hook_id,
                args
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
            let args = EntityList::from_slice(
                args,
                &mut self.func.values_pool
            );
            let inst = self.insert_inst(InstructionData::CallExt {
                func_id,
                args
            });
            for (i, ty) in result_tys.iter().enumerate() {
                self.make_inst_result(inst, *ty, i as _);
            }
            inst
        }
    }

    with_comment! {
        call_indirect_with_comment,
        #[inline]
        pub fn call_indirect(
            &mut self,
            result_tys: &[Type],
            callee: Value,
            args: &[Value],
        ) -> Inst {
            let args = EntityList::from_slice(
                args,
                &mut self.func.values_pool
            );
            let inst = self.insert_inst(InstructionData::CallIndirect {
                callee,
                args
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
                extra: u64::MAX,
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
                extra: u64::MAX,
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
                extra: u64::MAX,
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
            let args = EntityList::from_slice(
                vals,
                &mut self.func.values_pool
            );
            self.insert_inst(InstructionData::Return { args });
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

///////////////////////////////////////////////////////////////////////
// SSA Builder
//

/// Structure containing the data relevant the construction of SSA for a given function.
///
/// The parameter struct [`Variable`] corresponds to the way variables are represented in the
/// non-SSA language you're translating from.
///
/// The SSA building relies on information about the variables used and defined.
///
/// This SSA building module allows you to def and use variables on the fly while you are
/// constructing the CFG, no need for a separate SSA pass after the CFG is completed.
///
/// A basic block is said _filled_ if all the instruction that it contains have been translated,
/// and it is said _sealed_ if all of its predecessors have been declared. Only filled predecessors
/// can be declared.
#[derive(Default)]
pub struct SSABuilder {
    // TODO: Consider a sparse representation rather than SecondaryMap-of-SecondaryMap.
    /// Records for every variable and for every relevant block, the last definition of
    /// the variable in the block.
    variables: SecondaryMap<Variable, SecondaryMap<Block, PackedOption<Value>>>,

    /// Records the position of the basic blocks and the list of values used but not defined in the
    /// block.
    ssa_blocks: SecondaryMap<Block, SSABlockData>,

    /// Call stack for use in the `use_var`/`predecessors_lookup` state machine.
    calls: Vec<Call>,
    /// Result stack for use in the `use_var`/`predecessors_lookup` state machine.
    results: Vec<Value>,

    /// Side effects accumulated in the `use_var`/`predecessors_lookup` state machine.
    side_effects: SideEffects,

    /// Reused storage for cycle-detection.
    visited: EntitySet<Block>,

    /// Storage for pending variable definitions.
    variable_pool: ListPool<Variable>,

    /// Storage for predecessor definitions.
    inst_pool: ListPool<Inst>,
}

/// Side effects of a `use_var` or a `seal_block` method call.
#[derive(Default)]
pub struct SideEffects {
    /// When a variable is used but has never been defined before (this happens in the case of
    /// unreachable code), a placeholder `iconst` or `fconst` value is added to the right `Block`.
    /// This field signals if it is the case and return the `Block` to which the initialization has
    /// been added.
    pub instructions_added_to_blocks: Vec<Block>,
}

impl SideEffects {
    fn is_empty(&self) -> bool {
        let Self {
            instructions_added_to_blocks,
        } = self;
        instructions_added_to_blocks.is_empty()
    }
}

#[derive(Clone)]
enum Sealed {
    No {
        // List of current Block arguments for which an earlier def has not been found yet.
        undef_variables: EntityList<Variable>,
    },
    Yes,
}

impl Default for Sealed {
    fn default() -> Self {
        Sealed::No {
            undef_variables: EntityList::new(),
        }
    }
}

#[derive(Clone, Default)]
struct SSABlockData {
    // The predecessors of the Block with the block and branch instruction.
    predecessors: EntityList<Inst>,
    // A block is sealed if all of its predecessors have been declared.
    sealed: Sealed,
    // If this block is sealed and it has exactly one predecessor, this is that predecessor.
    single_predecessor: PackedOption<Block>,
}

impl SSABuilder {
    /// Clears a `SSABuilder` from all its data, letting it in a pristine state without
    /// deallocating memory.
    pub fn clear(&mut self) {
        self.variables.clear();
        self.ssa_blocks.clear();
        self.variable_pool.clear();
        self.inst_pool.clear();
        debug_assert!(self.calls.is_empty());
        debug_assert!(self.results.is_empty());
        debug_assert!(self.side_effects.is_empty());
    }

    /// Tests whether an `SSABuilder` is in a cleared state.
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
            && self.ssa_blocks.is_empty()
            && self.calls.is_empty()
            && self.results.is_empty()
            && self.side_effects.is_empty()
    }
}

/// States for the `use_var`/`predecessors_lookup` state machine.
enum Call {
    UseVar(Inst),
    FinishPredecessorsLookup(Value, Block),
}

/// Emit instructions to produce a zero value in the given type.
fn emit_zero(ty: Type, cur: &mut FunctionBuilder) -> Value {
    match ty {
        ty if ty.is_int() => cur.ins().iconst(ty, 0),
        ty if ty.is_float() => cur.ins().fconst(ty, 0.0),
        ty => panic!("unimplemented type: {ty:?}"),
    }
}

/// The following methods are the API of the SSA builder. Here is how it should be used when
/// translating to Cranelift IR:
///
/// - for each basic block, create a corresponding data for SSA construction with `declare_block`;
///
/// - while traversing a basic block and translating instruction, use `def_var` and `use_var`
///   to record definitions and uses of variables, these methods will give you the corresponding
///   SSA values;
///
/// - when all the instructions in a basic block have translated, the block is said _filled_ and
///   only then you can add it as a predecessor to other blocks with `declare_block_predecessor`;
///
/// - when you have constructed all the predecessor to a basic block,
///   call `seal_block` on it with the `Function` that you are building.
///
/// This API will give you the correct SSA values to use as arguments of your instructions,
/// as well as modify the jump instruction and `Block` parameters to account for the SSA
/// Phi functions.
///
impl SSABuilder {
    /// Get all of the values associated with the given variable that we have
    /// inserted in the function thus far.
    pub fn values_for_var(&self, var: Variable) -> impl Iterator<Item = Value> + '_ {
        self.variables[var].values().filter_map(|v| v.expand())
    }

    /// Declares a new definition of a variable in a given basic block.
    /// The SSA value is passed as an argument because it should be created with
    /// `ir::DataFlowGraph::append_result`.
    pub fn def_var(&mut self, var: Variable, val: Value, block: Block) {
        self.variables[var][block] = PackedOption::from(val);
    }

    /// Declares a use of a variable in a given basic block. Returns the SSA value corresponding
    /// to the current SSA definition of this variable and a list of newly created Blocks that
    /// are the results of critical edge splitting for `br_table` with arguments.
    ///
    /// If the variable has never been defined in this blocks or recursively in its predecessors,
    /// this method will silently create an initializer with `iconst` or `fconst`. You are
    /// responsible for making sure that you initialize your variables.
    pub fn use_var(
        &mut self,
        func: &mut SsaFunc,
        var: Variable,
        ty: Type,
        block: Block,
    ) -> (Value, SideEffects) {
        debug_assert!(self.calls.is_empty());
        debug_assert!(self.results.is_empty());
        debug_assert!(self.side_effects.is_empty());

        // Prepare the 'calls' and 'results' stacks for the state machine.
        self.use_var_nonlocal(func, var, ty, block);
        let value = self.run_state_machine(func, var, ty);

        let side_effects = core::mem::take(&mut self.side_effects);
        (value, side_effects)
    }

    /// Resolve the minimal SSA Value of `var` in `block` by traversing predecessors.
    ///
    /// This function sets up state for `run_state_machine()` but does not execute it.
    fn use_var_nonlocal(&mut self, func: &mut SsaFunc, var: Variable, ty: Type, mut block: Block) {
        // First, try Local Value Numbering (Algorithm 1 in the paper).
        // If the variable already has a known Value in this block, use that.
        if let Some(val) = self.variables[var][block].expand() {
            self.results.push(val);
            return;
        }

        // Otherwise, use Global Value Numbering (Algorithm 2 in the paper).
        // This resolves the Value with respect to its predecessors.
        // Find the most recent definition of `var`, and the block the definition comes from.
        let (val, from) = self.find_var(func, var, ty, block);

        // The `from` block returned from `find_var` is guaranteed to be on the path we follow by
        // traversing only single-predecessor edges. It might be equal to `block` if there is no
        // such path, but in that case `find_var` ensures that the variable is defined in this block
        // by a new block parameter. It also might be somewhere in a cycle, but even then this loop
        // will terminate the first time it encounters that block, rather than continuing around the
        // cycle forever.
        //
        // Why is it okay to copy the definition to all intervening blocks? For the initial block,
        // this may not be the final definition of this variable within this block, but if we've
        // gotten here then we know there is no earlier definition in the block already.
        //
        // For the remaining blocks: Recall that a block is only allowed to be set as a predecessor
        // after all its instructions have already been filled in, so when we follow a predecessor
        // edge to a block, we know there will never be any more local variable definitions added to
        // that block. We also know that `find_var` didn't find a definition for this variable in
        // any of the blocks before `from`.
        //
        // So in either case there is no definition in these blocks yet and we can blindly set one.
        let var_defs = &mut self.variables[var];
        while block != from {
            debug_assert!(var_defs[block].is_none());
            var_defs[block] = PackedOption::from(val);
            block = self.ssa_blocks[block].single_predecessor.unwrap();
        }
    }

    /// Find the most recent definition of this variable, returning both the definition and the
    /// block in which it was found. If we can't find a definition that's provably the right one for
    /// all paths to the current block, then append a block parameter to some block and use that as
    /// the definition. Either way, also arrange that the definition will be on the `results` stack
    /// when `run_state_machine` is done processing the current step.
    ///
    /// If a block has exactly one predecessor, and the block is sealed so we know its predecessors
    /// will never change, then its definition for this variable is the same as the definition from
    /// that one predecessor. In this case it's easy to see that no block parameter is necessary,
    /// but we need to look at the predecessor to see if a block parameter might be needed there.
    /// That holds transitively across any chain of sealed blocks with exactly one predecessor each.
    ///
    /// This runs into a problem, though, if such a chain has a cycle: Blindly following a cyclic
    /// chain that never defines this variable would lead to an infinite loop in the compiler. It
    /// doesn't really matter what code we generate in that case. Since each block in the cycle has
    /// exactly one predecessor, there's no way to enter the cycle from the function's entry block;
    /// and since all blocks in the cycle are sealed, the entire cycle is permanently dead code. But
    /// we still have to prevent the possibility of an infinite loop.
    ///
    /// To break cycles, we can pick any block within the cycle as the one where we'll add a block
    /// parameter. It's convenient to pick the block at which we entered the cycle, because that's
    /// the first place where we can detect that we just followed a cycle. Adding a block parameter
    /// gives us a definition we can reuse throughout the rest of the cycle.
    fn find_var(
        &mut self,
        func: &mut SsaFunc,
        var: Variable,
        ty: Type,
        mut block: Block,
    ) -> (Value, Block) {
        // Try to find an existing definition along single-predecessor edges first.
        self.visited.clear();
        let var_defs = &mut self.variables[var];
        while let Some(pred) = self.ssa_blocks[block].single_predecessor.expand() {
            if !self.visited.insert(block) {
                break;
            }
            block = pred;
            if let Some(val) = var_defs[block].expand() {
                self.results.push(val);
                return (val, block);
            }
        }

        // We've promised to return the most recent block where `var` was defined, but we didn't
        // find a usable definition. So create one.
        let val = func.append_block_param(block, ty);
        var_defs[block] = PackedOption::from(val);

        // Now every predecessor needs to pass its definition of this variable to the newly added
        // block parameter. To do that we have to "recursively" call `use_var`, but there are two
        // problems with doing that. First, we need to keep a fixed bound on stack depth, so we
        // can't actually recurse; instead we defer to `run_state_machine`. Second, if we don't
        // know all our predecessors yet, we have to defer this work until the block gets sealed.
        match &mut self.ssa_blocks[block].sealed {
            // Once all the `calls` added here complete, this leaves either `val` or an equivalent
            // definition on the `results` stack.
            Sealed::Yes => self.begin_predecessors_lookup(val, block),
            Sealed::No { undef_variables } => {
                undef_variables.push(var, &mut self.variable_pool);
                self.results.push(val);
            }
        }
        (val, block)
    }

    /// Declares a new basic block to construct corresponding data for SSA construction.
    /// No predecessors are declared here and the block is not sealed.
    /// Predecessors have to be added with `declare_block_predecessor`.
    pub fn declare_block(&mut self, block: Block) {
        // Ensure the block exists so seal_all_blocks will see it even if no predecessors or
        // variables get declared for this block. But don't assign anything to it:
        // SecondaryMap automatically sets all blocks to `default()`.
        let _ = &mut self.ssa_blocks[block];
    }

    /// Declares a new predecessor for a `Block` and record the branch instruction
    /// of the predecessor that leads to it.
    ///
    /// The precedent `Block` must be filled before added as predecessor.
    /// Note that you must provide no jump arguments to the branch
    /// instruction when you create it since `SSABuilder` will fill them for you.
    ///
    /// Callers are expected to avoid adding the same predecessor more than once in the case
    /// of a jump table.
    pub fn declare_block_predecessor(&mut self, block: Block, inst: Inst) {
        debug_assert!(!self.is_sealed(block));
        self.ssa_blocks[block]
            .predecessors
            .push(inst, &mut self.inst_pool);
    }

    /// Remove a previously declared Block predecessor by giving a reference to the jump
    /// instruction. Returns the basic block containing the instruction.
    ///
    /// Note: use only when you know what you are doing, this might break the SSA building problem
    pub fn remove_block_predecessor(&mut self, block: Block, inst: Inst) {
        debug_assert!(!self.is_sealed(block));
        let data = &mut self.ssa_blocks[block];
        let pred = data
            .predecessors
            .as_slice(&self.inst_pool)
            .iter()
            .position(|&branch| branch == inst)
            .expect("the predecessor you are trying to remove is not declared");
        data.predecessors.swap_remove(pred, &mut self.inst_pool);
    }

    /// Completes the global value numbering for a `Block`, all of its predecessors having been
    /// already sealed.
    ///
    /// This method modifies the function's `Layout` by adding arguments to the `Block`s to
    /// take into account the Phi function placed by the SSA algorithm.
    ///
    /// Returns the list of newly created blocks for critical edge splitting.
    #[track_caller]
    pub fn seal_block(&mut self, block: Block, func: &mut SsaFunc) -> SideEffects {
        debug_assert!(
            !self.is_sealed(block),
            "Attempting to seal {block} which is already sealed."
        );
        self.seal_one_block(block, func);
        core::mem::take(&mut self.side_effects)
    }

    /// Completes the global value numbering for all unsealed `Block`s in `func`.
    ///
    /// It's more efficient to seal `Block`s as soon as possible, during
    /// translation, but for frontends where this is impractical to do, this
    /// function can be used at the end of translating all blocks to ensure
    /// that everything is sealed.
    pub fn seal_all_blocks(&mut self, func: &mut SsaFunc) -> SideEffects {
        // Seal all `Block`s currently in the function. This can entail splitting
        // and creation of new blocks, however such new blocks are sealed on
        // the fly, so we don't need to account for them here.
        for block in self.ssa_blocks.keys() {
            self.seal_one_block(block, func);
        }
        core::mem::take(&mut self.side_effects)
    }

    /// Helper function for `seal_block` and `seal_all_blocks`.
    fn seal_one_block(&mut self, block: Block, func: &mut SsaFunc) {
        // For each undef var we look up values in the predecessors and create a block parameter
        // only if necessary.
        let mut undef_variables =
            match core::mem::replace(&mut self.ssa_blocks[block].sealed, Sealed::Yes) {
                Sealed::No { undef_variables } => undef_variables,
                Sealed::Yes => return,
            };
        let ssa_params = undef_variables.len(&self.variable_pool);

        let predecessors = self.predecessors(block);
        if predecessors.len() == 1 {
            let pred = func.layout.inst_block(predecessors[0]).unwrap();
            self.ssa_blocks[block].single_predecessor = PackedOption::from(pred);
        }

        // Note that begin_predecessors_lookup requires visiting these variables in the same order
        // that they were defined by find_var, because it appends arguments to the jump instructions
        // in all the predecessor blocks one variable at a time.
        for idx in 0..ssa_params {
            let var = undef_variables.get(idx, &self.variable_pool).unwrap();

            // We need the temporary Value that was assigned to this Variable. If that Value shows
            // up as a result from any of our predecessors, then it never got assigned on the loop
            // through that block. We get the value from the next block param, where it was first
            // allocated in find_var.
            let block_params = func.block_params(block);

            // On each iteration through this loop, there are (ssa_params - idx) undefined variables
            // left to process. Previous iterations through the loop may have removed earlier block
            // parameters, but the last (ssa_params - idx) block parameters always correspond to the
            // remaining undefined variables. So index from the end of the current block params.
            let val = block_params[block_params.len() - (ssa_params - idx)];

            debug_assert!(self.calls.is_empty());
            debug_assert!(self.results.is_empty());
            // self.side_effects may be non-empty here so that callers can
            // accumulate side effects over multiple calls.
            self.begin_predecessors_lookup(val, block);
            self.run_state_machine(func, var, func.value_type(val));
        }

        undef_variables.clear(&mut self.variable_pool);
    }

    /// Given the local SSA Value of a Variable in a Block, perform a recursive lookup on
    /// predecessors to determine if it is redundant with another Value earlier in the CFG.
    ///
    /// If such a Value exists and is redundant, the local Value is replaced by the
    /// corresponding non-local Value. If the original Value was a Block parameter,
    /// the parameter may be removed if redundant. Parameters are placed eagerly by callers
    /// to avoid infinite loops when looking up a Value for a Block that is in a CFG loop.
    ///
    /// Doing this lookup for each Value in each Block preserves SSA form during construction.
    ///
    /// ## Arguments
    ///
    /// `sentinel` is a dummy Block parameter inserted by `use_var_nonlocal()`.
    /// Its purpose is to allow detection of CFG cycles while traversing predecessors.
    fn begin_predecessors_lookup(&mut self, sentinel: Value, dest_block: Block) {
        self.calls
            .push(Call::FinishPredecessorsLookup(sentinel, dest_block));
        // Iterate over the predecessors.
        self.calls.extend(
            self.ssa_blocks[dest_block]
                .predecessors
                .as_slice(&self.inst_pool)
                .iter()
                .rev()
                .copied()
                .map(Call::UseVar),
        );
    }

    /// Examine the values from the predecessors and compute a result value, creating
    /// block parameters as needed.
    fn finish_predecessors_lookup(
        &mut self,
        func: &mut SsaFunc,
        sentinel: Value,
        dest_block: Block,
    ) -> Value {
        // Determine how many predecessors are yielding unique, non-temporary Values. If a variable
        // is live and unmodified across several control-flow join points, earlier blocks will
        // introduce aliases for that variable's definition, so we resolve aliases eagerly here to
        // ensure that we can tell when the same definition has reached this block via multiple
        // paths. Doing so also detects cyclic references to the sentinel, which can occur in
        // unreachable code.
        let num_predecessors = self.predecessors(dest_block).len();
        // When this `Drain` is dropped, these elements will get truncated.
        let results = self.results.drain(self.results.len() - num_predecessors..);

        let pred_val = {
            let mut iter = results
                .as_slice()
                .iter()
                .map(|&val| func.resolve_aliases(val))
                .filter(|&val| val != sentinel);
            if let Some(val) = iter.next() {
                // This variable has at least one non-temporary definition. If they're all the same
                // value, we can remove the block parameter and reference that value instead.
                if iter.all(|other| other == val) {
                    Some(val)
                } else {
                    None
                }
            } else {
                // The variable is used but never defined before. This is an irregularity in the
                // code, but rather than throwing an error we silently initialize the variable to
                // 0. This will have no effect since this situation happens in unreachable code.
                if !func.layout.is_block_inserted(dest_block) {
                    func.layout.append_block(dest_block);
                }
                self.side_effects
                    .instructions_added_to_blocks
                    .push(dest_block);

                fn insert_inst_at(block: Block, data: InstructionData, func: &mut SsaFunc) -> Inst {
                    let inst = func.dfg.make_inst(data);
                    let srcloc = func.base_srcloc();  // @KindaHack?

                    let cfg = &mut func.cfg;
                    cfg.blocks[block].insts.push(inst, &mut cfg.block_insts_pool);

                    func.srclocs.insert(inst, srcloc);
                    func.layout.inst_blocks.insert(inst, block);

                    inst
                }

                fn make_inst_result(inst: Inst, ty: Type, result_idx: u8, func: &mut SsaFunc) -> Value {
                    let value = func.dfg.make_value(ValueData {
                        ty,
                        def: ValueDef::Inst { inst, result_idx },
                    });

                    let results = &mut func.dfg.inst_results;

                    if let Some(results) = results.get_mut(inst) {
                        results.push(value);
                    } else {
                        results.insert(SparseInstResults {
                            key: inst,
                            value: smallvec![value]
                        });
                    }

                    value
                }

                // @Cleanup
                let ty = func.value_type(sentinel);
                let zero = if ty.is_int() {
                    let inst = insert_inst_at(dest_block, InstructionData::IConst { value: 0   }, func);
                    make_inst_result(inst, ty, 0, func)
                } else {
                    let inst = insert_inst_at(dest_block, InstructionData::FConst { value: 0.0 }, func);
                    make_inst_result(inst, ty, 0, func)
                };

                Some(zero)
            }
        };

        if let Some(pred_val) = pred_val {
            // Here all the predecessors use a single value to represent our variable
            // so we don't need to have it as a block argument.
            // We need to replace all the occurrences of val with pred_val but since
            // we can't afford a re-writing pass right now we just declare an alias.
            func.remove_block_param(sentinel);
            func.change_to_alias(sentinel, pred_val);
            pred_val
        } else {
            // There is disagreement in the predecessors on which value to use so we have
            // to keep the block argument.
            let mut preds = self.ssa_blocks[dest_block].predecessors;
            let dfg = &mut func.dfg;
            for (idx, &val) in results.as_slice().iter().enumerate() {
                let pred = preds.get_mut(idx, &mut self.inst_pool).unwrap();
                let branch = *pred;

                match &mut dfg.insts[branch] {  // @Hack
                    InstructionData::Branch { destinations, args, .. } => {
                        if destinations[0] == dest_block {
                            args[0].push(val, &mut func.values_pool);
                        } else if destinations[1] == dest_block {
                            args[1].push(val, &mut func.values_pool);
                        }
                    }

                    InstructionData::Jump { destination, args } => {
                        if *destination == dest_block {
                            args.push(val, &mut func.values_pool);
                        }
                    }

                    _ => {
                        panic!("you have declared a non-branch instruction as a predecessor to a block!");
                    }
                }
            }
            sentinel
        }
    }

    /// Returns the list of `Block`s that have been declared as predecessors of the argument.
    fn predecessors(&self, block: Block) -> &[Inst] {
        self.ssa_blocks[block]
            .predecessors
            .as_slice(&self.inst_pool)
    }

    /// Returns whether the given Block has any predecessor or not.
    pub fn has_any_predecessors(&self, block: Block) -> bool {
        !self.predecessors(block).is_empty()
    }

    /// Returns `true` if and only if `seal_block` has been called on the argument.
    pub fn is_sealed(&self, block: Block) -> bool {
        matches!(self.ssa_blocks[block].sealed, Sealed::Yes)
    }

    /// The main algorithm is naturally recursive: when there's a `use_var` in a
    /// block with no corresponding local defs, it recurses and performs a
    /// `use_var` in each predecessor. To avoid risking running out of callstack
    /// space, we keep an explicit stack and use a small state machine rather
    /// than literal recursion.
    fn run_state_machine(&mut self, func: &mut SsaFunc, var: Variable, ty: Type) -> Value {
        // Process the calls scheduled in `self.calls` until it is empty.
        while let Some(call) = self.calls.pop() {
            match call {
                Call::UseVar(branch) => {
                    let block = func.layout.inst_block(branch).unwrap();
                    self.use_var_nonlocal(func, var, ty, block);
                }
                Call::FinishPredecessorsLookup(sentinel, dest_block) => {
                    let val = self.finish_predecessors_lookup(func, sentinel, dest_block);
                    self.results.push(val);
                }
            }
        }
        debug_assert_eq!(self.results.len(), 1);
        self.results.pop().unwrap()
    }
}

///////////////////////////////////////////////////////////////////////
// Analysis & Pretty Printing
//

impl SsaFunc {
    pub fn fmt_block(&self, f: &mut dyn fmt::Write, block_id: Block) -> fmt::Result {
        let block_data = &self.cfg.blocks[block_id];
        write!(f, "{block_id}:")?;
        if !block_data.params.is_empty() {
            write!(
                f,
                "({})",
                block_data
                    .params
                    .as_slice(&self.values_pool)
                    .iter()
                    .map(|v| self.fmt_value(*v))
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }
        if let Some(preds) = self.cfg.predecessors.get(block_id) {
            write!(
                f,
                "  ; preds: {}",
                preds.value
                    .as_slice(&self.cfg.blocks_pool)
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }
        writeln!(f)?;
        for &inst_id in block_data.insts.as_slice(&self.cfg.block_insts_pool) {
            self.fmt_inst(f, inst_id)?;
            writeln!(f)?;
        }
        Ok(())
    }

    pub fn fmt_inst(&self, f: &mut dyn fmt::Write, inst_id: Inst) -> fmt::Result {
        let inst = &self.dfg.insts[inst_id];
        let mut s = String::new();
        if let Some(results) = self.dfg.inst_results.get(inst_id)
            && !results.is_empty()
        {
            s.push_str(
                &results
                    .iter()
                    .map(|r| self.fmt_value(*r))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            s.push_str(" = ");
        }
        #[allow(clippy::format_push_string)]
        match inst {
            InstructionData::Binary {
                binop: opcode,
                args,
            } => s.push_str(&format!(
                "{:?} {}, {}",
                opcode,
                self.fmt_value(args[0]),
                self.fmt_value(args[1])
            )),
            InstructionData::Icmp { code, args } => s.push_str(&format!(
                "icmp_{:?} {}, {}",
                code,
                self.fmt_value(args[0]),
                self.fmt_value(args[1])
            )),
            InstructionData::Fcmp { code, args } => s.push_str(&format!(
                "fcmp_{:?} {}, {}",
                code,
                self.fmt_value(args[0]),
                self.fmt_value(args[1])
            )),
            InstructionData::Unary { unop, arg } => {
                s.push_str(&format!("{:?} {}", unop, self.fmt_value(*arg)));
            }
            InstructionData::IConst { value } => s.push_str(&format!("iconst {value}")),
            InstructionData::FConst { value } => s.push_str(&format!("fconst {value}")),
            InstructionData::Jump { destination, args } => s.push_str(&format!(
                "jump {}({})",
                destination,
                args.as_slice(&self.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::Branch {
                destinations,
                arg,
                args,
            } => s.push_str(&format!(
                "brif {}, {}({}), {}({})",
                self.fmt_value(*arg),
                destinations[0],
                destinations[1],
                args[0].as_slice(&self.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", "),
                args[1].as_slice(&self.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::Call { func_id, args, .. } => s.push_str(&format!(
                "call {} ({})",
                func_id,
                args.as_slice(&self.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::CallHook { hook_id, args } => s.push_str(&format!(
                "call_hook {} ({})",
                hook_id,
                args.as_slice(&self.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::CallExt { func_id, args } => s.push_str(&format!(
                "call_ext {} ({})",
                func_id,
                args.as_slice(&self.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::CallIndirect { callee, args } => s.push_str(&format!(
                "call_indirect {} ({})",
                self.fmt_value(*callee),
                args.as_slice(&self.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::Return { args } => s.push_str(&format!(
                "return {}",
                args.as_slice(&self.values_pool)
                    .iter()
                    .map(|v| self.fmt_value(*v))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::StackAddr { slot } => s.push_str(&format!("stack_addr {slot}")),
            InstructionData::StackLoad { slot } => s.push_str(&format!("stack_load {slot}")),
            InstructionData::StackStore { slot, arg } => {
                s.push_str(&format!("stack_store {}, {}", slot, self.fmt_value(*arg)));
            }
            InstructionData::LoadNoOffset { ty, addr } => s.push_str(&format!(
                "load_no_offset {}:{:?}",
                self.fmt_value(*addr),
                ty
            )),
            InstructionData::StoreNoOffset { args } => s.push_str(&format!(
                "store_no_offset {}, {}",
                self.fmt_value(args[0]),
                self.fmt_value(args[1])
            )),
            InstructionData::DataAddr { data_id } => s.push_str(&format!("data_addr {data_id}")),
            InstructionData::Unreachable => s.push_str("unreachable"),
            InstructionData::Nop => s.push_str("nop"),
        }

        write!(f, "  {s:<70}")?;

        if let Some(comment) = self.comments.get(inst_id) {
            let comment = self.get_string(*comment);
            write!(f, "; {comment}")?;
        }

        Ok(())
    }

    #[must_use]
    pub fn fmt_value(&self, val: Value) -> String {
        let data = &self.dfg.values[val];
        format!("v{}:{}", val.index(), format!("{:?}", data.ty).to_lowercase())
    }
}

impl fmt::Display for SsaFunc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "function {}({}) -> {}",
            self.name(),
            self.signature
                .params
                .iter()
                .map(|t| format!("{t:?}"))
                .collect::<Vec<_>>()
                .join(", "),
            self.signature
                .returns
                .iter()
                .map(|t| format!("{t:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        for (slot_id, slot) in &self.stack_slots {
            writeln!(f, "  StackSlot{}: {:?}, size={}", slot_id.as_u32(), slot.ty, slot.size)?;
        }
        if let Some(entry) = self.layout.block_entry.expand() {
            let mut visited = IntSet::with_capacity_and_hasher(
                self.cfg.blocks.len(),
                nohash_hasher::BuildNoHashHasher::default()
            );
            let mut worklist = vec![entry];
            while let Some(block_id) = worklist.pop() {
                if !visited.insert(block_id) {
                    continue;
                }

                self.fmt_block(f, block_id)?;

                let block_data = &self.cfg.blocks[block_id];
                if let Some(last_inst_id) = block_data.insts.as_slice(&self.cfg.block_insts_pool).last() {
                    let inst_data = &self.dfg.insts[*last_inst_id];
                    match inst_data {
                        InstructionData::Jump { destination, .. } => worklist.push(*destination),
                        InstructionData::Branch { destinations, .. } => {
                            worklist.push(destinations[1]);
                            worklist.push(destinations[0]);
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }
}
