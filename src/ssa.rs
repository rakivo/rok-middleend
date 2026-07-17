#![allow(dead_code, unused)]

use crate::ctxhash::{CtxHashMap, NullCtx};
use crate::scoped_hash_map::ScopedHashMap;
use crate::with_comment;

use flow::BlockPredecessor;
use nohash_hasher::IntSet;
use rok_entity::packed_option::{PackedOption, ReservedValue};
use rok_entity::{EntityList, EntityRef, EntitySet, ListPool, PrimaryMap, SecondaryMap, SparseMap, sparse_pair};

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Type {
    U8, U16, U32, U64,
    I8, I16, I32, I64,
    F32, F64,
    Ptr, FuncPtr,
    INVALID
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

            Type::INVALID => unreachable!()
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

            Type::INVALID => unreachable!(),

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

            Type::INVALID => unreachable!(),
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
            Type::INVALID => unreachable!(),
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
            Type::INVALID => unreachable!(),
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

    /// User-defined stack maps.
    ///
    /// Not to be confused with the stack maps that `regalloc2` produces. These
    /// are defined by the user in `cranelift-frontend`. These will eventually
    /// replace the stack maps support in `regalloc2`, but in the name of
    /// incrementalism and avoiding gigantic PRs that completely overhaul
    /// Cranelift and Wasmtime at the same time, we are allowing them to live in
    /// parallel for the time being.
    user_stack_maps: BTreeMap<Inst, UserStackMapEntryVec>,

    pub values_pool: ListPool<Value>,

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

    /// Get an iterator over all values.
    pub fn values<'a>(&'a self) -> Values<'a> {
        Values {
            inner: self.values.iter(),
        }
    }

    /// Clear the list of result values from `inst`.
    ///
    /// This leaves `inst` without any result values. New result values can be created by calling
    /// `make_inst_results` or by using a `replace(inst)` builder.
    #[inline]
    pub fn clear_results(&mut self, inst: Inst) {
        if let Some(results) = self.inst_results.get_mut(inst) {
            results.value.clear();
        }
    }

    #[inline]
    #[must_use]
    pub fn inst_results(&self, inst: Inst) -> &[Value] {
        self.inst_results.get(inst).map_or(&[], |s| s.value.as_slice())
    }

    /// Returns an iterator yielding all values read and written by this instruction.
    #[inline]
    #[must_use]
    pub fn inst_values(&self, inst: Inst) -> InstValues<'_> {
        let inst_data = &self.insts[inst];
        let results = self.inst_results(inst);
        let args = inst_data.inst_args(&self.values_pool);

        InstValues {
            results: results.iter(),
            args,
        }
    }

    /// Construct a read-only visitor context for the values of this instruction.
    #[inline]
    #[must_use]
    pub fn inst_args(
        &self,
        inst: Inst,
    ) -> impl Iterator<Item = Value> {
        self.insts[inst].inst_args(&self.values_pool)
    }

    /// Construct a visitor context for the values of this instruction.
    #[inline]
    #[must_use]
    pub fn inst_args_mut(
        &mut self,
        inst: Inst,
    ) -> impl Iterator<Item = &mut Value> {
        self.insts[inst].inst_args_mut(&mut self.values_pool)
    }

    /// Check if a value reference is valid.
    pub fn value_is_valid(&self, v: Value) -> bool {
        self.values.is_valid(v)
    }

    /// Check whether a value is valid and not an alias.
    pub fn value_is_real(&self, value: Value) -> bool {
        // Deleted or unused values are also stored as aliases so this excludes
        // those as well.
        self.value_is_valid(value) && !matches!(self.values[value].def, ValueDef::Alias { .. })
    }

    /// Get the type of a value.
    pub fn value_type(&self, v: Value) -> Type {
        self.values[v].ty
    }

    /// Get the definition of a value.
    ///
    /// This is either the instruction that defined it or the Block that has the value as an
    /// parameter.
    pub fn value_def(&self, v: Value) -> ValueDef {
        match self.values[v].def {
            ValueDef::Alias { original, .. } => {
                // Make sure we only recurse one level. `resolve_aliases` has safeguards to
                // detect alias loops without overrunning the stack.
                self.value_def(self.resolve_aliases(original))
            }
            other => other
        }
    }

    /// Overwrite the instruction's value references with values from the iterator.
    /// NOTE: the iterator provided is expected to yield at least as many values as the instruction
    /// currently has.
    pub fn overwrite_inst_values<I>(&mut self, inst: Inst, mut values: I)
    where
        I: Iterator<Item = Value>,
    {
        self.insts[inst].map_values(
            &mut self.values_pool,
            |_| values.next().unwrap(),
        );
    }

    // /// Determine if `v` is an attached instruction result / block parameter.
    // ///
    // /// An attached value can't be attached to something else without first being detached.
    // ///
    // /// Value aliases are not considered to be attached to anything. Use `resolve_aliases()` to
    // /// determine if the original aliased value is attached.
    // pub fn value_is_attached(&self, v: Value) -> bool {
    //     match self.values[v].def {
    //         ValueDef::Inst { inst, result_idx } => Some(&v) == self.inst_results(inst).get(result_idx as usize),
    //         ValueDef::Param { block, param_idx } => Some(&v) == self.block_params(block).get(param_idx as usize),
    //         ValueDef::Alias { .. } => false,
    //     }
    // }

    /// Resolve all aliases among inst's arguments.
    ///
    /// For each argument of inst which is defined by an alias, replace the
    /// alias with the aliased value.
    pub fn resolve_aliases_in_arguments(&mut self, inst: Inst) {
        let inst_args_mut = self.insts[inst].inst_args_mut(&mut self.values_pool);
        for arg in inst_args_mut {
            let resolved = resolve_aliases(&self.values, *arg);
            if resolved != *arg {
                *arg = resolved;
            }
        }
    }

    /// Resolve value aliases.
    ///
    /// Find the original SSA value that `value` aliases.
    pub fn resolve_aliases(&self, value: Value) -> Value {
        resolve_aliases(&self.values, value)
    }

    /// Replace all uses of value aliases with their resolved values, and delete
    /// the aliases.
    pub fn resolve_all_aliases(&mut self) {
        let invalid_value = ValueData {
            ty: Type::INVALID,
            def: ValueDef::Alias {
                original: Value::reserved_value(),
            }
        };

        // Rewrite each chain of aliases. Update every alias along the chain
        // into an alias directly to the final value. Due to updating every
        // alias that it looks at, this loop runs in time linear in the number
        // of values.
        for mut src in self.values.keys() {
            let value_data = self.values[src];
            if value_data == invalid_value {
                continue;
            }

            if let ValueDef::Alias { mut original, .. } = value_data.def {
                // We don't use the type after this, we just need some place to
                // store the resolved aliases temporarily.
                let resolved = ValueData {
                    ty: Type::INVALID,
                    def: ValueDef::Alias {
                        original: resolve_aliases(&self.values, original),
                    }
                };
                // Walk the chain again, splatting the new alias everywhere.
                // resolve_aliases panics if there's an alias cycle, so we don't
                // need to guard against cycles here.
                loop {
                    self.values[src] = resolved;
                    src = original;
                    if let ValueDef::Alias { original: next, .. } = self.values[src].def {
                        original = next;
                    } else {
                        break;
                    }
                }
            }
        }

        // Now aliases don't point to other aliases, so we can replace any use
        // of an alias with the final value in constant time.

        // Rewrite InstructionData in `self.insts`.
        for inst in self.insts.values_mut() {
            inst.map_values(
                &mut self.values_pool,

                |arg| {
                    if let ValueDef::Alias { original, .. } = self.values[arg].def {
                        original
                    } else {
                        arg
                    }
                },
            );
        }

        // - `results` and block-params in `blocks` are not aliases, by
        //   definition.
        // - `dynamic_types` has no values.
        // - `value_lists` can only be accessed via references from elsewhere.
        // - `values` only has value references in aliases (which we've
        //   removed), and unions (but the egraph pass ensures there are no
        //   aliases before creating unions).

        // - `signatures` and `ext_funcs` have no values.

        if let Some(values_labels) = &mut self.values_labels {
            // Debug info is best-effort. If any is attached to value aliases,
            // just discard it.
            values_labels.retain(|&k, _| !matches!(self.values[k].def, ValueDef::Alias { .. }));

            // If debug-info says a value should have the same labels as another
            // value, then make sure that target is not a value alias.
            for value_label in values_labels.values_mut() {
                if let ValueLabelAssignments::Alias { value, .. } = value_label {
                    if let ValueDef::Alias { original, .. } = self.values[*value].def {
                        *value = original;
                    }
                }
            }
        }

        // - `constants` and `immediates` have no values.
        // - `jump_tables` is updated together with instruction-data above.

        // Delete all aliases now that there are no uses left.
        for value in self.values.values_mut() {
            if let ValueDef::Alias { .. } = value.def {
                *value = invalid_value;
            }
        }
    }

    /// Turn a value into an alias of another.
    ///
    /// Change the `dest` value to behave as an alias of `src`. This means that all uses of `dest`
    /// will behave as if they used that value `src`.
    ///
    /// The `dest` value can't be attached to an instruction or block.
    pub fn change_to_alias(&mut self, dest: Value, src: Value) {
        // debug_assert!(!self.value_is_attached(dest));

        // Try to create short alias chains by finding the original source value.
        // This also avoids the creation of loops.
        let original = self.resolve_aliases(src);
        debug_assert_ne!(
            dest, original,
            "Aliasing {dest} to {src} would create a loop"
        );
        let ty = self.value_type(original);
        debug_assert_eq!(
            self.value_type(dest),
            ty,
            "Aliasing {} to {} would change its type {:?} to {:?}",
            dest,
            src,
            self.value_type(dest),
            ty
        );
        debug_assert_ne!(ty, Type::INVALID);

        self.values[dest].def = ValueDef::Alias { original }.into();
        self.values[dest].ty = ty;
    }

    /// Replace the results of one instruction with aliases to the results of another.
    ///
    /// Change all the results of `dest_inst` to behave as aliases of
    /// corresponding results of `src_inst`, as if calling change_to_alias for
    /// each.
    ///
    /// After calling this instruction, `dest_inst` will have had its results
    /// cleared, so it likely needs to be removed from the graph.
    ///
    pub fn replace_with_aliases(&mut self, dest_inst: Inst, original_inst: Inst) {
        debug_assert_ne!(
            dest_inst, original_inst,
            "Replacing {dest_inst} with itself would create a loop"
        );

        let dest_results: SmallVec<[Value; 4]> = self.inst_results(dest_inst).into();
        let original_results: SmallVec<[Value; 4]> = self.inst_results(original_inst).into();

        debug_assert_eq!(
            dest_results.len(),
            original_results.len(),
            "Replacing {dest_inst} with {original_inst} would produce a different number of results."
        );

        for (&dest, original) in dest_results.iter().zip(original_results) {
            let ty = self.value_type(original);
            debug_assert_eq!(
                self.value_type(dest),
                ty,
                "Aliasing {} to {} would change its type {:?} to {:?}",
                dest,
                original,
                self.value_type(dest),
                ty
            );
            debug_assert_ne!(ty, Type::INVALID);

            self.values[dest] = ValueData {
                ty,
                def: ValueDef::Alias { original }
            };
        }

        self.clear_results(dest_inst);
    }

    /// Get the stack map entries associated with the given instruction.
    pub fn user_stack_map_entries(&self, inst: Inst) -> Option<&[UserStackMapEntry]> {
        self.user_stack_maps.get(&inst).map(|es| &**es)
    }

    /// Append a new stack map entry for the given call instruction.
    ///
    /// # Panics
    ///
    /// Panics if the given instruction is not a (non-tail) call instruction.
    pub fn append_user_stack_map_entry(&mut self, inst: Inst, entry: UserStackMapEntry) {
        assert!(self.insts[inst].is_safepoint());
        self.user_stack_maps.entry(inst).or_default().push(entry);
    }
}

/// Iterator over all Values in a DFG.
pub struct Values<'a> {
    inner: rok_entity::Iter<'a, Value, ValueData>,
}

/// Check for non-values.
fn valid_valuedata(data: ValueData) -> bool {
    if let ValueData {
        ty: Type::INVALID,
        def: ValueDef::Alias { original },
    } = data
    {
        if original == Value::reserved_value() {
            return false;
        }
    }
    true
}

impl<'a> Iterator for Values<'a> {
    type Item = Value;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .by_ref()
            .find(|kv| valid_valuedata(*kv.1))
            .map(|kv| kv.0)
    }
}


/// Resolve value aliases.
///
/// Find the original SSA value that `value` aliases, or None if an
/// alias cycle is detected.
fn maybe_resolve_aliases(
    values: &PrimaryMap<Value, ValueData>,
    value: Value,
) -> Option<Value> {
    let mut v = value;

    // Note that values may be empty here.
    for _ in 0..=values.len() {
        if let ValueDef::Alias { original } = values[v].def {
            v = original;
        } else {
            return Some(v);
        }
    }

    None
}

/// Resolve value aliases.
///
/// Find the original SSA value that `value` aliases.
fn resolve_aliases(values: &PrimaryMap<Value, ValueData>, value: Value) -> Value {
    if let Some(v) = maybe_resolve_aliases(values, value) {
        v
    } else {
        panic!("Value alias loop detected for {value}");
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
        let mut count = 0;
        for block in self.layout.blocks() {
            count += self.layout.block_insts(block).count();
        }
        count
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

    /// Checks that the specified block can be encoded as a basic block.
    ///
    /// On error, returns the first invalid instruction and an error message.
    pub fn is_block_basic(&self, block: Block) -> Result<(), (Inst, &'static str)> {
        let dfg = &self.dfg;
        let inst_iter = self.layout.block_insts(block);

        // Ignore all instructions prior to the first branch.
        let mut inst_iter = inst_iter.skip_while(|&inst| !dfg.insts[inst].is_branch());

        if let Some(_branch) = inst_iter.next() {
            if let Some(next) = inst_iter.next() {
                return Err((next, "post-terminator instruction"));
            }
        }

        Ok(())
    }

    /// Returns an iterator over the blocks succeeding the given block.
    pub fn block_successors(&self, block: Block) -> impl DoubleEndedIterator<Item = Block> + '_ {
        self.layout.last_inst(block).into_iter().flat_map(|inst| {
            self.dfg.insts[inst].branch_destination().iter().copied()
        })
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

    #[inline]
    #[must_use]
    pub fn instruction_data(&self, inst: Inst) -> &InstructionData {
        &self.dfg.insts[inst]
    }

    #[inline]
    #[must_use]
    pub fn inst_results(&self, inst: Inst) -> &[Value] {
        self.dfg.inst_results(inst)
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
        let param_idx = self.cfg.blocks[block].params.len(&self.dfg.values_pool) as u8;
        let val = self.dfg.make_value(ValueData { ty, def: ValueDef::Param { block, param_idx } });
        self.cfg.blocks[block].params.push(val, &mut self.dfg.values_pool);
        val
    }

    #[inline]
    #[must_use]
    pub fn block_params(&self, block: Block) -> &[Value] {
        self.cfg.blocks[block].params.as_slice(&self.dfg.values_pool)
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
        let idx = params.as_slice(&self.dfg.values_pool)
            .iter()
            .position(|&p| p == val)
            .expect("param missing from its own block's param list");

        params.remove(idx, &mut self.dfg.values_pool);

        // Indices after idx shifted down by one, renumber so `num` stays accurate
        let remaining: Vec<Value> = params.as_slice(&self.dfg.values_pool).to_vec();
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

type SequenceNumber = u32;

/// Initial stride assigned to new sequence numbers.
const MAJOR_STRIDE: SequenceNumber = 10;

/// Secondary stride used when renumbering locally.
const MINOR_STRIDE: SequenceNumber = 2;

/// Limit on the sequence number range we'll renumber locally. If this limit is exceeded, we'll
/// switch to a full block renumbering.
const LOCAL_LIMIT: SequenceNumber = 100 * MINOR_STRIDE;

/// Compute the midpoint between `a` and `b`.
/// Return `None` if the midpoint would be equal to either.
fn midpoint(a: SequenceNumber, b: SequenceNumber) -> Option<SequenceNumber> {
    debug_assert!(a < b);
    // Avoid integer overflow.
    let m = a + (b - a) / 2;
    if m > a { Some(m) } else { None }
}

/// The `Layout` struct determines the layout of blocks and instructions in a function. It does not
/// contain definitions of instructions or blocks, but depends on `Inst` and `Block` entity references
/// being defined elsewhere.
///
/// This data structure determines:
///
/// - The order of blocks in the function.
/// - Which block contains a given instruction.
/// - The order of instructions with a block.
///
/// While data dependencies are not recorded, instruction ordering does affect control
/// dependencies, so part of the semantics of the program are determined by the layout.
///
#[derive(Debug, Clone, Default)]
pub struct Layout {
    /// Linked list nodes for the layout order of blocks Forms a doubly linked list, terminated in
    /// both ends by `None`.
    blocks: SecondaryMap<Block, BlockNode>,

    /// Linked list nodes for the layout order of instructions. Forms a double linked list per block,
    /// terminated in both ends by `None`.
    insts: SecondaryMap<Inst, InstNode>,

    /// First block in the layout order, or `None` when no blocks have been laid out.
    first_block: Option<Block>,

    /// Last block in the layout order, or `None` when no blocks have been laid out.
    last_block: Option<Block>,
}

/// A single node in the linked-list of blocks.
// **Note:** Whenever you add new fields here, don't forget to update the custom serializer for `Layout` too.
#[derive(Clone, Debug, Default, PartialEq, Hash)]
struct BlockNode {
    prev: PackedOption<Block>,
    next: PackedOption<Block>,
    first_inst: PackedOption<Inst>,
    last_inst: PackedOption<Inst>,
    cold: bool,
}

/// Iterate over blocks in layout order. See [crate::ir::layout::Layout::blocks].
pub struct Blocks<'f> {
    layout: &'f Layout,
    next: Option<Block>,
}

impl<'f> Iterator for Blocks<'f> {
    type Item = Block;

    fn next(&mut self) -> Option<Block> {
        match self.next {
            Some(block) => {
                self.next = self.layout.next_block(block);
                Some(block)
            }
            None => None,
        }
    }
}

/// Use a layout reference in a for loop.
impl<'f> IntoIterator for &'f Layout {
    type Item = Block;
    type IntoIter = Blocks<'f>;

    fn into_iter(self) -> Blocks<'f> {
        self.blocks()
    }
}

/// A `ProgramPoint` represents a position in a function where the live range of an SSA value can
/// begin or end. It can be either:
///
/// 1. An instruction or
/// 2. A block header.
///
/// This corresponds more or less to the lines in the textual form of Cranelift IR.
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum ProgramPoint {
    /// An instruction in the function.
    Inst(Inst),
    /// A block header.
    Block(Block),
}

impl ProgramPoint {
    /// Get the instruction we know is inside.
    pub fn unwrap_inst(self) -> Inst {
        match self {
            Self::Inst(x) => x,
            Self::Block(x) => panic!("expected inst: {x}"),
        }
    }
}

impl From<Inst> for ProgramPoint {
    fn from(inst: Inst) -> Self {
        Self::Inst(inst)
    }
}

impl From<Block> for ProgramPoint {
    fn from(block: Block) -> Self {
        Self::Block(block)
    }
}

impl fmt::Display for ProgramPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Inst(x) => write!(f, "{x}"),
            Self::Block(x) => write!(f, "{x}"),
        }
    }
}

impl fmt::Debug for ProgramPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ProgramPoint({self})")
    }
}

/// Methods for arranging instructions.
///
/// An instruction starts out as *not inserted* in the layout. An instruction can be inserted into
/// a block at a given position.
impl Layout {
    /// Get the block containing `inst`, or `None` if `inst` is not inserted in the layout.
    pub fn inst_block(&self, inst: Inst) -> Option<Block> {
        self.insts[inst].block.into()
    }

    /// Get the block containing the program point `pp`. Panic if `pp` is not in the layout.
    pub fn pp_block(&self, pp: ProgramPoint) -> Block {
        match pp {
            ProgramPoint::Block(block) => block,
            ProgramPoint::Inst(inst) => self.inst_block(inst).expect("Program point not in layout"),
        }
    }

    /// Append `inst` to the end of `block`.
    pub fn append_inst(&mut self, inst: Inst, block: Block) {
        debug_assert_eq!(self.inst_block(inst), None);
        debug_assert!(
            self.is_block_inserted(block),
            "Cannot append instructions to block not in layout"
        );
        {
            let block_node = &mut self.blocks[block];
            {
                let inst_node = &mut self.insts[inst];
                inst_node.block = block.into();
                inst_node.prev = block_node.last_inst;
                debug_assert!(inst_node.next.is_none());
            }
            if block_node.first_inst.is_none() {
                block_node.first_inst = inst.into();
            } else {
                self.insts[block_node.last_inst.unwrap()].next = inst.into();
            }
            block_node.last_inst = inst.into();
        }
        self.assign_inst_seq(inst);
    }

    /// Fetch a block's first instruction.
    pub fn first_inst(&self, block: Block) -> Option<Inst> {
        self.blocks[block].first_inst.into()
    }

    /// Fetch a block's last instruction.
    pub fn last_inst(&self, block: Block) -> Option<Inst> {
        self.blocks[block].last_inst.into()
    }

    /// Fetch the instruction following `inst`.
    pub fn next_inst(&self, inst: Inst) -> Option<Inst> {
        self.insts[inst].next.expand()
    }

    /// Fetch the instruction preceding `inst`.
    pub fn prev_inst(&self, inst: Inst) -> Option<Inst> {
        self.insts[inst].prev.expand()
    }

    /// Insert `inst` before the instruction `before` in the same block.
    pub fn insert_inst(&mut self, inst: Inst, before: Inst) {
        debug_assert_eq!(self.inst_block(inst), None);
        let block = self
            .inst_block(before)
            .expect("Instruction before insertion point not in the layout");
        let after = self.insts[before].prev;
        {
            let inst_node = &mut self.insts[inst];
            inst_node.block = block.into();
            inst_node.next = before.into();
            inst_node.prev = after;
        }
        self.insts[before].prev = inst.into();
        match after.expand() {
            None => self.blocks[block].first_inst = inst.into(),
            Some(a) => self.insts[a].next = inst.into(),
        }
        self.assign_inst_seq(inst);
    }

    /// Remove `inst` from the layout.
    pub fn remove_inst(&mut self, inst: Inst) {
        let block = self.inst_block(inst).expect("Instruction already removed.");
        // Clear the `inst` node and extract links.
        let prev;
        let next;
        {
            let n = &mut self.insts[inst];
            prev = n.prev;
            next = n.next;
            n.block = None.into();
            n.prev = None.into();
            n.next = None.into();
        }
        // Fix up links to `inst`.
        match prev.expand() {
            None => self.blocks[block].first_inst = next,
            Some(p) => self.insts[p].next = next,
        }
        match next.expand() {
            None => self.blocks[block].last_inst = prev,
            Some(n) => self.insts[n].prev = prev,
        }
    }

    /// Iterate over the instructions in `block` in layout order.
    pub fn block_insts(&self, block: Block) -> Insts<'_> {
        Insts {
            layout: self,
            head: self.blocks[block].first_inst.into(),
            tail: self.blocks[block].last_inst.into(),
        }
    }

    /// Split the block containing `before` in two.
    ///
    /// Insert `new_block` after the old block and move `before` and the following instructions to
    /// `new_block`:
    ///
    /// ```text
    /// old_block:
    ///     i1
    ///     i2
    ///     i3 << before
    ///     i4
    /// ```
    /// becomes:
    ///
    /// ```text
    /// old_block:
    ///     i1
    ///     i2
    /// new_block:
    ///     i3 << before
    ///     i4
    /// ```
    pub fn split_block(&mut self, new_block: Block, before: Inst) {
        let old_block = self
            .inst_block(before)
            .expect("The `before` instruction must be in the layout");
        debug_assert!(!self.is_block_inserted(new_block));

        // Insert new_block after old_block.
        let next_block = self.blocks[old_block].next;
        let last_inst = self.blocks[old_block].last_inst;
        {
            let node = &mut self.blocks[new_block];
            node.prev = old_block.into();
            node.next = next_block;
            node.first_inst = before.into();
            node.last_inst = last_inst;
        }
        self.blocks[old_block].next = new_block.into();

        // Fix backwards link.
        if Some(old_block) == self.last_block {
            self.last_block = Some(new_block);
        } else {
            self.blocks[next_block.unwrap()].prev = new_block.into();
        }

        // Disconnect the instruction links.
        let prev_inst = self.insts[before].prev;
        self.insts[before].prev = None.into();
        self.blocks[old_block].last_inst = prev_inst;
        match prev_inst.expand() {
            None => self.blocks[old_block].first_inst = None.into(),
            Some(pi) => self.insts[pi].next = None.into(),
        }

        // Fix the instruction -> block pointers.
        let mut opt_i = Some(before);
        while let Some(i) = opt_i {
            debug_assert_eq!(self.insts[i].block.expand(), Some(old_block));
            self.insts[i].block = new_block.into();
            opt_i = self.insts[i].next.into();
        }
    }

    /// Assign a valid sequence number to `inst` such that the numbers are still monotonic. This may
    /// require renumbering.
    fn assign_inst_seq(&mut self, inst: Inst) {
        // Get the sequence number immediately before `inst`.
        let prev_seq = match self.insts[inst].prev.expand() {
            Some(prev_inst) => self.insts[prev_inst].seq,
            None => 0,
        };

        // Get the sequence number immediately following `inst`.
        let next_seq = if let Some(next_inst) = self.insts[inst].next.expand() {
            self.insts[next_inst].seq
        } else {
            // There is nothing after `inst`. We can just use a major stride.
            self.insts[inst].seq = prev_seq + MAJOR_STRIDE;
            return;
        };

        // Check if there is room between these sequence numbers.
        if let Some(seq) = midpoint(prev_seq, next_seq) {
            self.insts[inst].seq = seq;
        } else {
            // No available integers between `prev_seq` and `next_seq`. We have to renumber.
            self.renumber_insts(inst, prev_seq + MINOR_STRIDE, prev_seq + LOCAL_LIMIT);
        }
    }

    /// Renumber instructions starting from `inst` until the end of the block or until numbers catch
    /// up.
    ///
    /// If sequence numbers exceed `limit`, switch to a full block renumbering.
    fn renumber_insts(&mut self, inst: Inst, seq: SequenceNumber, limit: SequenceNumber) {
        let mut inst = inst;
        let mut seq = seq;

        loop {
            self.insts[inst].seq = seq;

            // Next instruction.
            inst = match self.insts[inst].next.expand() {
                None => return,
                Some(next) => next,
            };

            if seq < self.insts[inst].seq {
                // Sequence caught up.
                return;
            }

            if seq > limit {
                // We're pushing too many instructions in front of us.
                // Switch to a full block renumbering to make some space.
                self.full_block_renumber(
                    self.inst_block(inst)
                        .expect("inst must be inserted before assigning an seq"),
                );
                return;
            }

            seq += MINOR_STRIDE;
        }
    }

    /// Renumber all instructions in a block.
    ///
    /// This doesn't affect the position of anything, but it gives more room in the internal
    /// sequence numbers for inserting instructions later.
    fn full_block_renumber(&mut self, block: Block) {
        // let _tt = timing::layout_renumber();

        // Avoid 0 as this is reserved for the program point indicating the block itself
        let mut seq = MAJOR_STRIDE;
        let mut next_inst = self.blocks[block].first_inst.expand();
        while let Some(inst) = next_inst {
            self.insts[inst].seq = seq;
            seq += MAJOR_STRIDE;
            next_inst = self.insts[inst].next.expand();
        }

        // trace!("Renumbered {} program points", seq / MAJOR_STRIDE);
    }
}

impl Layout {
    /// Compare the program points `a` and `b` in the same block relative to this program order.
    ///
    /// Return `Less` if `a` appears in the program before `b`.
    ///
    /// This is declared as a generic such that it can be called with `Inst` and `Block` arguments
    /// directly. Depending on the implementation, there is a good chance performance will be
    /// improved for those cases where the type of either argument is known statically.
    pub fn pp_cmp<A, B>(&self, a: A, b: B) -> Ordering
    where
        A: Into<ProgramPoint>,
        B: Into<ProgramPoint>,
    {
        let a = a.into();
        let b = b.into();
        debug_assert_eq!(self.pp_block(a), self.pp_block(b));
        let a_seq = match a {
            ProgramPoint::Block(_block) => 0,
            ProgramPoint::Inst(inst) => self.insts[inst].seq,
        };
        let b_seq = match b {
            ProgramPoint::Block(_block) => 0,
            ProgramPoint::Inst(inst) => self.insts[inst].seq,
        };
        a_seq.cmp(&b_seq)
    }
}

/// Methods for laying out blocks.
///
/// An unknown block starts out as *not inserted* in the block layout. The layout is a linear order of
/// inserted blocks. Once a block has been inserted in the layout, instructions can be added. A block
/// can only be removed from the layout when it is empty.
///
/// Since every block must end with a terminator instruction which cannot fall through, the layout of
/// blocks do not affect the semantics of the program.
///
impl Layout {
    /// Returns the capacity of the `BlockData` map.
    pub fn block_capacity(&self) -> usize {
        self.blocks.capacity()
    }

    /// Is `block` currently part of the layout?
    pub fn is_block_inserted(&self, block: Block) -> bool {
        Some(block) == self.first_block || self.blocks[block].prev.is_some()
    }

    /// Insert `block` as the last block in the layout.
    #[track_caller]
    pub fn append_block(&mut self, block: Block) {
        debug_assert!(
            !self.is_block_inserted(block),
            "Cannot append block that is already in the layout"
        );
        {
            let node = &mut self.blocks[block];
            debug_assert!(node.first_inst.is_none() && node.last_inst.is_none());
            node.prev = self.last_block.into();
            node.next = None.into();
        }
        if let Some(last) = self.last_block {
            self.blocks[last].next = block.into();
        } else {
            self.first_block = Some(block);
        }
        self.last_block = Some(block);
    }

    /// Insert `block` in the layout before the existing block `before`.
    pub fn insert_block(&mut self, block: Block, before: Block) {
        debug_assert!(
            !self.is_block_inserted(block),
            "Cannot insert block that is already in the layout"
        );
        debug_assert!(
            self.is_block_inserted(before),
            "block Insertion point not in the layout"
        );
        let after = self.blocks[before].prev;
        {
            let node = &mut self.blocks[block];
            node.next = before.into();
            node.prev = after;
        }
        self.blocks[before].prev = block.into();
        match after.expand() {
            None => self.first_block = Some(block),
            Some(a) => self.blocks[a].next = block.into(),
        }
    }

    /// Insert `block` in the layout *after* the existing block `after`.
    pub fn insert_block_after(&mut self, block: Block, after: Block) {
        debug_assert!(
            !self.is_block_inserted(block),
            "Cannot insert block that is already in the layout"
        );
        debug_assert!(
            self.is_block_inserted(after),
            "block Insertion point not in the layout"
        );
        let before = self.blocks[after].next;
        {
            let node = &mut self.blocks[block];
            node.next = before;
            node.prev = after.into();
        }
        self.blocks[after].next = block.into();
        match before.expand() {
            None => self.last_block = Some(block),
            Some(b) => self.blocks[b].prev = block.into(),
        }
    }

    /// Remove `block` from the layout.
    pub fn remove_block(&mut self, block: Block) {
        debug_assert!(self.is_block_inserted(block), "block not in the layout");
        debug_assert!(self.first_inst(block).is_none(), "block must be empty.");

        // Clear the `block` node and extract links.
        let prev;
        let next;
        {
            let n = &mut self.blocks[block];
            prev = n.prev;
            next = n.next;
            n.prev = None.into();
            n.next = None.into();
        }
        // Fix up links to `block`.
        match prev.expand() {
            None => self.first_block = next.expand(),
            Some(p) => self.blocks[p].next = next,
        }
        match next.expand() {
            None => self.last_block = prev.expand(),
            Some(n) => self.blocks[n].prev = prev,
        }
    }

    /// Return an iterator over all blocks in layout order.
    pub fn blocks(&self) -> Blocks<'_> {
        Blocks {
            layout: self,
            next: self.first_block,
        }
    }

    /// Get the function's entry block.
    /// This is simply the first block in the layout order.
    pub fn entry_block(&self) -> Option<Block> {
        self.first_block
    }

    /// Get the last block in the layout.
    pub fn last_block(&self) -> Option<Block> {
        self.last_block
    }

    /// Get the block preceding `block` in the layout order.
    pub fn prev_block(&self, block: Block) -> Option<Block> {
        self.blocks[block].prev.expand()
    }

    /// Get the block following `block` in the layout order.
    pub fn next_block(&self, block: Block) -> Option<Block> {
        self.blocks[block].next.expand()
    }

    /// Mark a block as "cold".
    ///
    /// This will try to move it out of the ordinary path of execution
    /// when lowered to machine code.
    pub fn set_cold(&mut self, block: Block) {
        self.blocks[block].cold = true;
    }

    /// Is the given block cold?
    pub fn is_cold(&self, block: Block) -> bool {
        self.blocks[block].cold
    }
}

#[derive(Clone, Debug, Default)]
struct InstNode {
    /// The Block containing this instruction, or `None` if the instruction is not yet inserted.
    block: PackedOption<Block>,
    prev: PackedOption<Inst>,
    next: PackedOption<Inst>,
    seq: SequenceNumber,
}

impl PartialEq for InstNode {
    fn eq(&self, other: &Self) -> bool {
        // Ignore the sequence number as it is an optimization used by pp_cmp and may be different
        // even for equivalent layouts.
        self.block == other.block && self.prev == other.prev && self.next == other.next
    }
}

impl core::hash::Hash for InstNode {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Ignore the sequence number as it is an optimization used by pp_cmp and may be different
        // even for equivalent layouts.
        self.block.hash(state);
        self.prev.hash(state);
        self.next.hash(state);
    }
}

/// Iterate over instructions in a block in layout order. See `Layout::block_insts()`.
pub struct Insts<'f> {
    layout: &'f Layout,
    head: Option<Inst>,
    tail: Option<Inst>,
}

impl<'f> Iterator for Insts<'f> {
    type Item = Inst;

    fn next(&mut self) -> Option<Inst> {
        let rval = self.head;
        if let Some(inst) = rval {
            if self.head == self.tail {
                self.head = None;
                self.tail = None;
            } else {
                self.head = self.layout.insts[inst].next.into();
            }
        }
        rval
    }
}

impl<'f> DoubleEndedIterator for Insts<'f> {
    fn next_back(&mut self) -> Option<Inst> {
        let rval = self.tail;
        if let Some(inst) = rval {
            if self.head == self.tail {
                self.head = None;
                self.tail = None;
            } else {
                self.tail = self.layout.insts[inst].prev.into();
            }
        }
        rval
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Intrinsic {
    Memcmp,
    Memcpy,
    Memset,
}

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
    CallIntrinsic { callee: Intrinsic, args: EntityList<Value>, },
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
        use Intrinsic::*;

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

            Self::CallIntrinsic { callee: Memcmp | Memcpy | Memset, .. } => 8,

            Self::CallHook { .. } | Self::Unreachable | Self::Nop => 0,
        }
    }

    #[inline]
    #[must_use]
    pub fn branch_destination(&self) -> &[Block] {
        match self {
            Self::Jump { destination, .. } => std::slice::from_ref(destination),
            Self::Branch { destinations, .. } => destinations,
            _ => &[]
        }
    }

    /// Returns an iterator over all input `Value`s used by this instruction.
    pub fn inst_args<'a>(&'a self, pool: &'a ListPool<Value>) -> InstArgs<'a> {
        match self {
            // Instructions with 0 arguments
            InstructionData::Unreachable
            | InstructionData::Nop
            | InstructionData::IConst { .. }
            | InstructionData::FConst { .. }
            | InstructionData::StackLoad { .. }
            | InstructionData::StackAddr { .. }
            | InstructionData::DataAddr { .. } => InstArgs::Empty,

            // Instructions with 1 argument
            InstructionData::Unary { arg, .. }
            | InstructionData::StackStore { arg, .. }
            | InstructionData::LoadNoOffset { addr: arg, .. } => {
                InstArgs::One { val: *arg, done: false }
            }

            // Instructions with 2 arguments
            InstructionData::Binary { args, .. }
            | InstructionData::Icmp { args, .. }
            | InstructionData::Fcmp { args, .. }
            | InstructionData::StoreNoOffset { args, .. } => {
                InstArgs::Two { vals: *args, index: 0 }
            }

            // Instructions with a single list of arguments
            InstructionData::CallHook { args, .. }
            | InstructionData::Jump { args, .. }
            | InstructionData::Call { args, .. }
            | InstructionData::CallIntrinsic { args, .. }
            | InstructionData::CallExt { args, .. }
            | InstructionData::Return { args, .. } => {
                InstArgs::Slice { slice: args.as_slice(pool), index: 0 }
            }

            // Instruction with 1 argument + a list of arguments
            InstructionData::CallIndirect { callee, args } => {
                InstArgs::ValueAndSlice {
                    val: *callee,
                    val_done: false,
                    slice: args.as_slice(pool),
                    slice_index: 0,
                }
            }

            // Instruction with 1 argument + two separate lists of arguments
            InstructionData::Branch { args, arg, .. } => {
                InstArgs::Branch {
                    cond: *arg,
                    cond_done: false,
                    then_slice: args[0].as_slice(pool),
                    then_index: 0,
                    else_slice: args[1].as_slice(pool),
                    else_index: 0,
                }
            }
        }
    }

    pub fn inst_args_mut<'a>(&'a mut self, pool: &'a mut ListPool<Value>) -> InstArgsMut<'a> {
        match self {
            // Instructions with 0 arguments
            InstructionData::Unreachable
            | InstructionData::Nop
            | InstructionData::IConst { .. }
            | InstructionData::FConst { .. }
            | InstructionData::StackLoad { .. }
            | InstructionData::StackAddr { .. }
            | InstructionData::DataAddr { .. } => InstArgsMut::Empty,

            // Instructions with 1 argument
            InstructionData::Unary { arg, .. }
            | InstructionData::StackStore { arg, .. }
            | InstructionData::LoadNoOffset { addr: arg, .. } => {
                InstArgsMut::One(Some(arg))
            }

            // Instructions with 2 arguments
            InstructionData::Binary { args, .. }
            | InstructionData::Icmp { args, .. }
            | InstructionData::Fcmp { args, .. }
            | InstructionData::StoreNoOffset { args, .. } => {
                InstArgsMut::Slice(&mut args[..])
            }

            // Instructions with a single list of arguments
            InstructionData::CallHook { args, .. }
            | InstructionData::Jump { args, .. }
            | InstructionData::Call { args, .. }
            | InstructionData::CallIntrinsic { args, .. }
            | InstructionData::CallExt { args, .. }
            | InstructionData::Return { args, .. } => {
                InstArgsMut::Slice(args.as_mut_slice(pool))
            }

            // Instruction with 1 argument + a list of arguments
            InstructionData::CallIndirect { callee, args } => {
                InstArgsMut::ValueAndSlice {
                    val: Some(callee),
                    slice: args.as_mut_slice(pool),
                }
            }

            // Instruction with 1 argument + two separate lists of arguments
            InstructionData::Branch { args, arg, .. } => {
                let [then_list, else_list] = args;

                // SAFETY: `then_list` and `else_list` represent disjoint allocations within
                // the ListPool. Since the borrow checker locks the entire pool on the first
                // call, we cast through a raw pointer to obtain both slices simultaneously.
                let pool_ptr = pool as *mut ListPool<Value>;

                InstArgsMut::Branch {
                    cond: Some(arg),
                    then_slice: then_list.as_mut_slice(unsafe { &mut *pool_ptr }),
                    else_slice: else_list.as_mut_slice(unsafe { &mut *pool_ptr }),
                }
            }
        }
    }

    /// Rewrites all input `Value`s in this instruction using the provided mapping function.
    pub fn map_values<F>(&mut self, pool: &mut ListPool<Value>, mut map_fn: F)
    where
        F: FnMut(Value) -> Value,
    {
        match self {
            // Instructions with 0 arguments (Nothing to map)
            InstructionData::Unreachable
            | InstructionData::Nop
            | InstructionData::IConst { .. }
            | InstructionData::FConst { .. }
            | InstructionData::StackLoad { .. }
            | InstructionData::StackAddr { .. }
            | InstructionData::DataAddr { .. } => {}

            // Instructions with 1 inline argument
            InstructionData::Unary { arg, .. }
            | InstructionData::StackStore { arg, .. }
            | InstructionData::LoadNoOffset { addr: arg, .. } => {
                *arg = map_fn(*arg);
            }

            // Instructions with 2 inline arguments
            InstructionData::Binary { args, .. }
            | InstructionData::Icmp { args, .. }
            | InstructionData::Fcmp { args, .. }
            | InstructionData::StoreNoOffset { args, .. } => {
                args[0] = map_fn(args[0]);
                args[1] = map_fn(args[1]);
            }

            // Instructions with a single EntityList of arguments
            InstructionData::CallHook { args, .. }
            | InstructionData::Jump { args, .. }
            | InstructionData::Call { args, .. }
            | InstructionData::CallIntrinsic { args, .. }
            | InstructionData::CallExt { args, .. }
            | InstructionData::Return { args, .. } => {
                // Mutate the values directly inside the pool
                for val in args.as_mut_slice(pool) {
                    *val = map_fn(*val);
                }
            }

            // Instruction with 1 inline argument + an EntityList
            InstructionData::CallIndirect { callee, args } => {
                *callee = map_fn(*callee);
                for val in args.as_mut_slice(pool) {
                    *val = map_fn(*val);
                }
            }

            // Instruction with 1 inline argument + two separate EntityLists
            InstructionData::Branch { args, arg, .. } => {
                *arg = map_fn(*arg);

                // Rust's borrow checker allows this sequential mutation
                // because the mutable borrow of `pool` ends after each loop.
                for val in args[0].as_mut_slice(pool) {
                    *val = map_fn(*val);
                }
                for val in args[1].as_mut_slice(pool) {
                    *val = map_fn(*val);
                }
            }
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

    #[inline]
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        matches! {
            self,
            Self::Jump { .. }   |
            Self::Branch { .. }
        }
    }

    #[inline]
    #[must_use]
    pub const fn is_safepoint(&self) -> bool {
        !matches! {
            self,
            Self::Call { .. }   |
            Self::CallIndirect { .. }   |
            Self::CallHook { .. }   |
            Self::CallExt { .. }   |
            Self::Return { .. }
        }
    }
}

pub struct InstValues<'a> {
    results: std::slice::Iter<'a, Value>,
    args: InstArgs<'a>,
}

impl<'a> Iterator for InstValues<'a> {
    type Item = Value;

    fn next(&mut self) -> Option<Self::Item> {
        // 1. Yield all results (outputs) first
        if let Some(&res) = self.results.next() {
            return Some(res);
        }

        // 2. Once results are empty, yield arguments (inputs)
        self.args.next()
    }
}

pub enum InstArgsMut<'a> {
    Empty,
    One(Option<&'a mut Value>),
    Slice(&'a mut [Value]),
    ValueAndSlice {
        val: Option<&'a mut Value>,
        slice: &'a mut [Value],
    },
    Branch {
        cond: Option<&'a mut Value>,
        then_slice: &'a mut [Value],
        else_slice: &'a mut [Value],
    },
}

impl<'a> Iterator for InstArgsMut<'a> {
    type Item = &'a mut Value;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            InstArgsMut::Empty => None,

            InstArgsMut::One(val) => val.take(),

            InstArgsMut::Slice(slice) => {
                // std::mem::take replaces the active slice with an empty one temporarily
                let current_slice = std::mem::take(slice);
                let (first, rest) = current_slice.split_first_mut()?;
                *slice = rest; // Put the remaining slice back
                Some(first)
            }

            InstArgsMut::ValueAndSlice { val, slice } => {
                if let Some(v) = val.take() {
                    return Some(v);
                }
                let current_slice = std::mem::take(slice);
                let (first, rest) = current_slice.split_first_mut()?;
                *slice = rest;
                Some(first)
            }

            InstArgsMut::Branch { cond, then_slice, else_slice } => {
                if let Some(c) = cond.take() {
                    return Some(c);
                }
                if !then_slice.is_empty() {
                    let current_slice = std::mem::take(then_slice);
                    let (first, rest) = current_slice.split_first_mut()?;
                    *then_slice = rest;
                    return Some(first);
                }
                let current_slice = std::mem::take(else_slice);
                let (first, rest) = current_slice.split_first_mut()?;
                *else_slice = rest;
                Some(first)
            }
        }
    }
}

/// A zero-allocation iterator over the argument values of an instruction.
pub enum InstArgs<'a> {
    Empty,
    One {
        val: Value,
        done: bool,
    },
    Two {
        vals: [Value; 2],
        index: usize,
    },
    Slice {
        slice: &'a [Value],
        index: usize,
    },
    ValueAndSlice {
        val: Value,
        val_done: bool,
        slice: &'a [Value],
        slice_index: usize,
    },
    Branch {
        cond: Value,
        cond_done: bool,
        then_slice: &'a [Value],
        then_index: usize,
        else_slice: &'a [Value],
        else_index: usize,
    },
}

impl<'a> Iterator for InstArgs<'a> {
    type Item = Value;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            InstArgs::Empty => None,
            InstArgs::One { val, done } => {
                if !*done {
                    *done = true;
                    Some(*val)
                } else {
                    None
                }
            }
            InstArgs::Two { vals, index } => {
                if *index < 2 {
                    let val = vals[*index];
                    *index += 1;
                    Some(val)
                } else {
                    None
                }
            }
            InstArgs::Slice { slice, index } => {
                if *index < slice.len() {
                    let val = slice[*index];
                    *index += 1;
                    Some(val)
                } else {
                    None
                }
            }
            InstArgs::ValueAndSlice { val, val_done, slice, slice_index } => {
                if !*val_done {
                    *val_done = true;
                    Some(*val)
                } else if *slice_index < slice.len() {
                    let v = slice[*slice_index];
                    *slice_index += 1;
                    Some(v)
                } else {
                    None
                }
            }
            InstArgs::Branch { cond, cond_done, then_slice, then_index, else_slice, else_index } => {
                if !*cond_done {
                    *cond_done = true;
                    Some(*cond)
                } else if *then_index < then_slice.len() {
                    let v = then_slice[*then_index];
                    *then_index += 1;
                    Some(v)
                } else if *else_index < else_slice.len() {
                    let v = else_slice[*else_index];
                    *else_index += 1;
                    Some(v)
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
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

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum FloatCC {
    Equal,
    NotEqual,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
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

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ValueData {
    pub ty: Type,
    pub def: ValueDef,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ValueDef {
    Inst { inst: Inst, result_idx: u8 },
    Param { block: Block, param_idx: u8 },
    Alias { original: Value },
}

impl ValueDef {
    fn unwrap_inst(&self) -> Inst {
        if let Self::Inst { inst, .. } = self {
            *inst
        } else {
            unreachable!()
        }
    }
}

#[derive(Default)]
pub struct Module {
    pub funcs: PrimaryMap<FuncId, SsaFunc>,
    pub ext_funcs: PrimaryMap<ExtFuncId, ExtFunc>,

    pub _reused_func_ctx: FunctionBuilderContext,
    pub _reused_domtree:  DominatorTree,
    pub _reused_cfg:      flow::ControlFlowGraph,
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
        pub fn call_hook<T>(
            &self,
            hook_id: HookId,
            result_tys: &[Type],
            args: &[Value],
            ir_builder: &mut InstBuilder<'_, T>
        ) -> Inst where T: InstInserter {
            ir_builder.call_hook(result_tys, hook_id, args)
        }
    }

    with_comment! {
        ir_builder,
        call_ext_with_comment,
        #[inline]
        #[track_caller]
        pub fn call_ext<T>(
            &self,
            ext_func_id: ExtFuncId,
            args: &[Value],
            ir_builder: &mut InstBuilder<'_, T>
        ) -> Inst where T: InstInserter {
            let func = &self.ext_funcs[ext_func_id];
            let result_ty = &func.signature.returns;
            ir_builder.call_ext(result_ty, ext_func_id, args)
        }
    }

    with_comment! {
        ir_builder,
        call_with_comment,
        #[inline]
        #[track_caller]
        pub fn call<T>(
            &self,
            func_id: FuncId,
            args: &[Value],
            ir_builder: &mut InstBuilder<'_, T>
        ) -> Inst where T: InstInserter {
            let func = &self.funcs[func_id];
            let result_tys = &func.signature.returns;
            ir_builder.call(result_tys, func_id, args)
        }
    }

    with_comment! {
        ir_builder,
        call_abort_with_comment,
        #[inline]
        pub fn call_abort<T>(&mut self, ir_builder: &mut InstBuilder<'_, T>) where T: InstInserter {
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
    safepoints: SafepointSpiller,
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
            safepoints
        } = self;
        safepoints.clear();
        ssa.clear();
        status.clear();
        variables.clear();
        stack_map_values.clear();
        stack_map_vars.clear();
    }
}

impl<'a, 'long> FunctionBuilder<'long> {
    #[inline]
    pub fn ins(&'a mut self) -> InstBuilder<'a, Self> {
        InstBuilder { inserter: self }
    }
}

impl<'a> FuncCursor<'a> {
    #[inline]
    pub fn ins<'b>(&'b mut self) -> InstBuilder<'b, Self> {
        InstBuilder { inserter: self }
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
        let entry_block = if let Some(block) = func.layout.entry_block() {
            block
        } else {
            let block = func.cfg.blocks.push(BasicBlockData::default());
            func.layout.append_block(block);
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
        let block = self.func.cfg.blocks.push(BasicBlockData::default());
        self.func.layout.append_block(block);
        self.ssa.declare_block(block);
        block
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
        let param_idx_start = block_data.params.len(&self.func.dfg.values_pool);
        for (i, &ty) in types.iter().enumerate() {
            let value = self.func.dfg.make_value(ValueData {
                ty,
                def: ValueDef::Param {
                    block,
                    param_idx: (param_idx_start + i) as u8,
                },
            });
            block_data.params.push(value, &mut self.func.dfg.values_pool);
        }
        &block_data.params.as_slice(&self.func.dfg.values_pool)[param_idx_start..]
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
        // println!("try_use_var: {var:?} = {val:?}");
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
        // println!("try_def_var: {var:?} = {val:?}");

        let var_ty = *self
            .variables
            .get(var)
            .ok_or(DefVariableError::DefinedBeforeDeclared(var))?;
        let val_ty = self.func.value_type(val);
        if var_ty != val_ty && val_ty.bits() != var_ty.bits() {  // @KindaHack?
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

    pub fn finalize(&mut self, reused_domtree: &mut DominatorTree, reused_cfg: &mut flow::ControlFlowGraph) {
        // Check that all the `Block`s are filled and sealed.
        #[cfg(debug_assertions)]
        {
            for block in self.func_ctx.status.keys() {
                if !self.is_pristine(block) {
                    assert!(
                        self.func_ctx.ssa.is_sealed(block),
                        "FunctionBuilder finalized, but block {block} is not sealed",
                    );
                    assert!(
                        self.is_filled(block),
                        "FunctionBuilder finalized, but block {block} is not filled",
                    );
                }
            }
        }

        // In debug mode, check that all blocks are valid basic blocks.
        #[cfg(debug_assertions)]
        {
            // Iterate manually to provide more helpful error messages.
            for block in self.func_ctx.status.keys() {
                if let Err((inst, msg)) = self.func.is_block_basic(block) {
                    let mut inst_str = String::new();
                    self.func.fmt_inst(&mut inst_str, inst).unwrap();
                    panic!("{block} failed basic block invariants on {inst_str}: {msg}");
                }
            }
        }

        // Propagate the needs-stack-map bit from variables to each of their
        // associated values.
        for var in self.func_ctx.stack_map_vars.iter() {
            for val in self.func_ctx.ssa.values_for_var(var) {
                // println!("propagating needs-stack-map from {var:?} to {val:?}");
                debug_assert_eq!(self.func.dfg.value_type(val), self.func_ctx.variables[var]);
                self.func_ctx.stack_map_values.insert(val);
            }
        }

        // If we have any values that need inclusion in stack maps, then we need
        // to run our pass to spill those values to the stack at safepoints and
        // generate stack maps.
        if !self.func_ctx.stack_map_values.is_empty() {
            self.func_ctx
                .safepoints
                .run(&mut self.func, &self.func_ctx.stack_map_values);
        }

        reused_cfg.compute(self.func);
        reused_domtree.compute(self.func, reused_cfg);

        do_simple_gvn(self.func, reused_cfg, reused_domtree);
        do_simple_dce(self.func, reused_domtree);

        self.func.dfg.resolve_all_aliases();

        // Clear the state (but preserve the allocated buffers) in preparation
        // for translation another function.
        self.func_ctx.clear();
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

pub trait InstInserter {
    /// Get a shared reference to the underlying function.
    fn func(&self) -> &SsaFunc;

    /// Get a mutable reference to the underlying function.
    fn func_mut(&mut self) -> &mut SsaFunc;

    fn add_pred(&mut self, _block: Block, _inst: Inst) {}

    fn is_sealed(&self, _block: Block) -> bool { false }

    /// Create the instruction in the DFG, insert it into the Layout and CFG
    /// at the cursor's current location, and return its ID.
    fn insert_inst_data(&mut self, data: InstructionData) -> Inst;

    fn fill_current_block(&mut self);

    /// Get the block we are currently inserting into.
    fn current_block(&self) -> Block;
}

impl InstInserter for FunctionBuilder<'_> {
    #[inline]
    fn func(&self) -> &SsaFunc { self.func }

    #[inline]
    fn func_mut(&mut self) -> &mut SsaFunc { self.func }

    #[inline]
    fn add_pred(&mut self, block: Block, inst: Inst) {
        self.ssa.declare_block_predecessor(block, inst);
    }

    #[inline]
    fn is_sealed(&self, block: Block) -> bool {
        self.ssa.is_sealed(block)
    }

    #[inline]
    fn fill_current_block(&mut self) {
        self.fill_current_block();
    }

    #[inline]
    fn insert_inst_data(&mut self, data: InstructionData) -> Inst {
        let inst = self.func.dfg.make_inst(data);
        let block = self.cursor.current_block;
        let srcloc = self.cursor.current_srcloc;

        let cfg = &mut self.func.cfg;
        cfg.blocks[block].insts.push(inst, &mut cfg.block_insts_pool);

        self.func.srclocs.insert(inst, srcloc);
        self.func.layout.append_inst(inst, block);

        inst
    }

    #[inline]
    fn current_block(&self) -> Block {
        self.cursor.current_block
    }
}

pub enum CursorPosition {
    /// Not pointing anywhere.
    Nowhere,
    /// Pointing at an existing instruction.
    /// Insertions go *before* this instruction.
    At(Inst),
    /// Pointing before the top of a block. (Iteration doorway)
    Before(Block),
    /// Pointing after the end of a block. (Append mode)
    After(Block),
}

pub struct FuncCursor<'a> {
    pub func: &'a mut SsaFunc,
    pub pos: CursorPosition,
    pub srcloc: SourceLoc,
}

impl<'a> FuncCursor<'a> {
    pub fn new(func: &'a mut SsaFunc) -> Self {
        Self {
            srcloc: func.base_srcloc(),
            func,
            pos: CursorPosition::Nowhere,
        }
    }

    // Notice the return type is Self, which allows the chaining!
    pub fn at_inst(mut self, inst: Inst) -> Self {
        self.pos = CursorPosition::At(inst);
        self
    }

    pub fn after_inst(mut self, inst: Inst) -> Self {
        // To be "after" an instruction, we move to the next one,
        // or to the end of the block if it's the last one.
        if let Some(next) = self.func.layout.next_inst(inst) {
            self.pos = CursorPosition::At(next);
        } else {
            let block = self.func.layout.inst_block(inst)
                .expect("Instruction not in layout");
            self.pos = CursorPosition::After(block);
       }
        self
    }

    pub fn next_inst(&mut self) -> Option<Inst> {
        use CursorPosition::*;

        match self.pos {
            Nowhere | After(..) => None,
            At(inst) => {
                if let Some(next) = self.func.layout.next_inst(inst) {
                    self.pos = At(next);
                    Some(next)
                } else {
                    self.pos = After(
                        self.func.layout
                            .inst_block(inst)
                            .expect("current instruction removed?"),
                    );
                    None
                }
            }
            Before(block) => {
                if let Some(next) = self.func.layout.first_inst(block) {
                    self.pos = At(next);
                    Some(next)
                } else {
                    self.pos = After(block);
                    None
                }
            }
        }
    }

    /// Get the block corresponding to the current position.
    fn current_block(&self) -> Option<Block> {
        use CursorPosition::*;

        match self.pos {
            Nowhere => None,
            At(inst) => self.func.layout.inst_block(inst),
            Before(block) | After(block) => Some(block),
        }
    }

    /// Get the instruction corresponding to the current position, if any.
    fn current_inst(&self) -> Option<Inst> {
        use CursorPosition::*;

        match self.pos {
            At(inst) => Some(inst),
            _ => None,
        }
    }

    /// Remove the instruction under the cursor.
    ///
    /// The cursor is left pointing at the position following the current instruction.
    ///
    /// Return the instruction that was removed.
    fn remove_inst(&mut self) -> Inst {
        let inst = self.current_inst().expect("No instruction to remove");
        self.next_inst();
        self.func.layout.remove_inst(inst);
        inst
    }

    /// Move to the previous instruction in the same block and return it.
    ///
    /// - If the cursor was positioned after a block, go to the last instruction in that block.
    /// - If there are no more instructions in the block, go to the `Before(block)` position and return
    ///   `None`.
    /// - If the cursor wasn't pointing anywhere, keep doing that.
    ///
    /// This method will never move the cursor to a different block.
    ///
    /// # Examples
    ///
    /// The `prev_inst()` method is intended for iterating backwards over the instructions in an
    /// block like this:
    ///
    /// ```
    /// # use cranelift_codegen::ir::{Function, Block};
    /// # use cranelift_codegen::cursor::{Cursor, FuncCursor};
    /// fn edit_block(func: &mut Function, block: Block) {
    ///     let mut cursor = FuncCursor::new(func).at_bottom(block);
    ///     while let Some(inst) = cursor.prev_inst() {
    ///         // Edit instructions...
    ///     }
    /// }
    /// ```
    fn prev_inst(&mut self) -> Option<Inst> {
        use CursorPosition::*;

        match self.pos {
            Nowhere | Before(..) => None,
            At(inst) => {
                if let Some(prev) = self.func.layout.prev_inst(inst) {
                    self.pos = At(prev);
                    Some(prev)
                } else {
                    let pos = Before(
                        self.func.layout
                            .inst_block(inst)
                            .expect("current instruction removed?"),
                    );
                    self.pos = pos;
                    None
                }
            }
            After(block) => {
                if let Some(prev) = self.func.layout.last_inst(block) {
                    self.pos = At(prev);
                    Some(prev)
                } else {
                    self.pos = Before(block);
                    None
                }
            }
        }
    }

    /// Remove the instruction under the cursor.
    ///
    /// The cursor is left pointing at the position preceding the current instruction.
    ///
    /// Return the instruction that was removed.
    fn remove_inst_and_step_back(&mut self) -> Inst {
        let inst = self.current_inst().expect("No instruction to remove");
        self.prev_inst();
        self.func.layout.remove_inst(inst);
        inst
    }

    /// Go to a specific instruction which must be inserted in the layout.
    /// New instructions will be inserted before `inst`.
    fn goto_inst(&mut self, inst: Inst) {
        debug_assert!(self.func.layout.inst_block(inst).is_some());
        self.pos = CursorPosition::At(inst);
    }

    /// Go to the top of `block` which must be inserted into the layout.
    /// At this position, instructions cannot be inserted, but `next_inst()` will move to the first
    /// instruction in `block`.
    fn goto_top(&mut self, block: Block) {
        debug_assert!(self.func.layout.is_block_inserted(block));
        self.pos = CursorPosition::Before(block);
    }

    /// Go to the bottom of `block` which must be inserted into the layout.
    /// At this position, inserted instructions will be appended to `block`.
    fn goto_bottom(&mut self, block: Block) {
        debug_assert!(self.func.layout.is_block_inserted(block));
        self.pos = CursorPosition::After(block);
    }

    /// Rebuild this cursor positioned at the first insertion point for `block`.
    /// This differs from `at_first_inst` in that it doesn't assume that any
    /// instructions have been inserted into `block` yet.
    fn at_first_insertion_point(mut self, block: Block) -> Self
    where
        Self: Sized,
    {
        self.goto_first_insertion_point(block);
        self
    }

    /// Go to the position for inserting instructions at the beginning of `block`,
    /// which unlike `goto_first_inst` doesn't assume that any instructions have
    /// been inserted into `block` yet.
    fn goto_first_insertion_point(&mut self, block: Block) {
        if let Some(inst) = self.func.layout.first_inst(block) {
            self.goto_inst(inst);
        } else {
            self.goto_bottom(block);
        }
    }

    pub fn at_position(mut self, pos: CursorPosition) -> Self {
        self.pos = pos;
        self
    }
}

impl InstInserter for FuncCursor<'_> {
    #[inline]
    fn func(&self) -> &SsaFunc { self.func }

    #[inline]
    fn func_mut(&mut self) -> &mut SsaFunc { self.func }

    fn fill_current_block(&mut self) {}

    fn insert_inst_data(&mut self, data: InstructionData) -> Inst {
        use CursorPosition::*;

        let inst = self.func.dfg.make_inst(data);
        self.func.srclocs.insert(inst, self.srcloc);

        match self.pos {
            Nowhere | Before(..) => panic!("Invalid insert_inst position"),
            At(cur) => self.func.layout.insert_inst(inst, cur),
            After(block) => self.func.layout.append_inst(inst, block),
        };

        inst
    }

    fn current_block(&self) -> Block {
        match self.pos {
            // 1. Nowhere: No block exists. You have to decide if you want to
            // panic here or return an Option<Block>.
            CursorPosition::Nowhere => panic!("Cursor is Nowhere; no block exists."),

            // 2. Before(Block): We are at the entrance of this specific block.
            CursorPosition::Before(b) => b,

            // 3. After(Block): We are at the end of this specific block.
            CursorPosition::After(b) => b,

            // 4. At(Inst): We are currently sitting on an instruction.
            // We must look up which block this instruction belongs to.
            CursorPosition::At(i) => {
                self.func.layout.inst_block(i)
                    .expect("Instruction in At(i) must be attached to a block")
            }
        }
    }
}

pub struct InstBuilder<'a, T: InstInserter> {
    inserter: &'a mut T,
}

// Transparently Deref to whatever is driving the insertion!
impl<T: InstInserter> Deref for InstBuilder<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.inserter
    }
}

impl<T: InstInserter> DerefMut for InstBuilder<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inserter
    }
}

impl<T> InstBuilder<'_, T> where T: InstInserter {
    #[inline]
    fn insert_inst(&mut self, data: InstructionData) -> Inst {
        let inst = self.inserter.insert_inst_data(data);

        if self.func().dfg.insts[inst].is_terminator() {
            self.fill_current_block();
        }

        inst
    }

    #[inline(always)]
    pub fn insert_comment(&mut self, inst: Inst, comment: impl AsRef<str>) {
        let func = self.func_mut();
        let string = func.push_string(comment);
        func.comments.insert(inst, string);
    }

    #[inline]
    #[must_use]
    pub fn get_last_inst(&self) -> Option<Inst> {
        let block = self.current_block();
        self.func().cfg.blocks[block]
            .insts
            .as_slice(&self.func().cfg.block_insts_pool)
            .last()
            .copied()
    }

    #[inline]
    fn make_inst_result(&mut self, inst: Inst, ty: Type, result_idx: u8) -> Value {
        let func = self.func_mut();

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
            let ty = self.func().dfg.values[lhs].ty;
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
            let ty = self.func().dfg.values[lhs].ty;
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
            let ty = self.func().dfg.values[lhs].ty;
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
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FRem, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    #[inline]
    pub fn fmod_imm(&mut self, lhs: Value, rhs: f64) -> Value {
        let ty = self.func().value_type(lhs);
        let rhs = self.fconst(ty, rhs);
        self.frem(lhs, rhs)
    }

    with_comment! {
        isub_with_comment,
        #[inline]
        pub fn isub(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::ISub, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        imul_with_comment,
        #[inline]
        pub fn imul(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::IMul, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        sdiv_with_comment,
        #[inline]
        pub fn sdiv(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::SDiv, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        udiv_with_comment,
        #[inline]
        pub fn udiv(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
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
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::And, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        or_with_comment,
        #[inline]
        pub fn or(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Or, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        xor_with_comment,
        #[inline]
        pub fn xor(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
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

        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.iadd(lhs, rhs)
    }

    #[inline]
    pub fn isub_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        if rhs == 0 {
            return lhs;
        }

        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.isub(lhs, rhs)
    }

    #[inline]
    pub fn imul_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        if rhs == 1 {
            return lhs;
        }

        let ty = self.func().value_type(lhs);
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
        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.sdiv(lhs, rhs)
    }

    #[inline]
    pub fn udiv_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        if rhs == 1 {
            return lhs;
        }
        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.udiv(lhs, rhs)
    }

    #[inline]
    pub fn and_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.func().value_type(lhs);

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

        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.or(lhs, rhs)
    }

    #[inline]
    pub fn xor_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        if rhs == 0 {
            return lhs;
        }

        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.xor(lhs, rhs)
    }

    #[inline]
    pub fn icmp_imm(&mut self, code: IntCC, lhs: Value, rhs: i64) -> Value {
        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.icmp(code, lhs, rhs)
    }

    #[inline]
    pub fn fcmp_imm(&mut self, code: FloatCC, lhs: Value, rhs: f64) -> Value {
        let ty = self.func().value_type(lhs);
        let rhs = self.fconst(ty, rhs);
        self.fcmp(code, lhs, rhs)
    }

    with_comment! {
        ushr_with_comment,
        #[inline]
        pub fn ushr(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Ushr, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        sshr_with_comment,
        #[inline]
        pub fn sshr(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Sshr, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        ishl_with_comment,
        #[inline]
        pub fn ishl(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Ishl, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        band_with_comment,
        #[inline]
        pub fn band(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Band, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        bor_with_comment,
        #[inline]
        pub fn bor(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::Bor, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    #[inline]
    pub fn ushr_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.ushr(lhs, rhs)
    }

    #[inline]
    pub fn sshr_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.sshr(lhs, rhs)
    }

    #[inline]
    pub fn ishl_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.ishl(lhs, rhs)
    }

    #[inline]
    pub fn band_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.band(lhs, rhs)
    }

    #[inline]
    pub fn bor_imm(&mut self, lhs: Value, rhs: i64) -> Value {
        let ty = self.func().value_type(lhs);
        let rhs = self.iconst(ty, rhs);
        self.bor(lhs, rhs)
    }

    with_comment! {
        ireduce_with_comment,
        #[inline]
        pub fn ireduce(&mut self, ty: Type, arg: Value) -> Value {
            if self.func().value_type(arg) == ty {
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
            if self.func().value_type(arg) == ty {
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
            if self.func().value_type(arg) == ty {
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
            if self.func().value_type(arg) == ty {
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
            if self.func().value_type(arg) == ty {
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
            let ty = self.func().dfg.values[arg].ty;
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
                self.func().value_type(arg).bits(),
                ty.bits(),
                "bitcasting value to a type with a different size"
            };

            if self.func().value_type(arg) == ty {
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
            let arg_ty = self.func().value_type(arg);

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
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FAdd, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fsub_with_comment,
        #[inline]
        pub fn fsub(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FSub, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fmul_with_comment,
        #[inline]
        pub fn fmul(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
            let inst = self.insert_inst(InstructionData::Binary { binop: BinaryOp::FMul, args: [lhs, rhs] });
            self.make_inst_result(inst, ty, 0)
        }
    }

    with_comment! {
        fdiv_with_comment,
        #[inline]
        pub fn fdiv(&mut self, lhs: Value, rhs: Value) -> Value {
            let ty = self.func().dfg.values[lhs].ty;
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
        pub fn stack_store(&mut self, slot: StackSlot, val: Value) -> Inst {
            self.insert_inst(InstructionData::StackStore { slot, arg: val })
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
            self.jump_params(dest, &[]);
        }
    }

    with_comment! {
        jump_params_with_comment,
        #[inline]
        pub fn jump_params(&mut self, dest: Block, params: &[Value]) {
            let args = EntityList::from_slice(
                params,
                &mut self.func_mut().dfg.values_pool
            );
            let inst = self.insert_inst(InstructionData::Jump {
                destination: dest,
                args,
            });
            let from = self.current_block();

            self.func_mut().cfg.add_pred(from, dest);
            self.add_pred(dest, inst);

            assert!(!self.is_sealed(dest));
        }
    }

    with_comment! {
        brif_params_with_comment,
        #[inline]
        pub fn brif_params(&mut self, cond: Value, true_dest: Block, false_dest: Block, true_args: &[Value], false_args: &[Value]) {
            let true_args = EntityList::from_slice(
                true_args,
                &mut self.func_mut().dfg.values_pool
            );
            let false_args = EntityList::from_slice(
                false_args,
                &mut self.func_mut().dfg.values_pool
            );
            let inst = self.insert_inst(InstructionData::Branch {
                destinations: [true_dest, false_dest],
                arg: cond,
                args: [true_args, false_args]
            });

            let from = self.current_block();
            self.func_mut().cfg.add_pred(from, true_dest);
            self.func_mut().cfg.add_pred(from, false_dest);

            self.add_pred(true_dest, inst);
            self.add_pred(false_dest, inst);

            assert!(!self.is_sealed(true_dest));
            assert!(!self.is_sealed(false_dest));
        }
    }

    with_comment! {
        brif_with_comment,
        #[inline]
        pub fn brif(&mut self, cond: Value, true_dest: Block, false_dest: Block) {
            self.brif_params(cond, true_dest, false_dest, &[], &[]);
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
                &mut self.func_mut().dfg.values_pool
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
        call_intrinsic_with_comment,
        #[inline]
        pub fn call_intrinsic(
            &mut self,
            intrinsic: Intrinsic,
            args: &[Value],
        ) -> Inst {
            let result_tys: &[Type] = match intrinsic {
                Intrinsic::Memcmp => &[Type::I32],
                Intrinsic::Memcpy => &[],
                Intrinsic::Memset => &[],
            };

            let args = EntityList::from_slice(
                args,
                &mut self.func_mut().dfg.values_pool
            );

            let inst = self.insert_inst(InstructionData::CallIntrinsic {
                callee: intrinsic,
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
                &mut self.func_mut().dfg.values_pool
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
                &mut self.func_mut().dfg.values_pool
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
                &mut self.func_mut().dfg.values_pool
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
            dest: Value,
            src: Value,
            size: Value,
        ) {
            self.call_intrinsic(Intrinsic::Memcpy, &[dest, src, size]);
        }
    }

    with_comment! {
        call_memcmp_with_comment,
        #[inline]
        pub fn call_memcmp(
            &mut self,
            src1: Value,
            src2: Value,
            size: Value,
        ) -> Value {
            let inst = self.call_intrinsic(Intrinsic::Memcmp, &[src1, src2, size]);
            self.func().inst_results(inst)[0]
        }
    }

    with_comment! {
        call_memset_with_comment,
        #[inline]
        pub fn call_memset(
            &mut self,
            dest: Value,
            c: Value,
            n: Value,
        ) {
            self.call_intrinsic(Intrinsic::Memset, &[dest, c, n]);
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
                &mut self.func_mut().dfg.values_pool
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
fn emit_zero(ty: Type, cur: &mut FuncCursor) -> Value {
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

                // @Cleanup
                let ty = func.value_type(sentinel);
                let mut cur = FuncCursor::new(func).at_first_insertion_point(dest_block);
                let zero = emit_zero(ty, &mut cur);

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
                            args[0].push(val, &mut dfg.values_pool);
                        } else if destinations[1] == dest_block {
                            args[1].push(val, &mut dfg.values_pool);
                        }
                    }

                    InstructionData::Jump { destination, args } => {
                        if *destination == dest_block {
                            args.push(val, &mut dfg.values_pool);
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

use core::ops::{Index, IndexMut};

#[derive(Clone, Copy)]
#[repr(u8)]
enum SlotSize {
    Size8 = 0,
    Size16 = 1,
    Size32 = 2,
    Size64 = 3,
    Size128 = 4,
    // If adding support for more slot sizes, update `SLOT_SIZE_LEN` below.
}
const SLOT_SIZE_LEN: usize = 5;

impl TryFrom<Type> for SlotSize {
    type Error = &'static str;

    fn try_from(ty: Type) -> Result<Self, Self::Error> {
        Self::new(ty.bytes()).ok_or("type is not supported in stack maps")
    }
}

impl SlotSize {
    fn new(bytes: u32) -> Option<Self> {
        match bytes {
            1 => Some(Self::Size8),
            2 => Some(Self::Size16),
            4 => Some(Self::Size32),
            8 => Some(Self::Size64),
            16 => Some(Self::Size128),
            _ => None,
        }
    }

    fn unwrap_new(bytes: u32) -> Self {
        Self::new(bytes).unwrap_or_else(|| panic!("cannot create a `SlotSize` for {bytes} bytes"))
    }
}

/// A map from every `SlotSize` to a `T`.
struct SlotSizeMap<T>([T; SLOT_SIZE_LEN]);

impl<T> Default for SlotSizeMap<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Index<SlotSize> for SlotSizeMap<T> {
    type Output = T;
    fn index(&self, index: SlotSize) -> &Self::Output {
        self.get(index)
    }
}

impl<T> IndexMut<SlotSize> for SlotSizeMap<T> {
    fn index_mut(&mut self, index: SlotSize) -> &mut Self::Output {
        self.get_mut(index)
    }
}

impl<T> SlotSizeMap<T> {
    fn new() -> Self
    where
        T: Default,
    {
        Self([
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
        ])
    }

    fn clear(&mut self)
    where
        T: Default,
    {
        *self = Self::new();
    }

    fn get(&self, size: SlotSize) -> &T {
        let index = size as u8 as usize;
        &self.0[index]
    }

    fn get_mut(&mut self, size: SlotSize) -> &mut T {
        let index = size as u8 as usize;
        &mut self.0[index]
    }
}

/// A set of live values.
///
/// Make sure to copy to a vec and sort, or something, before iterating over the
/// values to ensure deterministic output.
type LiveSet = HashSet<Value>;

/// A worklist of blocks' post-order indices that we need to process.
#[derive(Default)]
struct Worklist {
    /// Stack of blocks to process.
    stack: Vec<u32>,

    /// The set of blocks that need to be updated.
    ///
    /// This is a subset of the elements present in `self.stack`, *not* the
    /// exact same elements. `self.stack` is allowed to have duplicates, and
    /// once we pop the first occurrence of a duplicate, we remove it from this
    /// set, since it no longer needs updates at that point. This potentially
    /// uses more stack space than necessary, but prefers processing immediate
    /// predecessors, and therefore inner loop bodies before continuing to
    /// process outer loop bodies. This ultimately results in fewer iterations
    /// required to reach a fixed point.
    need_updates: HashSet<u32>,
}

impl Extend<u32> for Worklist {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = u32>,
    {
        for block_index in iter {
            self.push(block_index);
        }
    }
}

impl Worklist {
    fn clear(&mut self) {
        let Worklist {
            stack,
            need_updates,
        } = self;
        stack.clear();
        need_updates.clear();
    }

    fn reserve(&mut self, capacity: usize) {
        let Worklist {
            stack,
            need_updates,
        } = self;
        stack.reserve(capacity);
        need_updates.reserve(capacity);
    }

    fn push(&mut self, block_index: u32) {
        // Mark this block as needing an update. If it wasn't in `self.stack`,
        // now it is and it needs an update. If it was already in `self.stack`,
        // then pushing this copy logically hoists it to the top of the
        // stack. See the above note about processing inner-most loops first.
        self.need_updates.insert(block_index);
        self.stack.push(block_index);
    }

    fn pop(&mut self) -> Option<u32> {
        while let Some(block_index) = self.stack.pop() {
            // If this block was pushed multiple times, we only need to update
            // it once, so remove it from the need-updates set. In other words
            // it was logically hoisted up to the top of the stack, while this
            // entry was left behind, and we already popped the hoisted
            // copy. See the above note about processing inner-most loops first.
            if self.need_updates.remove(&block_index) {
                return Some(block_index);
            }
        }
        None
    }
}

/// A simple liveness analysis.
///
/// This analysis is used to determine which needs-stack-map values are live
/// across safepoint instructions.
///
/// This is a backwards analysis, from uses (which mark values live) to defs
/// (which remove values from the live set) and from successor blocks to
/// predecessor blocks.
///
/// We compute two live sets for each block:
///
/// 1. The live-in set, which is the set of values that are live when control
///    enters the block.
///
/// 2. The live-out set, which is the set of values that are live when control
///    exits the block.
///
/// A block's live-out set is the union of its successors' live-in sets. A
/// block's live-in set is the set of values that are still live after the
/// block's instructions have been processed.
///
/// ```text
/// live_in(block) = union(live_out(s) for s in successors(block))
/// live_out(block) = live_in(block) - defs(block) + uses(block)
/// ```
///
/// Whenever we update a block's live-in set, we must reprocess all of its
/// predecessors, because those predecessors' live-out sets depend on this
/// block's live-in set. Processing continues until the live sets stop changing
/// and we've reached a fixed-point. Each time we process a block, its live sets
/// can only grow monotonically, and therefore we know that the computation will
/// reach its fixed-point and terminate. This fixed-point is implemented with a
/// classic worklist algorithm.
///
/// The worklist is seeded such that we initially process blocks in post-order,
/// which ensures that, when we have a loop-free control-flow graph, we only
/// process each block once. We pop a block off the worklist for
/// processing. Whenever a block's live-in set is updated during processing, we
/// push its predecessors onto the worklist so that their live-in sets can be
/// updated. Once the worklist is empty, there are no more blocks needing
/// updates, and we've reached the fixed-point.
///
/// Note: For simplicity, we do not flow liveness from block parameters back to
/// branch arguments, and instead always consider branch arguments live.
///
/// Furthermore, we do not differentiate between uses of a needs-stack-map value
/// that ultimately flow into a side-effecting operation versus uses that
/// themselves are not live. This could be tightened up in the future, but we're
/// starting with the easiest, simplest thing. It also means that we do not need
/// `O(all values)` space, only `O(needs-stack-map values)`. Finally, none of
/// our mid-end optimization passes have run at this point in time yet, so there
/// probably isn't much, if any, dead code.
///
/// After we've computed the live-in and -out sets for each block, we pass once
/// more over each block, processing its instructions again. This time, we
/// record the precise set of needs-stack-map values that are live across each
/// safepoint instruction inside the block, which is the final output of this
/// analysis.
pub(crate) struct LivenessAnalysis {
    /// Reusable depth-first search state for traversing a function's blocks.
    dfs: Dfs,

    /// The cached post-order traversal of the function's blocks.
    post_order: Vec<Block>,

    /// A secondary map from each block to its index in `post_order`.
    block_to_index: SecondaryMap<Block, u32>,

    /// A mapping from each block's post-order index to the post-order indices
    /// of its direct (non-transitive) predecessors.
    predecessors: Vec<SmallVec<[u32; 4]>>,

    /// A worklist of blocks to process. Used to determine which blocks need
    /// updates cascaded to them and when we reach a fixed-point.
    worklist: Worklist,

    /// A map from a block's post-order index to its live-in set.
    live_ins: Vec<LiveSet>,

    /// A map from a block's post-order index to its live-out set.
    live_outs: Vec<LiveSet>,

    /// The set of each needs-stack-map value that is currently live while
    /// processing a block.
    currently_live: LiveSet,

    /// A mapping from each safepoint instruction to the set of needs-stack-map
    /// values that are live across it.
    safepoints: HashMap<Inst, SmallVec<[Value; 4]>>,

    /// The set of values that are live across *any* safepoint in the function,
    /// i.e. the union of all the values in the `safepoints` map.
    live_across_any_safepoint: EntitySet<Value>,
}

impl Default for LivenessAnalysis {
    fn default() -> Self {
        Self {
            dfs: Default::default(),
            post_order: Default::default(),
            block_to_index: SecondaryMap::with_default(u32::MAX),
            predecessors: Default::default(),
            worklist: Default::default(),
            live_ins: Default::default(),
            live_outs: Default::default(),
            currently_live: Default::default(),
            safepoints: Default::default(),
            live_across_any_safepoint: Default::default(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordSafepoints {
    Yes,
    No,
}

impl LivenessAnalysis {
    /// Clear and reset all internal state such that this analysis is ready for
    /// reuse with a new function.
    pub fn clear(&mut self) {
        let LivenessAnalysis {
            dfs,
            post_order,
            block_to_index,
            predecessors,
            worklist,
            live_ins,
            live_outs,
            currently_live,
            safepoints,
            live_across_any_safepoint,
        } = self;
        dfs.clear();
        post_order.clear();
        block_to_index.clear();
        predecessors.clear();
        worklist.clear();
        live_ins.clear();
        live_outs.clear();
        currently_live.clear();
        safepoints.clear();
        live_across_any_safepoint.clear();
    }

    /// Given that we've initialized `self.post_order`, reserve capacity for the
    /// various data structures we use during our analysis.
    fn reserve_capacity(&mut self, func: &SsaFunc) {
        let LivenessAnalysis {
            dfs: _,
            post_order,
            block_to_index,
            predecessors,
            worklist,
            live_ins,
            live_outs,
            currently_live: _,
            safepoints: _,
            live_across_any_safepoint: _,
        } = self;

        block_to_index.resize(func.cfg.blocks.len());

        let capacity = post_order.len();
        worklist.reserve(capacity);
        predecessors.resize(capacity, Default::default());
        live_ins.resize(capacity, Default::default());
        live_outs.resize(capacity, Default::default());
    }

    fn initialize_block_to_index_map(&mut self) {
        for (block_index, block) in self.post_order.iter().enumerate() {
            self.block_to_index[*block] = u32::try_from(block_index).unwrap();
        }
    }

    fn initialize_predecessors_map(&mut self, func: &SsaFunc) {
        for (block_index, block) in self.post_order.iter().enumerate() {
            let block_index = u32::try_from(block_index).unwrap();
            for succ in func.block_successors(*block) {
                let succ_index = self.block_to_index[succ];
                debug_assert_ne!(succ_index, u32::MAX);
                let succ_index = usize::try_from(succ_index).unwrap();
                self.predecessors[succ_index].push(block_index);
            }
        }
    }

    /// Process a value's definition, removing it from the currently-live set.
    fn process_def(&mut self, val: Value) {
        if self.currently_live.remove(&val) {
            // println!("liveness:   defining {val:?}, removing it from the live set");
        }
    }

    /// Record the live set of needs-stack-map values at the given safepoint.
    fn record_safepoint(&mut self, func: &SsaFunc, inst: Inst) {
        // println!(
        //     "liveness:   found safepoint: {inst:?}: {}",
        //     func.inst_to_string(inst)
        // );
        // println!("liveness:     live set = {:?}", self.currently_live);

        let mut live = self.currently_live.iter().copied().collect::<SmallVec<_>>();
        // Keep order deterministic since we add stack map entries in this
        // order.
        live.sort();

        self.live_across_any_safepoint.extend(live.iter().copied());
        self.safepoints.insert(inst, live);
    }

    /// Process a use of a needs-stack-map value, inserting it into the
    /// currently-live set.
    fn process_use(&mut self, func: &SsaFunc, inst: Inst, val: Value) {
        if self.currently_live.insert(val) {
            // println!(
            //     "liveness:   found use of {val:?}, marking it live: {inst:?}: {}",
            //     func.inst_to_string(inst)
            // );
        }
    }

    /// Process all the instructions in a block in reverse order.
    fn process_block(
        &mut self,
        func: &mut SsaFunc,
        stack_map_values: &EntitySet<Value>,
        block_index: usize,
        record_safepoints: RecordSafepoints,
    ) {
        let block = self.post_order[block_index];
        // println!("liveness: traversing {block:?}");

        // Reset the currently-live set to this block's live-out set.
        self.currently_live.clear();
        self.currently_live
            .extend(self.live_outs[block_index].iter().copied());

        // Now process this block's instructions, incrementally building its
        // live-in set inside the currently-live set.
        let mut option_inst = func.layout.last_inst(block);
        while let Some(inst) = option_inst {
            // Process any needs-stack-map values defined by this instruction.
            for val in func.inst_results(inst) {
                self.process_def(*val);
            }

            // If this instruction is a safepoint and we've been asked to record
            // safepoints, then do so.
            let is_safepoint = func.dfg.insts[inst].is_safepoint();
            if record_safepoints == RecordSafepoints::Yes && is_safepoint {
                self.record_safepoint(func, inst);
            }

            // Process any needs-stack-map values used by this instruction.
            for val in func.dfg.inst_values(inst) {
                let val = func.resolve_aliases(val);
                if stack_map_values.contains(val) {
                    self.process_use(func, inst, val);
                }
            }

            option_inst = func.layout.prev_inst(inst);
        }

        // After we've processed this block's instructions, remove its
        // parameters from the live set. This is part of step (1).
        for val in func.block_params(block) {
            self.process_def(*val);
        }
    }

    /// Run the liveness analysis on the given function.
    pub fn run(&mut self, func: &mut SsaFunc, stack_map_values: &EntitySet<Value>) {
        self.clear();
        self.post_order.extend(self.dfs.post_order_iter(func));
        self.reserve_capacity(func);
        self.initialize_block_to_index_map();
        self.initialize_predecessors_map(func);

        // Initially enqueue all blocks for processing. We push them in reverse
        // post-order (which yields them in post-order when popped) because if
        // there are no back-edges in the control-flow graph, post-order will
        // result in only a single pass over the blocks.
        self.worklist
            .extend((0..u32::try_from(self.post_order.len()).unwrap()).rev());

        // Pump the worklist until we reach a fixed-point.
        while let Some(block_index) = self.worklist.pop() {
            let block_index = usize::try_from(block_index).unwrap();

            // Because our live sets grow monotonically, we just need to see if
            // the size changed to determine whether the whole set changed.
            let initial_live_in_len = self.live_ins[block_index].len();

            // The live-out set for a block is the union of the live-in sets of
            // its successors.
            for successor in func.block_successors(self.post_order[block_index]) {
                let successor_index = self.block_to_index[successor];
                debug_assert_ne!(successor_index, u32::MAX);
                let successor_index = usize::try_from(successor_index).unwrap();
                self.live_outs[block_index].extend(self.live_ins[successor_index].iter().copied());
            }

            // Process the block to compute its live-in set, but do not record
            // safepoints yet, as we haven't yet processed loop back edges (see
            // below).
            self.process_block(func, stack_map_values, block_index, RecordSafepoints::No);

            // The live-in set for a block is the set of values that are still
            // live after the block's instructions have been processed.
            self.live_ins[block_index].extend(self.currently_live.iter().copied());

            // If the live-in set changed, then we need to revisit all this
            // block's predecessors.
            if self.live_ins[block_index].len() != initial_live_in_len {
                self.worklist
                    .extend(self.predecessors[block_index].iter().copied());
            }
        }

        // Once we've reached a fixed-point, compute the actual live set for
        // each safepoint instruction in each block, backwards from the block's
        // live-out set.
        for block_index in 0..self.post_order.len() {
            self.process_block(func, stack_map_values, block_index, RecordSafepoints::Yes);

            debug_assert_eq!(
                self.currently_live, self.live_ins[block_index],
                "when we recompute the live-in set for a block as part of \
                 computing live sets at each safepoint, we should get the same \
                 result we computed in the fixed-point"
            );
        }
    }
}

/// A mapping from each needs-stack-map value to its associated stack slot.
///
/// Internally maintains free lists for stack slots that won't be used again, so
/// that we can reuse them and minimize the number of stack slots we need to
/// allocate.
#[derive(Default)]
struct StackSlots {
    /// A mapping from each needs-stack-map value that is live across some
    /// safepoint to the stack slot that it resides within. Note that if a
    /// needs-stack-map value is never live across a safepoint, then we won't
    /// ever add it to this map, it can remain in a virtual register for the
    /// duration of its lifetime, and we won't replace all its uses with reloads
    /// and all that stuff.
    stack_slots: HashMap<Value, StackSlot>,

    /// A map from slot size to free stack slots that are not being used
    /// anymore. This allows us to reuse stack slots across multiple values
    /// helps cut down on the ultimate size of our stack frames.
    free_stack_slots: SlotSizeMap<SmallVec<[StackSlot; 4]>>,
}

impl StackSlots {
    fn clear(&mut self) {
        let StackSlots {
            stack_slots,
            free_stack_slots,
        } = self;
        stack_slots.clear();
        free_stack_slots.clear();
    }

    fn get(&self, val: Value) -> Option<StackSlot> {
        self.stack_slots.get(&val).copied()
    }

    fn get_or_create_stack_slot(&mut self, func: &mut SsaFunc, val: Value) -> StackSlot {
        *self.stack_slots.entry(val).or_insert_with(|| {
            // println!("rewriting:     {val:?} needs a stack slot");
            let ty = func.value_type(val);
            let size = ty.bytes();
            match self.free_stack_slots[SlotSize::unwrap_new(size)].pop() {
                Some(slot) => {
                    // println!("rewriting:       reusing free stack slot {slot:?} for {val:?}");
                    slot
                }
                None => {
                    debug_assert!(size.is_power_of_two());
                    let log2_size = size.ilog2();
                    let slot = func.create_stack_slot(ty, size, log2_size.try_into().unwrap());
                    // println!("rewriting:       created new stack slot {slot:?} for {val:?}");
                    slot
                }
            }
        })
    }

    fn free_stack_slot(&mut self, size: SlotSize, slot: StackSlot) {
        // println!("rewriting:     returning {slot:?} to the free list");
        self.free_stack_slots[size].push(slot);
    }
}

/// A pass to rewrite a function's instructions to spill and reload values that
/// are live across safepoints.
///
/// A single `SafepointSpiller` instance may be reused to rewrite many
/// functions, amortizing the cost of its internal allocations and avoiding
/// repeated `malloc` and `free` calls.
#[derive(Default)]
pub(super) struct SafepointSpiller {
    liveness: LivenessAnalysis,
    stack_slots: StackSlots,
}

impl SafepointSpiller {
    /// Clear and reset all internal state such that this pass is ready to run
    /// on a new function.
    pub fn clear(&mut self) {
        let SafepointSpiller {
            liveness,
            stack_slots,
        } = self;
        liveness.clear();
        stack_slots.clear();
    }

    /// Identify needs-stack-map values that are live across safepoints, and
    /// rewrite the function's instructions to spill and reload them as
    /// necessary.
    pub fn run(&mut self, func: &mut SsaFunc, stack_map_values: &EntitySet<Value>) {
        // println!(
        //     "values needing inclusion in stack maps: {:?}",
        //     stack_map_values
        // );
        // println!(
        //     "before inserting safepoint spills and reloads:\n{}",
        //     func
        // );

        self.clear();
        self.liveness.run(func, stack_map_values);
        self.rewrite(func);

        // println!(
        //     "after inserting safepoint spills and reloads:\n{}",
        //     func
        // );
    }

    /// Spill this value to a stack slot if it has been declared that it must be
    /// included in stack maps and is live across any safepoints.
    ///
    /// The given cursor must point just after this value's definition.
    fn rewrite_def<'a>(&mut self, pos: &mut FuncCursor<'a>, val: Value) {
        if let Some(slot) = self.stack_slots.get(val) {
            let ty = pos.func.dfg.value_type(val);

            let i = pos.ins().stack_store(slot, val);
            // println!(
            //     "rewriting:   spilling {val:?} to {slot:?}: {}",
            //     pos.func.inst_to_string(i)
            // );

            // Now that we've defined this value, there cannot be any more uses
            // of it, and therefore this stack slot is now available for reuse.
            let size = SlotSize::try_from(ty).unwrap();
            self.stack_slots.free_stack_slot(size, slot);
        }
    }

    /// Add a stack map entry for each needs-stack-map value that is live across
    /// the given safepoint instruction.
    ///
    /// This will additionally assign stack slots to needs-stack-map values, if
    /// no such assignment has already been made.
    fn rewrite_safepoint(&mut self, func: &mut SsaFunc, inst: Inst) {
        // println!(
        //     "rewriting:   found safepoint: {inst:?}: {}",
        //     func.inst_to_string(inst)
        // );

        let live = self
            .liveness
            .safepoints
            .get(&inst)
            .expect("should only call `rewrite_safepoint` on safepoint instructions");

        for val in live {
            // Get or create the stack slot for this live needs-stack-map value.
            let slot = self.stack_slots.get_or_create_stack_slot(func, *val);

            println!(
                "rewriting:     adding stack map entry for {val:?} at {slot:?}: {}",
                func.inst_to_string(inst)
            );
            let ty = func.value_type(*val);
            func.dfg.append_user_stack_map_entry(
                inst,
                UserStackMapEntry {
                    ty,
                    slot,
                    offset: 0,
                },
            );
        }
    }

    /// If `val` is a needs-stack-map value that has been spilled to a stack
    /// slot, then rewrite `val` to be a load from its associated stack
    /// slot.
    ///
    /// Returns `true` if `val` was rewritten, `false` if not.
    ///
    /// The given cursor must point just before the use of the value that we are
    /// replacing.
    fn rewrite_use(&mut self, pos: &mut FuncCursor<'_>, val: &mut Value) -> bool {
        if !self.liveness.live_across_any_safepoint.contains(*val) {
            return false;
        }

        let old_val = *val;
        // println!("rewriting:     found use of {old_val:?}");

        let ty = pos.func.dfg.value_type(*val);
        let slot = self.stack_slots.get_or_create_stack_slot(pos.func, *val);
        *val = pos.ins().stack_load(ty, slot);

        // println!(
        //     "rewriting:     reloading {old_val:?}: {}",
        //     pos.func.inst_to_string(pos.func.dfg.value_def(*val).unwrap_inst())
        // );

        true
    }

    /// Rewrite the function's instructions to spill and reload values that are
    /// live across safepoints:
    ///
    /// 1. Definitions of needs-stack-map values that are live across some
    ///    safepoint need to be spilled to their assigned stack slot.
    ///
    /// 2. Instructions that are themselves safepoints must have stack map
    ///    entries added for the needs-stack-map values that are live across
    ///    them.
    ///
    /// 3. Uses of needs-stack-map values that have been spilled to a stack slot
    ///    need to be replaced with reloads from the slot.
    fn rewrite(&mut self, func: &mut SsaFunc) {
        // Shared temporary storage for operand and result lists.
        let mut vals: SmallVec<[_; 8]> = Default::default();

        // Rewrite the function's instructions in post-order. This ensures that
        // we rewrite uses before defs, and therefore once we see a def we know
        // its stack slot will never be used for that value again. Therefore,
        // the slot can be reappropriated for a new needs-stack-map value with a
        // non-overlapping live range. See `rewrite_def` and `free_stack_slots`
        // for more details.
        for block_index in 0..self.liveness.post_order.len() {
            let block = self.liveness.post_order[block_index];
            // println!("rewriting: processing {block:?}");

            let mut option_inst = func.layout.last_inst(block);
            while let Some(inst) = option_inst {
                // If this instruction defines a needs-stack-map value that is
                // live across a safepoint, then spill the value to its stack
                // slot.
                let mut pos = FuncCursor::new(func).after_inst(inst);
                vals.extend_from_slice(pos.func.dfg.inst_results(inst));
                for val in vals.drain(..) {
                    self.rewrite_def(&mut pos, val);
                }

                // If this instruction is a safepoint, then we must add stack
                // map entries for the needs-stack-map values that are live
                // across it.
                if self.liveness.safepoints.contains_key(&inst) {
                    self.rewrite_safepoint(func, inst);
                }

                // Replace all uses of needs-stack-map values with loads from
                // the value's associated stack slot.
                let mut pos = FuncCursor::new(func).at_inst(inst);
                vals.extend(pos.func.dfg.inst_values(inst));
                let mut replaced_any = false;
                for val in &mut vals {
                    replaced_any |= self.rewrite_use(&mut pos, val);
                }
                if replaced_any {
                    pos.func.dfg.overwrite_inst_values(inst, vals.drain(..));
                    // println!(
                    //     "rewriting:     updated {inst:?} operands with reloaded values: {}",
                    //     pos.func.inst_to_string(inst)
                    // );
                } else {
                    vals.clear();
                }

                option_inst = func.layout.prev_inst(inst);
            }

            // Spill needs-stack-map values defined by block parameters to their
            // associated stack slots.
            let mut pos = FuncCursor::new(func).at_position(CursorPosition::Before(block));
            pos.next_inst(); // Advance to the first instruction in the block.
            vals.clear();
            vals.extend_from_slice(pos.func.block_params(block));
            for val in vals.drain(..) {
                self.rewrite_def(&mut pos, val);
            }
        }
    }
}

use core::fmt::Debug;

/// A low-level DFS traversal event: either entering or exiting the traversal of
/// a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Event {
    /// Entering traversal of a block.
    ///
    /// Processing a block upon this event corresponds to a pre-order,
    /// depth-first traversal.
    Enter,

    /// Exiting traversal of a block.
    ///
    /// Processing a block upon this event corresponds to a post-order,
    /// depth-first traversal.
    Exit,
}

/// A depth-first traversal.
///
/// This is a fairly low-level traversal type, and is generally intended to be
/// used as a building block for making specific pre-order or post-order
/// traversals for whatever problem is at hand.
///
/// This type may be reused multiple times across different passes or functions
/// and will internally reuse any heap allocations its already made.
///
/// Traversal is not recursive.
#[derive(Debug, Default, Clone)]
pub struct Dfs {
    stack: Vec<(Event, Block)>,
    seen: EntitySet<Block>,
}

impl Dfs {
    /// Construct a new depth-first traversal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Perform a depth-first traversal over the given function.
    ///
    /// Yields pairs of `(Event, ir::Block)`.
    ///
    /// This iterator can be used to perform either pre- or post-order
    /// traversals, or a combination of the two.
    pub fn iter<'a>(&'a mut self, func: &'a SsaFunc) -> DfsIter<'a> {
        self.clear();
        if let Some(e) = func.layout.entry_block() {
            self.stack.push((Event::Enter, e));
        }
        DfsIter { dfs: self, func }
    }

    /// Perform a pre-order traversal over the given function.
    ///
    /// Yields `ir::Block` items.
    pub fn pre_order_iter<'a>(&'a mut self, func: &'a SsaFunc) -> DfsPreOrderIter<'a> {
        DfsPreOrderIter(self.iter(func))
    }

    /// Perform a post-order traversal over the given function.
    ///
    /// Yields `ir::Block` items.
    pub fn post_order_iter<'a>(&'a mut self, func: &'a SsaFunc) -> DfsPostOrderIter<'a> {
        DfsPostOrderIter(self.iter(func))
    }

    /// Clear this DFS, but keep its allocations for future reuse.
    pub fn clear(&mut self) {
        let Dfs { stack, seen } = self;
        stack.clear();
        seen.clear();
    }
}

/// An iterator that yields pairs of `(Event, ir::Block)` items as it performs a
/// depth-first traversal over its associated function.
pub struct DfsIter<'a> {
    dfs: &'a mut Dfs,
    func: &'a SsaFunc,
}

impl Iterator for DfsIter<'_> {
    type Item = (Event, Block);

    fn next(&mut self) -> Option<(Event, Block)> {
        let (event, block) = self.dfs.stack.pop()?;

        if event == Event::Enter && self.dfs.seen.insert(block) {
            self.dfs.stack.push((Event::Exit, block));
            self.dfs.stack.extend(
                self.func
                    .block_successors(block)
                    // Heuristic: chase the children in reverse. This puts
                    // the first successor block first in the postorder, all
                    // other things being equal, which tends to prioritize
                    // loop backedges over out-edges, putting the edge-block
                    // closer to the loop body and minimizing live-ranges in
                    // linear instruction space. This heuristic doesn't have
                    // any effect on the computation of dominators, and is
                    // purely for other consumers of the postorder we cache
                    // here.
                    .rev()
                    // This is purely an optimization to avoid additional
                    // iterations of the loop, and is not required; it's
                    // merely inlining the check from the outer conditional
                    // of this case to avoid the extra loop iteration. This
                    // also avoids potential excess stack growth.
                    .filter(|block| !self.dfs.seen.contains(*block))
                    .map(|block| (Event::Enter, block)),
            );
        }

        Some((event, block))
    }
}

/// An iterator that yields `ir::Block` items during a depth-first, pre-order
/// traversal over its associated function.
pub struct DfsPreOrderIter<'a>(DfsIter<'a>);

impl Iterator for DfsPreOrderIter<'_> {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.0.next()? {
                (Event::Enter, b) => return Some(b),
                (Event::Exit, _) => continue,
            }
        }
    }
}

/// An iterator that yields `ir::Block` items during a depth-first, post-order
/// traversal over its associated function.
pub struct DfsPostOrderIter<'a>(DfsIter<'a>);

impl Iterator for DfsPostOrderIter<'_> {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.0.next()? {
                (Event::Exit, b) => return Some(b),
                (Event::Enter, _) => continue,
            }
        }
    }
}

/// User-defined stack maps.
///
/// This module provides types allowing users to define stack maps and associate
/// them with safepoints.
///
/// A **safepoint** is a program point (i.e. CLIF instruction) where it must be
/// safe to run GC. Currently all non-tail call instructions are considered
/// safepoints. (This does *not* allow, for example, skipping safepoints for
/// calls that are statically known not to trigger collections, or to have a
/// safepoint on a volatile load to a page that gets protected when it is time
/// to GC, triggering a fault that pauses the mutator and lets the collector do
/// its work before resuming the mutator. We can lift this restriction in the
/// future, if necessary.)
///
/// A **stack map** is a description of where to find all the GC-managed values
/// that are live at a particular safepoint. Stack maps let the collector find
/// on-stack roots. Each stack map is logically a set of offsets into the stack
/// frame and the type of value at that associated offset. However, because the
/// stack layout isn't defined until much later in the compiler's pipeline, each
/// stack map entry instead includes both an `ir::StackSlot` and an offset
/// within that slot.
///
/// These stack maps are **user-defined** in that it is the CLIF producer's
/// responsibility to identify and spill the live GC-managed values and attach
/// the associated stack map entries to each safepoint themselves (see
/// `cranelift_frontend::Function::declare_needs_stack_map` and
/// `cranelift_codegen::ir::DataFlowGraph::append_user_stack_map_entry`). Cranelift
/// will not insert spills and record these stack map entries automatically.
///
/// Logically, a set of stack maps for a function record a table of the form:
///
/// ```text
/// +---------------------+-------------------------------------------+
/// | Instruction Pointer | SP-Relative Offsets of Live GC References |
/// +---------------------+-------------------------------------------+
/// | 0x12345678          | 2, 6, 12                                  |
/// | 0x1234abcd          | 2, 6                                      |
/// | ...                 | ...                                       |
/// +---------------------+-------------------------------------------+
/// ```
///
/// Where "instruction pointer" is an instruction pointer within the function,
/// and "offsets of live GC references" contains the offsets (in units of words)
/// from the frame's stack pointer where live GC references are stored on the
/// stack. Instruction pointers within the function that do not have an entry in
/// this table are not GC safepoints.
///
/// Because
///
/// * offsets of live GC references are relative from the stack pointer, and
/// * stack frames grow down from higher addresses to lower addresses,
///
/// to get a pointer to a live reference at offset `x` within a stack frame, you
/// add `x` to the frame's stack pointer.
///
/// For example, to calculate the pointer to the live GC reference inside "frame
/// 1" below, you would do `frame_1_sp + x`:
///
/// ```text
///           Stack
///         +-------------------+
///         | Frame 0           |
///         |                   |
///    |    |                   |
///    |    +-------------------+ <--- Frame 0's SP
///    |    | Frame 1           |
///  Grows  |                   |
///  down   |                   |
///    |    | Live GC reference | --+--
///    |    |                   |   |
///    |    |                   |   |
///    V    |                   |   x = offset of live GC reference
///         |                   |   |
///         |                   |   |
///         +-------------------+ --+--  <--- Frame 1's SP
///         | Frame 2           |
///         | ...               |
/// ```
///
/// An individual `UserStackMap` is associated with just one instruction pointer
/// within the function, contains the size of the stack frame, and represents
/// the stack frame as a bitmap. There is one bit per word in the stack frame,
/// and if the bit is set, then the word contains a live GC reference.
///
/// Note that a caller's outgoing argument stack slots (if any) and callee's
/// incoming argument stack slots (if any) overlap, so we must choose which
/// function's stack maps record live GC references in these slots. We record
/// the incoming arguments in the callee's stack map. This choice plays nice
/// with tail calls, where by the time we transfer control to the callee, the
/// caller no longer exists.

use cranelift_bitset::CompoundBitSet;

pub(crate) type UserStackMapEntryVec = SmallVec<[UserStackMapEntry; 4]>;

/// A stack map entry describes a single GC-managed value and its location on
/// the stack.
///
/// A stack map entry is associated with a particular instruction, and that
/// instruction must be a safepoint. The GC-managed value must be stored in the
/// described location across this entry's instruction.
#[derive(Clone, Debug, PartialEq, Hash)]
pub struct UserStackMapEntry {
    /// The type of the value stored in this stack map entry.
    pub ty: Type,

    /// The stack slot that this stack map entry is within.
    pub slot: StackSlot,

    /// The offset within the stack slot where this entry's value can be found.
    pub offset: u32,
}

/// A compiled stack map, describing the location of many GC-managed values.
///
/// A stack map is associated with a particular instruction, and that
/// instruction is a safepoint.
#[derive(Clone, Debug, PartialEq)]
pub struct UserStackMap {
    // Offsets into the frame's sized stack slots that are GC references, by type.
    by_type: SmallVec<[(Type, CompoundBitSet); 1]>,

    // The offset of the sized stack slots, from SP, for this stack map's
    // associated PC.
    //
    // This is initially `None` upon construction during lowering, but filled in
    // after regalloc during emission when we have the precise frame layout.
    sp_to_sized_stack_slots: Option<u32>,
}

impl UserStackMap {
    /// Coalesce the given entries into a new `UserStackMap`.
    pub(crate) fn new(
        entries: &[UserStackMapEntry],
        stack_slot_offsets: &PrimaryMap<StackSlot, u32>,
    ) -> Self {
        let mut by_type = SmallVec::<[(Type, CompoundBitSet); 1]>::default();

        for entry in entries {
            let offset = stack_slot_offsets[entry.slot] + entry.offset;
            let offset = usize::try_from(offset).unwrap();

            // Don't bother trying to avoid an `O(n)` search here: `n` is
            // basically always one in practice; even if it isn't, there aren't
            // that many different CLIF types.
            let index = by_type
                .iter()
                .position(|(ty, _)| *ty == entry.ty)
                .unwrap_or_else(|| {
                    by_type.push((entry.ty, CompoundBitSet::with_capacity(offset + 1)));
                    by_type.len() - 1
                });

            by_type[index].1.insert(offset);
        }

        UserStackMap {
            by_type,
            sp_to_sized_stack_slots: None,
        }
    }

    /// Finalize this stack map by filling in the SP-to-stack-slots offset.
    pub(crate) fn finalize(&mut self, sp_to_sized_stack_slots: u32) {
        debug_assert!(self.sp_to_sized_stack_slots.is_none());
        self.sp_to_sized_stack_slots = Some(sp_to_sized_stack_slots);
    }

    /// Iterate over the entries in this stack map.
    ///
    /// Yields pairs of the type of GC reference that is at the offset, and the
    /// offset from SP. If a pair `(i64, 0x42)` is yielded, for example, then
    /// when execution is at this stack map's associated PC, `SP + 0x42` is a
    /// pointer to an `i64`, and that `i64` is a live GC reference.
    pub fn entries(&self) -> impl Iterator<Item = (Type, u32)> + '_ {
        let sp_to_sized_stack_slots = self.sp_to_sized_stack_slots.expect(
            "`sp_to_sized_stack_slots` should have been filled in before this stack map was used",
        );
        self.by_type.iter().flat_map(move |(ty, bitset)| {
            bitset.iter().map(move |slot_offset| {
                (
                    *ty,
                    sp_to_sized_stack_slots + u32::try_from(slot_offset).unwrap(),
                )
            })
        })
    }
}

/// A control flow graph represented as mappings of basic blocks to their predecessors
/// and successors.
///
/// Successors are represented as basic blocks while predecessors are represented by basic
/// blocks. Basic blocks are denoted by tuples of block and branch/jump instructions. Each
/// predecessor tuple corresponds to the end of a basic block.
///
/// ```c
///     Block0:
///         ...          ; beginning of basic block
///
///         ...
///
///         brif vx, Block1, Block2 ; end of basic block
///
///     Block1:
///         jump block3
/// ```
///
/// Here `Block1` and `Block2` would each have a single predecessor denoted as `(Block0, brif)`,
/// while `Block3` would have a single predecessor denoted as `(Block1, jump block3)`.

use cranelift_bforest as bforest;
use core::mem;

mod flow {
    use rok_entity::SecondaryMap;

    use super::{Block, Inst, SsaFunc, bforest, visit_block_succs};

    /// A basic block denoted by its enclosing Block and last instruction.
    #[derive(Debug, PartialEq, Eq)]
    pub struct BlockPredecessor {
        /// Enclosing Block key.
        pub block: Block,
        /// Last instruction in the basic block.
        pub inst: Inst,
    }

    impl BlockPredecessor {
        /// Convenient method to construct new BlockPredecessor.
        pub fn new(block: Block, inst: Inst) -> Self {
            Self { block, inst }
        }
    }

    /// A container for the successors and predecessors of some Block.
    #[derive(Clone, Default)]
    struct CFGNode {
        /// Instructions that can branch or jump to this block.
        ///
        /// This maps branch instruction -> predecessor block which is redundant since the block containing
        /// the branch instruction is available from the `layout.inst_block()` method. We store the
        /// redundant information because:
        ///
        /// 1. Many `pred_iter()` consumers want the block anyway, so it is handily available.
        /// 2. The `invalidate_block_successors()` may be called *after* branches have been removed from
        ///    their block, but we still need to remove them form the old block predecessor map.
        ///
        /// The redundant block stored here is always consistent with the CFG successor lists, even after
        /// the IR has been edited.
        pub predecessors: bforest::Map<Inst, Block>,

        /// Set of blocks that are the targets of branches and jumps in this block.
        /// The set is ordered by block number, indicated by the `()` comparator type.
        pub successors: bforest::Set<Block>,
    }

    /// The Control Flow Graph maintains a mapping of blocks to their predecessors
    /// and successors where predecessors are basic blocks and successors are
    /// basic blocks.
    pub struct ControlFlowGraph {
        data: SecondaryMap<Block, CFGNode>,
        pred_forest: bforest::MapForest<Inst, Block>,
        succ_forest: bforest::SetForest<Block>,
        valid: bool,
    }

    impl Default for ControlFlowGraph {
        fn default() -> Self {
            Self {
                data: SecondaryMap::default(),
                pred_forest: bforest::MapForest::new(),
                succ_forest: bforest::SetForest::new(),
                valid: false
            }
        }
    }

    impl ControlFlowGraph {
        /// Allocate a new blank control flow graph.
        pub fn new() -> Self {
            Self {
                data: SecondaryMap::new(),
                valid: false,
                pred_forest: bforest::MapForest::new(),
                succ_forest: bforest::SetForest::new(),
            }
        }

        /// Clear all data structures in this control flow graph.
        pub fn clear(&mut self) {
            self.data.clear();
            self.pred_forest.clear();
            self.succ_forest.clear();
            self.valid = false;
        }

        /// Allocate and compute the control flow graph for `func`.
        pub fn with_function(func: &SsaFunc) -> Self {
            let mut cfg = Self::new();
            cfg.compute(func);
            cfg
        }

        /// Compute the control flow graph of `func`.
        ///
        /// This will clear and overwrite any information already stored in this data structure.
        pub fn compute(&mut self, func: &SsaFunc) {
            self.clear();
            self.data.resize(func.cfg.blocks.len());

            for block in &func.layout {
                self.compute_block(func, block);
            }

            self.valid = true;
        }

        fn compute_block(&mut self, func: &SsaFunc, block: Block) {
            visit_block_succs(func, block, |inst, dest, _| {
                self.add_edge(block, inst, dest);
            });
        }

        fn invalidate_block_successors(&mut self, block: Block) {
            // Temporarily take ownership because we need mutable access to self.data inside the loop.
            // Unfortunately borrowck cannot see that our mut accesses to predecessors don't alias
            // our iteration over successors.
            let mut successors = core::mem::replace(&mut self.data[block].successors, Default::default());
            for succ in successors.iter(&self.succ_forest) {
                self.data[succ]
                    .predecessors
                    .retain(&mut self.pred_forest, |_, &mut e| e != block);
            }
            successors.clear(&mut self.succ_forest);
        }

        /// Recompute the control flow graph of `block`.
        ///
        /// This is for use after modifying instructions within a specific block. It recomputes all edges
        /// from `block` while leaving edges to `block` intact. Its functionality a subset of that of the
        /// more expensive `compute`, and should be used when we know we don't need to recompute the CFG
        /// from scratch, but rather that our changes have been restricted to specific blocks.
        pub fn recompute_block(&mut self, func: &SsaFunc, block: Block) {
            debug_assert!(self.is_valid());
            self.invalidate_block_successors(block);
            self.compute_block(func, block);
        }

        fn add_edge(&mut self, from: Block, from_inst: Inst, to: Block) {
            self.data[from]
                .successors
                .insert(to, &mut self.succ_forest, &());
            self.data[to]
                .predecessors
                .insert(from_inst, from, &mut self.pred_forest, &());
        }

        /// Get an iterator over the CFG predecessors to `block`.
        pub fn pred_iter(&self, block: Block) -> PredIter<'_> {
            PredIter(self.data[block].predecessors.iter(&self.pred_forest))
        }

        /// Get an iterator over the CFG successors to `block`.
        pub fn succ_iter(&self, block: Block) -> SuccIter<'_> {
            debug_assert!(self.is_valid());
            self.data[block].successors.iter(&self.succ_forest)
        }

        /// Check if the CFG is in a valid state.
        ///
        /// Note that this doesn't perform any kind of validity checks. It simply checks if the
        /// `compute()` method has been called since the last `clear()`. It does not check that the
        /// CFG is consistent with the function.
        pub fn is_valid(&self) -> bool {
            self.valid
        }
    }

    /// An iterator over block predecessors. The iterator type is `BlockPredecessor`.
    ///
    /// Each predecessor is an instruction that branches to the block.
    pub struct PredIter<'a>(bforest::MapIter<'a, Inst, Block>);

    impl<'a> Iterator for PredIter<'a> {
        type Item = BlockPredecessor;

        fn next(&mut self) -> Option<BlockPredecessor> {
            self.0.next().map(|(i, e)| BlockPredecessor::new(e, i))
        }
    }

    /// An iterator over block successors. The iterator type is `Block`.
    pub type SuccIter<'a> = bforest::SetIter<'a, Block>;
}

/// Instruction predicates/properties, shared by various analyses.

/// Test whether the given opcode is unsafe to even consider as side-effect-free.
#[inline(always)]
fn trivially_has_side_effects(data: &InstructionData) -> bool {
    matches!(
        data,
        InstructionData::CallHook { .. }
            | InstructionData::Call { .. }
            | InstructionData::CallExt { .. }
            | InstructionData::CallIndirect { .. }
            | InstructionData::Jump { .. }
            | InstructionData::Branch { .. }
            | InstructionData::Return { .. }
            | InstructionData::StackStore { .. }
            | InstructionData::StoreNoOffset { .. }
    )
}

fn is_load(data: &InstructionData) -> bool {
    matches!(data, InstructionData::StackLoad { .. } | InstructionData::LoadNoOffset { .. })
}

fn has_side_effect(func: &SsaFunc, inst: Inst) -> bool {
    let data = &func.dfg.insts[inst];
    // Until you have alias analysis / MemFlags, treat every load as
    // side-effecting-enough to survive DCE if unused is uncertain.
    // StackLoad from a non-escaping, non-aliased slot is the one
    // exception worth carving out early, since you already compute that.
    trivially_has_side_effects(data) || is_load(data)
}

/// Get the store data, if any, from an instruction.
pub fn inst_store_data(func: &SsaFunc, inst: Inst) -> Option<Value> {
    match &func.dfg.insts[inst] {
        InstructionData::StackStore { arg, .. } => {
            Some(*arg)
        }

        InstructionData::StoreNoOffset { args, .. } => {
            Some(args[0])
        }
        _ => None,
    }
}

/// Visit all successors of a block with a given visitor closure. The closure
/// arguments are the branch instruction that is used to reach the successor,
/// the successor block itself, and a flag indicating whether the block is
/// branched to via a table entry.
pub(crate) fn visit_block_succs<F: FnMut(Inst, Block, bool)>(
    f: &SsaFunc,
    block: Block,
    mut visit: F,
) {
    if let Some(inst) = f.layout.last_inst(block) {
        match &f.dfg.insts[inst] {
            InstructionData::Jump {
                destination: dest, ..
            } => {
                visit(inst, *dest, false);
            }

            InstructionData::Branch {
                destinations: [block_then, block_else],
                ..
            } => {
                visit(inst, *block_then, false);
                visit(inst, *block_else, false);
            }

            inst => debug_assert!(!inst.is_branch()),
        }
    }
}

/// A Dominator Tree represented as mappings of Blocks to their immediate dominator.

/// Spanning tree node, used during domtree computation.
#[derive(Clone, Default)]
struct SpanningTreeNode {
    /// This node's block in function CFG.
    block: PackedOption<Block>,
    /// Node's ancestor in the spanning tree.
    /// Gets invalidated during semi-dominator computation.
    ancestor: u32,
    /// The smallest semi value discovered on any semi-dominator path
    /// that went through the node up till the moment.
    /// Gets updated in the course of semi-dominator computation.
    label: u32,
    /// Semidominator value for the node.
    semi: u32,
    /// Immediate dominator value for the node.
    /// Initialized to node's ancestor in the spanning tree.
    idom: u32,
}

/// DFS preorder number for unvisited nodes and the virtual root in the spanning tree.
const NOT_VISITED: u32 = 0;

/// Spanning tree, in CFG preorder.
/// Node 0 is the virtual root and doesn't have a corresponding block.
/// It's not required because function's CFG in Cranelift always have
/// a singular root, but helps to avoid additional checks.
/// Numbering nodes from 0 also follows the convention in
/// `SimpleDominatorTree` and `DominatorTreePreorder`.
#[derive(Clone, Default)]
struct SpanningTree {
    nodes: Vec<SpanningTreeNode>,
}

impl SpanningTree {
    fn new() -> Self {
        // Include the virtual root.
        Self {
            nodes: vec![Default::default()],
        }
    }

    fn with_capacity(capacity: usize) -> Self {
        // Include the virtual root.
        let mut nodes = Vec::with_capacity(capacity + 1);
        nodes.push(Default::default());
        Self { nodes }
    }

    fn len(&self) -> usize {
        self.nodes.len()
    }

    fn reserve(&mut self, capacity: usize) {
        // Virtual root should be already included.
        self.nodes.reserve(capacity);
    }

    fn clear(&mut self) {
        self.nodes.resize(1, Default::default());
    }

    /// Returns pre_number for the new node.
    fn push(&mut self, ancestor: u32, block: Block) -> u32 {
        // Virtual root should be already included.
        debug_assert!(!self.nodes.is_empty());

        let pre_number = self.nodes.len() as u32;

        self.nodes.push(SpanningTreeNode {
            block: block.into(),
            ancestor: ancestor,
            label: pre_number,
            semi: pre_number,
            idom: ancestor,
        });

        pre_number
    }
}

impl std::ops::Index<u32> for SpanningTree {
    type Output = SpanningTreeNode;

    fn index(&self, idx: u32) -> &Self::Output {
        &self.nodes[idx as usize]
    }
}

impl std::ops::IndexMut<u32> for SpanningTree {
    fn index_mut(&mut self, idx: u32) -> &mut Self::Output {
        &mut self.nodes[idx as usize]
    }
}

/// Traversal event to compute both preorder spanning tree
/// and postorder block list. Can't use `Dfs` from traversals.rs
/// here because of the need for parent links.
enum TraversalEvent {
    Enter(u32, Block),
    Exit(Block),
}

/// Dominator tree node. We keep one of these per block.
#[derive(Clone, Default)]
struct DominatorTreeNode {
    /// Immediate dominator for the block, `None` for unreachable blocks.
    idom: PackedOption<Block>,
    /// Preorder traversal number, zero for unreachable blocks.
    pre_number: u32,
}

/// The dominator tree for a single function,
/// computed using Semi-NCA algorithm.
#[derive(Default)]
pub struct DominatorTree {
    /// DFS spanning tree.
    stree: SpanningTree,
    /// List of CFG blocks in postorder.
    postorder: Vec<Block>,
    /// Dominator tree nodes.
    nodes: SecondaryMap<Block, DominatorTreeNode>,

    /// Stack for building the spanning tree.
    dfs_worklist: Vec<TraversalEvent>,
    /// Stack used for processing semidominator paths
    /// in link-eval procedure.
    eval_worklist: Vec<u32>,

    valid: bool,
}

/// Methods for querying the dominator tree.
impl DominatorTree {
    /// Is `block` reachable from the entry block?
    pub fn is_reachable(&self, block: Block) -> bool {
        self.nodes[block].pre_number != NOT_VISITED
    }

    /// Get the CFG post-order of blocks that was used to compute the dominator tree.
    ///
    /// Note that this post-order is not updated automatically when the CFG is modified. It is
    /// computed from scratch and cached by `compute()`.
    pub fn cfg_postorder(&self) -> &[Block] {
        debug_assert!(self.is_valid());
        &self.postorder
    }

    /// Get an iterator over CFG reverse post-order of blocks used to compute the dominator tree.
    ///
    /// Note that the post-order is not updated automatically when the CFG is modified. It is
    /// computed from scratch and cached by `compute()`.
    pub fn cfg_rpo(&self) -> impl Iterator<Item = &Block> {
        debug_assert!(self.is_valid());
        self.postorder.iter().rev()
    }

    /// Returns the immediate dominator of `block`.
    ///
    /// `block_a` is said to *dominate* `block_b` if all control flow paths from the function
    /// entry to `block_b` must go through `block_a`.
    ///
    /// The *immediate dominator* is the dominator that is closest to `block`. All other dominators
    /// also dominate the immediate dominator.
    ///
    /// This returns `None` if `block` is not reachable from the entry block, or if it is the entry block
    /// which has no dominators.
    pub fn idom(&self, block: Block) -> Option<Block> {
        self.nodes[block].idom.into()
    }

    /// Returns `true` if `a` dominates `b`.
    ///
    /// This means that every control-flow path from the function entry to `b` must go through `a`.
    ///
    /// Dominance is ill defined for unreachable blocks. This function can always determine
    /// dominance for instructions in the same block, but otherwise returns `false` if either block
    /// is unreachable.
    ///
    /// An instruction is considered to dominate itself.
    /// A block is also considered to dominate itself.
    pub fn dominates<A, B>(&self, a: A, b: B, layout: &Layout) -> bool
    where
        A: Into<ProgramPoint>,
        B: Into<ProgramPoint>,
    {
        let a = a.into();
        let b = b.into();
        match a {
            ProgramPoint::Block(block_a) => match b {
                ProgramPoint::Block(block_b) => self.block_dominates(block_a, block_b),
                ProgramPoint::Inst(inst_b) => {
                    let block_b = layout
                        .inst_block(inst_b)
                        .expect("Instruction not in layout.");
                    self.block_dominates(block_a, block_b)
                }
            },
            ProgramPoint::Inst(inst_a) => {
                let block_a: Block = layout
                    .inst_block(inst_a)
                    .expect("Instruction not in layout.");
                match b {
                    ProgramPoint::Block(block_b) => {
                        block_a != block_b && self.block_dominates(block_a, block_b)
                    }
                    ProgramPoint::Inst(inst_b) => {
                        let block_b = layout
                            .inst_block(inst_b)
                            .expect("Instruction not in layout.");
                        if block_a == block_b {
                            layout.pp_cmp(a, b) != Ordering::Greater
                        } else {
                            self.block_dominates(block_a, block_b)
                        }
                    }
                }
            }
        }
    }

    /// Returns `true` if `block_a` dominates `block_b`.
    ///
    /// A block is considered to dominate itself.
    fn block_dominates(&self, block_a: Block, mut block_b: Block) -> bool {
        let pre_a = self.nodes[block_a].pre_number;

        // Run a finger up the dominator tree from b until we see a.
        // Do nothing if b is unreachable.
        while pre_a < self.nodes[block_b].pre_number {
            let idom = match self.idom(block_b) {
                Some(idom) => idom,
                None => return false, // a is unreachable, so we climbed past the entry
            };
            block_b = idom;
        }

        block_a == block_b
    }
}

impl DominatorTree {
    /// Allocate a new blank dominator tree. Use `compute` to compute the dominator tree for a
    /// function.
    pub fn new() -> Self {
        Self {
            stree: SpanningTree::new(),
            nodes: SecondaryMap::new(),
            postorder: Vec::new(),
            dfs_worklist: Vec::new(),
            eval_worklist: Vec::new(),
            valid: false,
        }
    }

    /// Allocate and compute a dominator tree.
    pub fn with_function(func: &SsaFunc, cfg: &flow::ControlFlowGraph) -> Self {
        let block_capacity = func.layout.block_capacity();
        let mut domtree = Self {
            stree: SpanningTree::with_capacity(block_capacity),
            nodes: SecondaryMap::with_capacity(block_capacity),
            postorder: Vec::with_capacity(block_capacity),
            dfs_worklist: Vec::new(),
            eval_worklist: Vec::new(),
            valid: false,
        };
        domtree.compute(func, cfg);
        domtree
    }

    /// Reset and compute a CFG post-order and dominator tree,
    /// using Semi-NCA algorithm, described in the paper:
    ///
    /// Linear-Time Algorithms for Dominators and Related Problems.
    /// Loukas Georgiadis, Princeton University, November 2005.
    ///
    /// The same algorithm is used by Julia, SpiderMonkey and LLVM,
    /// the implementation is heavily inspired by them.
    pub fn compute(&mut self, func: &SsaFunc, cfg: &flow::ControlFlowGraph) {
        debug_assert!(cfg.is_valid());

        self.clear();
        self.compute_spanning_tree(func);
        self.compute_domtree(cfg);

        self.valid = true;
    }

    /// Clear the data structures used to represent the dominator tree. This will leave the tree in
    /// a state where `is_valid()` returns false.
    pub fn clear(&mut self) {
        self.stree.clear();
        self.nodes.clear();
        self.postorder.clear();
        self.valid = false;
    }

    /// Check if the dominator tree is in a valid state.
    ///
    /// Note that this doesn't perform any kind of validity checks. It simply checks if the
    /// `compute()` method has been called since the last `clear()`. It does not check that the
    /// dominator tree is consistent with the CFG.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Reset all internal data structures, build spanning tree
    /// and compute a post-order of the control flow graph.
    fn compute_spanning_tree(&mut self, func: &SsaFunc) {
        self.nodes.resize(func.cfg.blocks.len());
        self.stree.reserve(func.cfg.blocks.len());

        if let Some(block) = func.layout.entry_block() {
            self.dfs_worklist.push(TraversalEvent::Enter(0, block));
        }

        loop {
            match self.dfs_worklist.pop() {
                Some(TraversalEvent::Enter(parent, block)) => {
                    let node = &mut self.nodes[block];
                    if node.pre_number != NOT_VISITED {
                        continue;
                    }

                    self.dfs_worklist.push(TraversalEvent::Exit(block));

                    let pre_number = self.stree.push(parent, block);
                    node.pre_number = pre_number;

                    // Use the same traversal heuristics as in traversals.rs.
                    self.dfs_worklist.extend(
                        func.block_successors(block)
                            // Heuristic: chase the children in reverse. This puts
                            // the first successor block first in the postorder, all
                            // other things being equal, which tends to prioritize
                            // loop backedges over out-edges, putting the edge-block
                            // closer to the loop body and minimizing live-ranges in
                            // linear instruction space. This heuristic doesn't have
                            // any effect on the computation of dominators, and is
                            // purely for other consumers of the postorder we cache
                            // here.
                            .rev()
                            // A simple optimization: push less items to the stack.
                            .filter(|successor| self.nodes[*successor].pre_number == NOT_VISITED)
                            .map(|successor| TraversalEvent::Enter(pre_number, successor)),
                    );
                }
                Some(TraversalEvent::Exit(block)) => self.postorder.push(block),
                None => break,
            }
        }
    }

    /// Eval-link procedure from the paper.
    /// For a predecessor V of node W returns V if V < W, otherwise the minimum of sdom(U),
    /// where U > W and U is on a semi-dominator path for W in CFG.
    /// Use path compression to bring complexity down to O(m*log(n)).
    fn eval(&mut self, v: u32, last_linked: u32) -> u32 {
        if self.stree[v].ancestor < last_linked {
            return self.stree[v].label;
        }

        // Follow semi-dominator path.
        let mut root = v;
        loop {
            self.eval_worklist.push(root);
            root = self.stree[root].ancestor;

            if self.stree[root].ancestor < last_linked {
                break;
            }
        }

        let mut prev = root;
        let root = self.stree[prev].ancestor;

        // Perform path compression. Point all ancestors to the root
        // and propagate minimal sdom(U) value from ancestors to children.
        while let Some(curr) = self.eval_worklist.pop() {
            if self.stree[prev].label < self.stree[curr].label {
                self.stree[curr].label = self.stree[prev].label;
            }

            self.stree[curr].ancestor = root;
            prev = curr;
        }

        self.stree[v].label
    }

    fn compute_domtree(&mut self, cfg: &flow::ControlFlowGraph) {
        // Compute semi-dominators.
        for w in (1..self.stree.len() as u32).rev() {
            let w_node = &mut self.stree[w];
            let block = w_node.block.expect("Virtual root must have been excluded");
            let mut semi = w_node.ancestor;

            let last_linked = w + 1;

            for pred in cfg
                .pred_iter(block)
                .map(|pred: BlockPredecessor| pred.block)
            {
                // Skip unreachable nodes.
                if self.nodes[pred].pre_number == NOT_VISITED {
                    continue;
                }

                let semi_candidate = self.eval(self.nodes[pred].pre_number, last_linked);
                semi = std::cmp::min(semi, semi_candidate);
            }

            let w_node = &mut self.stree[w];
            w_node.label = semi;
            w_node.semi = semi;
        }

        // Compute immediate dominators.
        for v in 1..self.stree.len() as u32 {
            let semi = self.stree[v].semi;
            let block = self.stree[v]
                .block
                .expect("Virtual root must have been excluded");
            let mut idom = self.stree[v].idom;

            while idom > semi {
                idom = self.stree[idom].idom;
            }

            self.stree[v].idom = idom;

            self.nodes[block].idom = self.stree[idom].block;
        }
    }
}

/// Optional pre-order information that can be computed for a dominator tree.
///
/// This data structure is computed from a `DominatorTree` and provides:
///
/// - A forward traversable dominator tree through the `children()` iterator.
/// - An ordering of blocks according to a dominator tree pre-order.
/// - Constant time dominance checks at the block granularity.
///
/// The information in this auxiliary data structure is not easy to update when the control flow
/// graph changes, which is why it is kept separate.
pub struct DominatorTreePreorder {
    nodes: SecondaryMap<Block, ExtraNode>,

    // Scratch memory used by `compute_postorder()`.
    stack: Vec<Block>,
}

#[derive(Default, Clone)]
struct ExtraNode {
    /// First child node in the domtree.
    child: PackedOption<Block>,

    /// Next sibling node in the domtree. This linked list is ordered according to the CFG RPO.
    sibling: PackedOption<Block>,

    /// Sequence number for this node in a pre-order traversal of the dominator tree.
    /// Unreachable blocks have number 0, the entry block is 1.
    pre_number: u32,

    /// Maximum `pre_number` for the sub-tree of the dominator tree that is rooted at this node.
    /// This is always >= `pre_number`.
    pre_max: u32,
}

/// Creating and computing the dominator tree pre-order.
impl DominatorTreePreorder {
    /// Create a new blank `DominatorTreePreorder`.
    pub fn new() -> Self {
        Self {
            nodes: SecondaryMap::new(),
            stack: Vec::new(),
        }
    }

    /// Recompute this data structure to match `domtree`.
    pub fn compute(&mut self, domtree: &DominatorTree) {
        self.nodes.clear();

        // Step 1: Populate the child and sibling links.
        //
        // By following the CFG post-order and pushing to the front of the lists, we make sure that
        // sibling lists are ordered according to the CFG reverse post-order.
        for &block in domtree.cfg_postorder() {
            if let Some(idom) = domtree.idom(block) {
                let sib = mem::replace(&mut self.nodes[idom].child, block.into());
                self.nodes[block].sibling = sib;
            } else {
                // The only block without an immediate dominator is the entry.
                self.stack.push(block);
            }
        }

        // Step 2. Assign pre-order numbers from a DFS of the dominator tree.
        debug_assert!(self.stack.len() <= 1);
        let mut n = 0;
        while let Some(block) = self.stack.pop() {
            n += 1;
            let node = &mut self.nodes[block];
            node.pre_number = n;
            node.pre_max = n;
            if let Some(n) = node.sibling.expand() {
                self.stack.push(n);
            }
            if let Some(n) = node.child.expand() {
                self.stack.push(n);
            }
        }

        // Step 3. Propagate the `pre_max` numbers up the tree.
        // The CFG post-order is topologically ordered w.r.t. dominance so a node comes after all
        // its dominator tree children.
        for &block in domtree.cfg_postorder() {
            if let Some(idom) = domtree.idom(block) {
                let pre_max = core::cmp::max(self.nodes[block].pre_max, self.nodes[idom].pre_max);
                self.nodes[idom].pre_max = pre_max;
            }
        }
    }
}

/// An iterator that enumerates the direct children of a block in the dominator tree.
pub struct ChildIter<'a> {
    dtpo: &'a DominatorTreePreorder,
    next: PackedOption<Block>,
}

impl<'a> Iterator for ChildIter<'a> {
    type Item = Block;

    fn next(&mut self) -> Option<Block> {
        let n = self.next.expand();
        if let Some(block) = n {
            self.next = self.dtpo.nodes[block].sibling;
        }
        n
    }
}

/// Query interface for the dominator tree pre-order.
impl DominatorTreePreorder {
    /// Get an iterator over the direct children of `block` in the dominator tree.
    ///
    /// These are the block's whose immediate dominator is an instruction in `block`, ordered according
    /// to the CFG reverse post-order.
    pub fn children(&self, block: Block) -> ChildIter<'_> {
        ChildIter {
            dtpo: self,
            next: self.nodes[block].child,
        }
    }

    /// Fast, constant time dominance check with block granularity.
    ///
    /// This computes the same result as `domtree.dominates(a, b)`, but in guaranteed fast constant
    /// time. This is less general than the `DominatorTree` method because it only works with block
    /// program points.
    ///
    /// A block is considered to dominate itself.
    pub fn dominates(&self, a: Block, b: Block) -> bool {
        let na = &self.nodes[a];
        let nb = &self.nodes[b];
        na.pre_number <= nb.pre_number && na.pre_max >= nb.pre_max
    }

    /// Compare two blocks according to the dominator pre-order.
    pub fn pre_cmp_block(&self, a: Block, b: Block) -> Ordering {
        self.nodes[a].pre_number.cmp(&self.nodes[b].pre_number)
    }

    /// Compare two program points according to the dominator tree pre-order.
    ///
    /// This ordering of program points have the property that given a program point, pp, all the
    /// program points dominated by pp follow immediately and contiguously after pp in the order.
    pub fn pre_cmp<A, B>(&self, a: A, b: B, layout: &Layout) -> Ordering
    where
        A: Into<ProgramPoint>,
        B: Into<ProgramPoint>,
    {
        let a = a.into();
        let b = b.into();
        self.pre_cmp_block(layout.pp_block(a), layout.pp_block(b))
            .then_with(|| layout.pp_cmp(a, b))
    }
}

/// A simple GVN pass.

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
enum GvnKey {
    Binary { binop: BinaryOp, args: [Value; 2] },
    Unary { unop: UnaryOp, arg: Value },
    Icmp { code: IntCC, args: [Value; 2] },
    Fcmp { code: FloatCC, args: [Value; 2] },
    IConst { value: i64 },
    FConst { bits: u64 },
    StackLoad { slot: StackSlot },
    StackAddr { slot: StackSlot },
    LoadNoOffset { ty: Type, addr: Value },
    DataAddr { data_id: DataId },
    // Deliberately omit: Call.*, Jump, Branch, Return, StackStore,
    // StoreNoOffset, CallHook, Unreachable, Nop because they're never CSEd
}

fn gvn_key(func: &SsaFunc, inst: Inst) -> Option<GvnKey> {
    let resolved = |v: Value| func.dfg.resolve_aliases(v);
    match &func.dfg.insts[inst] {
        InstructionData::Binary { binop, args } =>
            Some(GvnKey::Binary { binop: *binop, args: [resolved(args[0]), resolved(args[1])] }),
        InstructionData::Unary { unop, arg } =>
            Some(GvnKey::Unary { unop: *unop, arg: resolved(*arg) }),
        InstructionData::Icmp { code, args } =>
            Some(GvnKey::Icmp { code: *code, args: [resolved(args[0]), resolved(args[1])] }),
        InstructionData::Fcmp { code, args } =>
            Some(GvnKey::Fcmp { code: *code, args: [resolved(args[0]), resolved(args[1])] }),
        InstructionData::IConst { value } => Some(GvnKey::IConst { value: *value }),
        InstructionData::FConst { value } => Some(GvnKey::FConst { bits: value.to_bits() }),
        InstructionData::StackAddr { slot } => Some(GvnKey::StackAddr { slot: *slot }),
        InstructionData::DataAddr { data_id } => Some(GvnKey::DataAddr { data_id: *data_id }),


        //
        // @Optimization: Can't include StackLoad / LoadNoOffset because no
        // aliasing analysis exists yet!
        //
        _ => None, // Call, CallExt, CallIndirect, CallHook, Jump, Branch,
                   // Return, StackStore, StoreNoOffset, Unreachable, Nop
    }
}

pub fn do_simple_dce(func: &mut SsaFunc, domtree: &DominatorTree) {
    let mut used_values = BTreeSet::new();

    let mut pos = FuncCursor::new(func);

    for &block in domtree.cfg_postorder().iter() {
        pos.goto_bottom(block);

        while let Some(inst) = pos.prev_inst() {
            let inst_data = &pos.func.dfg.insts[inst];

            // Keep Nops (for debugging) and Unreachable
            if matches!(inst_data, InstructionData::Nop | InstructionData::Unreachable) {
                continue;
            }

            let results = pos.func.dfg.inst_results(inst);
            let has_side_effects = trivially_has_side_effects(inst_data);

            // An instruction is dead if it has NO side effects AND
            // It has no results OR none of its results are in the `used_values` set.
            let is_dead = !has_side_effects &&
                (results.is_empty() || results.iter().all(|res| !used_values.contains(res)));

            if is_dead {
                // When iterating backward, `remove_inst()` removes the current instruction
                // and leaves the cursor on the *following* instruction. The next call to
                // `prev_inst()` naturally steps to the correct preceding instruction.
                pos.remove_inst();
            } else {
                //
                // If it's live, ensure arguments point to their latest aliases
                // and mark them as used so preceding instructions know they are needed.
                //
                pos.func.dfg.resolve_aliases_in_arguments(inst);
                for arg in pos.func.dfg.inst_args(inst) {
                    used_values.insert(arg);
                }
            }
        }
    }
}

pub fn do_simple_gvn(func: &mut SsaFunc, cfg: &mut flow::ControlFlowGraph, domtree: &DominatorTree) {
    debug_assert!(cfg.is_valid());
    debug_assert!(domtree.is_valid());

    type ValueKey = (GvnKey, SmallVec<[Type; 2]>);

    let mut visible_values: ScopedHashMap<ValueKey, Inst> = ScopedHashMap::new();
    let mut scope_stack: Vec<Inst> = Vec::new();

    // Visit blocks in a reverse post-order.
    let mut pos = FuncCursor::new(func);

    for &block in domtree.cfg_postorder().iter().rev() {
        {
            // Pop any scopes that we just exited.
            let layout = &pos.func.layout;
            loop {
                if let Some(current) = scope_stack.last() {
                    if domtree.dominates(*current, block, layout) {
                        break;
                    }
                } else {
                    break;
                }
                scope_stack.pop();
                visible_values.decrement_depth();
            }

            // Push a scope for the current block.
            scope_stack.push(layout.first_inst(block).unwrap());
            visible_values.increment_depth();
        }

        pos.goto_top(block);

        while let Some(inst) = pos.next_inst() {
            // Resolve aliases, particularly aliases we created earlier.
            pos.func.dfg.resolve_aliases_in_arguments(inst);

            let inst_data = &pos.func.dfg.insts[inst];

            if trivially_has_side_effects(inst_data) {
                continue;
            }

            let Some(gvn) = gvn_key(pos.func, inst) else {
                continue;
            };

            let results = pos.func.dfg.inst_results(inst).iter().map(|value| pos.func.value_type(*value)).collect();
            let key = (gvn, results);

            use crate::scoped_hash_map::Entry::*;

            match visible_values.entry(&NullCtx, key) {
                Occupied(entry) => {
                    #[allow(clippy::debug_assert_with_mut_call)]
                    {
                        debug_assert!(domtree.dominates(*entry.get(), inst, &pos.func.layout));
                    }

                    // If the redundant instruction is representing the current
                    // scope, pick a new representative.
                    let old = scope_stack.last_mut().unwrap();
                    if *old == inst {
                        *old = pos.func.layout.next_inst(inst).unwrap();
                    }

                    pos.func.dfg.replace_with_aliases(inst, *entry.get());
                    pos.remove_inst_and_step_back();
                }
                Vacant(entry) => {
                    entry.insert(inst);
                }
            }
        }
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
                    .as_slice(&self.dfg.values_pool)
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

        for inst in self.layout.block_insts(block_id) {
            self.fmt_inst(f, inst)?;
            writeln!(f)?;
        }

        Ok(())
    }

    pub fn inst_to_string(&self, inst_id: Inst) -> String {
        let mut s = String::new();
        self.fmt_inst(&mut s, inst_id).unwrap();
        s
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
                args.as_slice(&self.dfg.values_pool)
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
                args[0].as_slice(&self.dfg.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", "),
                destinations[1],
                args[1].as_slice(&self.dfg.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::Call { func_id, args, .. } => s.push_str(&format!(
                "call {} ({})",
                func_id,
                args.as_slice(&self.dfg.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::CallIntrinsic { callee, args, .. } => s.push_str(&format!(
                "call {:?} ({})",
                callee,
                args.as_slice(&self.dfg.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::CallHook { hook_id, args } => s.push_str(&format!(
                "call_hook {} ({})",
                hook_id,
                args.as_slice(&self.dfg.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::CallExt { func_id, args } => s.push_str(&format!(
                "call_ext {} ({})",
                func_id,
                args.as_slice(&self.dfg.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::CallIndirect { callee, args } => s.push_str(&format!(
                "call_indirect {} ({})",
                self.fmt_value(*callee),
                args.as_slice(&self.dfg.values_pool)
                    .iter()
                    .map(|a| self.fmt_value(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            InstructionData::Return { args } => s.push_str(&format!(
                "return {}",
                args.as_slice(&self.dfg.values_pool)
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
        if let Some(entry) = self.layout.entry_block() {
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
