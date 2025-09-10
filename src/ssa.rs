/// A minimal SSA-based intermediate representation.
use std::fmt;
use std::hash::Hash;
use std::collections::{HashMap, HashSet};

use smallvec::{smallvec, SmallVec};

//-////////////////////////////////////////////////////////////////////
// Entity References
//
// We use newtype wrappers for indices to provide type safety.
// This pattern is common in compilers (e.g., Cranelift, rustc).

/// A macro to create a new entity reference type.
macro_rules! entity_ref {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(u32);

        impl $name {
            #[must_use]
            pub fn new(index: usize) -> Self {
                Self(index as u32)
            }

            #[must_use]
            pub fn index(self) -> usize {
                self.0 as usize
            }
        }

        impl std::ops::Deref for $name {
            type Target = u32;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name).to_lowercase(), self.0)
            }
        }
    };
}

entity_ref!(Value);
entity_ref!(Inst);
entity_ref!(Block);
entity_ref!(StackSlot);
entity_ref!(FuncId);

//-////////////////////////////////////////////////////////////////////
// Core Data Structures
//

/// Represents a data type in the IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    I32, I64, F32, F64, Ptr
}

impl Type {
    #[must_use]
    pub const fn bytes(self) -> u32 {
        match self {
            Type::I32 | Type::F32 => 4,
            Type::I64 | Type::F64 | Type::Ptr => 8,
        }
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.bytes() * 8
    }

    #[must_use]
    pub const fn align_bytes(self) -> u32 {
        match self {
            Type::I32 | Type::F32 => 4,
            Type::I64 | Type::F64 | Type::Ptr => 8,
        }
    }

    #[must_use]
    pub const fn align_bits(self) -> u32 {
        self.align_bytes() * 8
    }
}

/// Represents a function signature.
#[derive(Debug, Clone, Default)]
pub struct Signature {
    pub params: Vec<Type>,
    pub returns: Vec<Type>,
}

/// The core data flow graph, containing all instructions and values.
#[derive(Debug, Clone, Default)]
pub struct DataFlowGraph {
    pub insts: Vec<InstructionData>,
    pub values: Vec<ValueData>,
    pub inst_results: HashMap<Inst, SmallVec<[Value; 2]>>,
}

impl DataFlowGraph {
    pub fn make_value(&mut self, data: ValueData) -> Value {
        let id = Value::new(self.values.len());
        self.values.push(data);
        id
    }

    pub fn make_inst(&mut self, data: InstructionData) -> Inst {
        let id = Inst::new(self.insts.len());
        self.insts.push(data);
        id
    }
}

/// The control flow graph, containing all basic blocks.
#[derive(Debug, Clone, Default)]
pub struct ControlFlowGraph {
    pub blocks: Vec<BasicBlockData>,
    pub predecessors: HashMap<Block, SmallVec<[Block; 4]>>,
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
    pub fn new(name: impl AsRef<str>, signature: Signature) -> Self {
        Self {
            name: name.as_ref().into(),
            signature,
            ..Default::default()
        }
    }

    pub fn create_stack_slot(&mut self, ty: Type, size: u32) -> StackSlot {
        let id = StackSlot::new(self.stack_slots.len());
        self.stack_slots.push(StackSlotData { ty, size });
        id
    }

    /// Return the Type of a Value (assumes `ValueData` has `ty` field).
    #[must_use]
    pub fn value_type(&self, v: Value) -> Type {
        // adjust field name if your ValueData uses a different name
        self.dfg.values[v.index()].ty
    }

    #[inline]
    pub fn instruction_data(&self, inst: Inst) -> &InstructionData {
        &self.dfg.insts[inst.index()]
    }

    #[inline]
    pub fn pretty_print_inst(&self, inst: Inst) -> String {
        let mut inst_string = String::with_capacity(128);
        self.fmt_inst(&mut inst_string, inst).unwrap();
        inst_string
    }
}

/// Maps logical entities (Inst, Block) to their container.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    pub inst_blocks: HashMap<Inst, Block>,
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
}

//-////////////////////////////////////////////////////////////////////
// Instructions & Values
//

#[derive(Debug, Clone)]
pub enum InstructionData {
    Binary { opcode: BinaryOp, args: [Value; 2] },
    IConst { value: i64 },
    FConst { value: f64 },
    Jump { destination: Block },
    Branch { destinations: [Block; 2], arg: Value },
    Call { func_id: FuncId, args: SmallVec<[Value; 8]> },
    Return { args: SmallVec<[Value; 2]> },
    StackLoad { slot: StackSlot },
    StackAddr { slot: StackSlot },
    StackStore { slot: StackSlot, arg: Value },
    Nop,
}

impl InstructionData {
    pub fn bits(&self, inst_id: Inst, context: &SsaFunc) -> u32 {
        let vbits = |v: &Value|  context.dfg.values[v.index()].ty.bits();
        let rbits = |idx: usize| {
            let r = &context.dfg.inst_results[&inst_id];
            context.dfg.values[r[idx].index()].ty.bits()
        };

        match self {
            Self::Binary { args, .. } => vbits(&args[0]),
            Self::IConst { .. } => rbits(0),
            Self::FConst { .. } => rbits(0),
            Self::StackLoad { .. } => rbits(0),
            Self::StackAddr { .. } => rbits(0),
            Self::StackStore { arg, .. } => vbits(arg),

            Self::Jump { .. } => 32,
            Self::Branch { .. } => 32,
            Self::Call { .. } => 32,
            Self::Return { .. } => 32,
            Self::Nop => 32,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BinaryOp {
    IAdd, ISub, IMul, ILt,
    FAdd, FSub, FMul, FDiv,
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

#[derive(Debug, Clone, Default)]
pub struct Module {
    pub functions: Vec<SsaFunc>,
}

impl Module {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn declare_function(&mut self, name: impl AsRef<str>, signature: Signature) -> FuncId {
        let id = FuncId::new(self.functions.len());
        self.functions.push(SsaFunc {
            name: name.as_ref().into(),
            signature,
            metadata: FunctionMetadata {
                is_external: true,
            },
            ..Default::default()
        });
        id
    }

    pub fn define_function(&mut self, _id: FuncId) {
        // ...
    }

    pub fn get_func_mut(&mut self, id: FuncId) -> &mut SsaFunc {
        &mut self.functions[id.index()]
    }
}

//-////////////////////////////////////////////////////////////////////
// Function Builder
//

pub struct FunctionBuilder<'a> {
    func: &'a mut SsaFunc,
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

    #[inline(always)]
    pub fn create_stack_slot(&mut self, ty: Type, size: u32) -> StackSlot {
        self.func.create_stack_slot(ty, size)
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
    fn make_inst_result(&mut self, inst: Inst, ty: Type, result_idx: u8) -> Value {
        let value = self.builder.func.dfg.make_value(ValueData {
            ty,
            def: ValueDef::Inst { inst, result_idx },
        });
        self.builder.func.dfg.inst_results.entry(inst).or_default().push(value);
        value
    }

    #[inline]
    pub fn iconst(&mut self, ty: Type, val: i64) -> Value {
        let inst = self.insert_inst(InstructionData::IConst { value: val });
        self.make_inst_result(inst, ty, 0)
    }

    #[inline]
    pub fn iadd(&mut self, lhs: Value, rhs: Value) -> Value {
        let ty = self.builder.func.dfg.values[lhs.index()].ty;
        let inst = self.insert_inst(InstructionData::Binary { opcode: BinaryOp::IAdd, args: [lhs, rhs] });
        self.make_inst_result(inst, ty, 0)
    }

    #[inline]
    pub fn ilt(&mut self, lhs: Value, rhs: Value) -> Value {
        let ty = Type::I64; // Result of comparison is a boolean, but we use i64 for now
        let inst = self.insert_inst(InstructionData::Binary { opcode: BinaryOp::ILt, args: [lhs, rhs] });
        self.make_inst_result(inst, ty, 0)
    }

    #[inline]
    pub fn isub(&mut self, lhs: Value, rhs: Value) -> Value {
        let ty = self.builder.func.dfg.values[lhs.index()].ty;
        let inst = self.insert_inst(InstructionData::Binary { opcode: BinaryOp::ISub, args: [lhs, rhs] });
        self.make_inst_result(inst, ty, 0)
    }

    #[inline]
    pub fn fadd(&mut self, lhs: Value, rhs: Value) -> Value {
        let ty = self.builder.func.dfg.values[lhs.index()].ty;
        let inst = self.insert_inst(InstructionData::Binary { opcode: BinaryOp::FAdd, args: [lhs, rhs] });
        self.make_inst_result(inst, ty, 0)
    }

    #[inline]
    pub fn fsub(&mut self, lhs: Value, rhs: Value) -> Value {
        let ty = self.builder.func.dfg.values[lhs.index()].ty;
        let inst = self.insert_inst(InstructionData::Binary { opcode: BinaryOp::FSub, args: [lhs, rhs] });
        self.make_inst_result(inst, ty, 0)
    }

    #[inline]
    pub fn fmul(&mut self, lhs: Value, rhs: Value) -> Value {
        let ty = self.builder.func.dfg.values[lhs.index()].ty;
        let inst = self.insert_inst(InstructionData::Binary { opcode: BinaryOp::FMul, args: [lhs, rhs] });
        self.make_inst_result(inst, ty, 0)
    }

    #[inline]
    pub fn fdiv(&mut self, lhs: Value, rhs: Value) -> Value {
        let ty = self.builder.func.dfg.values[lhs.index()].ty;
        let inst = self.insert_inst(InstructionData::Binary { opcode: BinaryOp::FDiv, args: [lhs, rhs] });
        self.make_inst_result(inst, ty, 0)
    }

    #[inline]
    pub fn fconst(&mut self, ty: Type, val: f64) -> Value {
        let inst = self.insert_inst(InstructionData::FConst { value: val });
        self.make_inst_result(inst, ty, 0)
    }

    #[inline]
    pub fn stack_addr(&mut self, ty: Type, slot: StackSlot) -> Value {
        let inst = self.insert_inst(InstructionData::StackLoad { slot });
        self.make_inst_result(inst, ty, 0)
    }

    #[inline]
    pub fn stack_load(&mut self, ty: Type, slot: StackSlot) -> Value {
        let inst = self.insert_inst(InstructionData::StackLoad { slot });
        self.make_inst_result(inst, ty, 0)
    }

    #[inline]
    pub fn stack_store(&mut self, slot: StackSlot, val: Value) {
        self.insert_inst(InstructionData::StackStore { slot, arg: val });
    }

    #[inline]
    pub fn jump(&mut self, dest: Block) {
        self.insert_inst(InstructionData::Jump { destination: dest });
        let from = self.position.current_block;
        self.builder.func.cfg.add_pred(from, dest);
    }

    #[inline]
    pub fn brif(&mut self, cond: Value, true_dest: Block, false_dest: Block) {
        self.insert_inst(InstructionData::Branch { destinations: [true_dest, false_dest], arg: cond });
        let from = self.position.current_block;
        self.builder.func.cfg.add_pred(from, true_dest);
        self.builder.func.cfg.add_pred(from, false_dest);
    }

    #[inline]
    pub fn call(&mut self, func_id: FuncId, args: &[Value]) -> SmallVec<[Value; 2]> {
        let inst = self.insert_inst(InstructionData::Call { func_id, args: args.into() });
        let result_ty = Type::I64; // TODO: Get from function signature
        let result = self.make_inst_result(inst, result_ty, 0);
        smallvec![result]
    }

    #[inline]
    pub fn ret(&mut self, vals: &[Value]) {
        self.insert_inst(InstructionData::Return { args: vals.into() });
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
        write!(f, "  ")?;
        if let Some(results) = self.dfg.inst_results.get(&inst_id) {
            if !results.is_empty() {
                write!(f, "{}", results.iter().map(|r| self.fmt_value(*r)).collect::<Vec<_>>().join(", "))?;
                write!(f, " = ")?;
            }
        }
        match inst {
            InstructionData::Binary { opcode, args } => write!(f, "{:?} {}, {}", opcode, self.fmt_value(args[0]), self.fmt_value(args[1])),
            InstructionData::IConst { value } => write!(f, "iconst {value}"),
            InstructionData::FConst { value } => write!(f, "fconst {value}"),
            InstructionData::Jump { destination } => write!(f, "jump {destination}"),
            InstructionData::Branch { destinations, arg } => write!(f, "brif {}, {}, {}", self.fmt_value(*arg), destinations[0], destinations[1]),
            InstructionData::Call { func_id, args } => write!(f, "call F{}, ({})", func_id.index(), args.iter().map(|a| self.fmt_value(*a)).collect::<Vec<_>>().join(", ")),
            InstructionData::Return { args } => write!(f, "return {}", args.iter().map(|v| self.fmt_value(*v)).collect::<Vec<_>>().join(", ")),
            InstructionData::StackAddr { slot } => write!(f, "stack_addr {slot}"),
            InstructionData::StackLoad { slot } => write!(f, "stack_load {slot}"),
            InstructionData::StackStore { slot, arg } => write!(f, "stack_store {}, {}", slot, self.fmt_value(*arg)),
            InstructionData::Nop => write!(f, "nop"),
        }
    }

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
        if let Some(entry) = self.layout.block_entry {
            let mut visited = HashSet::new();
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
