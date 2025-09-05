pub mod bytecode;

/// A minimal SSA-based intermediate representation.
use hashbrown::{HashMap, HashSet};
use smallvec::{smallvec, SmallVec};
use std::fmt;
use std::hash::Hash;

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
            pub fn new(index: usize) -> Self {
                Self(index as u32)
            }

            pub fn index(self) -> usize {
                self.0 as usize
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name).to_lowercase(), self.0)
            }
        }
    };
}

entity_ref!(Value);
entity_ref!(Inst);
entity_ref!(Block);
entity_ref!(StackSlot);

//-////////////////////////////////////////////////////////////////////
// Core Data Structures
//

/// Represents a data type in the IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    I32,
    I64,
    F32,
    F64,
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
}

/// The top-level structure for a single function's IR.
#[derive(Debug, Clone, Default)]
pub struct Function {
    pub name: String,
    pub signature: Signature,
    pub dfg: DataFlowGraph,
    pub cfg: ControlFlowGraph,
    pub layout: Layout,
    pub stack_slots: Vec<StackSlotData>,
    pub metadata: FunctionMetadata,
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
pub struct FunctionMetadata {}

//-////////////////////////////////////////////////////////////////////
// Instructions & Values
//

#[derive(Debug, Clone)]
pub struct InstructionData {
    pub opcode: Opcode,
    pub args: SmallVec<[Value; 4]>,
}

#[derive(Debug, Clone)]
pub enum Opcode {
    IAdd, ISub, IMul, ILt,
    IConst(i64),
    Jump(Block),
    BranchIf(Value, Block, Block),
    Call(FunctionRef, SmallVec<[Value; 8]>),
    Return(SmallVec<[Value; 2]>),
    Nop,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FunctionRef {
    Name(String),
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

//-////////////////////////////////////////////////////////////////////
// Function Builder
//

pub struct FunctionBuilder<'a> {
    func: &'a mut Function,
    cursor: Cursor,
}

#[derive(Debug, Clone, Copy)]
struct Cursor {
    current_block: Block,
}

impl<'a> FunctionBuilder<'a> {
    pub fn new(func: &'a mut Function) -> Self {
        let entry_block = if let Some(block) = func.layout.block_entry {
            block
        } else {
            let block = Block::new(func.cfg.blocks.len());
            func.cfg.blocks.push(Default::default());
            func.layout.block_entry = Some(block);
            block
        };
        Self { func, cursor: Cursor { current_block: entry_block } }
    }

    pub fn create_block(&mut self) -> Block {
        let id = Block::new(self.func.cfg.blocks.len());
        self.func.cfg.blocks.push(Default::default());
        id
    }

    pub fn switch_to_block(&mut self, block: Block) {
        self.cursor.current_block = block;
    }

    pub fn current_block(&self) -> Block {
        self.cursor.current_block
    }

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

    pub fn ins<'b>(&'b mut self) -> InstBuilder<'a, 'b> {
        let position = self.cursor;
        InstBuilder { builder: self, position }
    }

    pub fn create_stack_slot(&mut self, ty: Type, size: u32) -> StackSlot {
        let id = StackSlot::new(self.func.stack_slots.len());
        self.func.stack_slots.push(StackSlotData { ty, size });
        id
    }
}

pub struct InstBuilder<'a, 'b> {
    builder: &'b mut FunctionBuilder<'a>,
    position: Cursor,
}

impl<'a, 'b> InstBuilder<'a, 'b> {
    fn insert_inst(&mut self, data: InstructionData) -> Inst {
        let inst = self.builder.func.dfg.make_inst(data);
        let block = self.position.current_block;
        self.builder.func.cfg.blocks[block.index()].insts.push(inst);
        self.builder.func.layout.inst_blocks.insert(inst, block);
        inst
    }

    fn make_inst_result(&mut self, inst: Inst, ty: Type, result_idx: u8) -> Value {
        let value = self.builder.func.dfg.make_value(ValueData {
            ty,
            def: ValueDef::Inst { inst, result_idx },
        });
        self.builder.func.dfg.inst_results.entry(inst).or_default().push(value);
        value
    }

    pub fn iconst(&mut self, ty: Type, val: i64) -> Value {
        let inst = self.insert_inst(InstructionData { opcode: Opcode::IConst(val), args: smallvec![] });
        self.make_inst_result(inst, ty, 0)
    }

    pub fn iadd(&mut self, lhs: Value, rhs: Value) -> Value {
        let ty = self.builder.func.dfg.values[lhs.index()].ty;
        let inst = self.insert_inst(InstructionData { opcode: Opcode::IAdd, args: smallvec![lhs, rhs] });
        self.make_inst_result(inst, ty, 0)
    }

    pub fn ilt(&mut self, lhs: Value, rhs: Value) -> Value {
        let ty = Type::I64; // Result of comparison is a boolean, but we use i64 for now
        let inst = self.insert_inst(InstructionData { opcode: Opcode::ILt, args: smallvec![lhs, rhs] });
        self.make_inst_result(inst, ty, 0)
    }

    pub fn isub(&mut self, lhs: Value, rhs: Value) -> Value {
        let ty = self.builder.func.dfg.values[lhs.index()].ty;
        let inst = self.insert_inst(InstructionData { opcode: Opcode::ISub, args: smallvec![lhs, rhs] });
        self.make_inst_result(inst, ty, 0)
    }

    pub fn jump(&mut self, dest: Block) {
        self.insert_inst(InstructionData { opcode: Opcode::Jump(dest), args: smallvec![] });
        let from = self.position.current_block;
        self.builder.func.cfg.add_pred(from, dest);
    }

    pub fn brif(&mut self, cond: Value, true_dest: Block, false_dest: Block) {
        self.insert_inst(InstructionData { opcode: Opcode::BranchIf(cond, true_dest, false_dest), args: smallvec![cond] });
        let from = self.position.current_block;
        self.builder.func.cfg.add_pred(from, true_dest);
        self.builder.func.cfg.add_pred(from, false_dest);
    }

    pub fn call(&mut self, func_ref: FunctionRef, args: &[Value]) -> SmallVec<[Value; 2]> {
        let inst = self.insert_inst(InstructionData { opcode: Opcode::Call(func_ref, args.into()), args: args.into() });
        let result_ty = Type::I64;
        let result = self.make_inst_result(inst, result_ty, 0);
        smallvec![result]
    }

    pub fn ret(&mut self, vals: &[Value]) {
        self.insert_inst(InstructionData { opcode: Opcode::Return(vals.into()), args: vals.into() });
    }
}

//-////////////////////////////////////////////////////////////////////
// Analysis & Pretty Printing
//

impl Function {
    pub fn map_ssa_to_stack(&mut self) -> HashMap<Value, StackSlot> {
        let mut mapping = HashMap::new();
        for i in 0..self.dfg.values.len() {
            let value = Value::new(i);
            let value_data = &self.dfg.values[value.index()];
            let slot = self.create_stack_slot(value_data.ty, 8);
            mapping.insert(value, slot);
        }
        mapping
    }

    fn create_stack_slot(&mut self, ty: Type, size: u32) -> StackSlot {
        let id = StackSlot::new(self.stack_slots.len());
        self.stack_slots.push(StackSlotData { ty, size });
        id
    }

    fn fmt_block(&self, f: &mut fmt::Formatter<'_>, block_id: Block) -> fmt::Result {
        let block_data = &self.cfg.blocks[block_id.index()];
        write!(f, "{}:", block_id)?;
        if !block_data.params.is_empty() {
            write!(f, "({})", block_data.params.iter().map(|v| self.fmt_value(*v)).collect::<Vec<_>>().join(", "))?;
        }
        if let Some(preds) = self.cfg.predecessors.get(&block_id) {
            write!(f, "  ; preds: {}", preds.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "))?;
        }
        writeln!(f)?;
        for &inst_id in &block_data.insts {
            self.fmt_inst(f, inst_id)?;
        }
        Ok(())
    }

    fn fmt_inst(&self, f: &mut fmt::Formatter<'_>, inst_id: Inst) -> fmt::Result {
        let inst = &self.dfg.insts[inst_id.index()];
        write!(f, "  ")?;
        if let Some(results) = self.dfg.inst_results.get(&inst_id) {
            if !results.is_empty() {
                write!(f, "{}", results.iter().map(|r| self.fmt_value(*r)).collect::<Vec<_>>().join(", "))?;
                write!(f, " = ")?;
            }
        }
        match &inst.opcode {
            Opcode::IConst(val) => write!(f, "iconst {}", val)?,
            Opcode::IAdd => write!(f, "iadd {}, {}", self.fmt_value(inst.args[0]), self.fmt_value(inst.args[1]))?,
            Opcode::ISub => write!(f, "isub {}, {}", self.fmt_value(inst.args[0]), self.fmt_value(inst.args[1]))?,
            Opcode::Jump(dest) => write!(f, "jump {}", dest)?,
            Opcode::BranchIf(cond, t, fa) => write!(f, "brif {}, {}, {}", self.fmt_value(*cond), t, fa)?,
            Opcode::Call(name, args) => write!(f, "call {:?}, ({})", name, args.iter().map(|a| self.fmt_value(*a)).collect::<Vec<_>>().join(", "))?,
            Opcode::Return(vals) => write!(f, "return {}", vals.iter().map(|v| self.fmt_value(*v)).collect::<Vec<_>>().join(", "))?,
            _ => write!(f, "{:?}", inst.opcode)?,
        }
        writeln!(f)
    }

    fn fmt_value(&self, val: Value) -> String {
        let data = &self.dfg.values[val.index()];
        format!("{}:{:?}", val, data.ty)
    }
}

impl fmt::Display for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "function {}({}) -> {}", self.name,
            self.signature.params.iter().map(|t| format!("{:?}", t)).collect::<Vec<_>>().join(", "),
            self.signature.returns.iter().map(|t| format!("{:?}", t)).collect::<Vec<_>>().join(", ")
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
                    match &inst_data.opcode {
                        Opcode::Jump(dest) => worklist.push(*dest),
                        Opcode::BranchIf(_, t, fa) => { worklist.push(*fa); worklist.push(*t); },
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}
