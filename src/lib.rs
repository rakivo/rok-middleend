//! A minimal SSA-based intermediate representation.
use hashbrown::{HashMap, HashSet};
use smallvec::{smallvec, SmallVec};
use std::fmt;
use std::hash::Hash;

pub mod bytecode;
pub mod vm;

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
    IAdd, ISub, IMul,
    IConst(i64),
    Load, Store,
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

//-////////////////////////////////////////////////////////////////////
// Lowering to Bytecode
//

use bytecode::{BytecodeChunk, Register};
use std::collections::BTreeMap;

const NUM_REGISTERS: u8 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LiveInterval { start: u32, end: u32 }

struct LoweringContext<'a> {
    func: &'a Function,
    live_intervals: HashMap<Value, LiveInterval>,
    value_locations: HashMap<Value, ValueLocation>,
    block_order: Vec<Block>,
    inst_positions: HashMap<Inst, u32>,
    block_offsets: HashMap<Block, u32>,
}

#[derive(Debug, Clone, Copy)]
enum ValueLocation {
    Reg(Register),
    Stack(StackSlot),
}

impl Function {
    pub fn lower_to_bytecode(&self) -> BytecodeChunk {
        fn opcode_name(b: u8) -> &'static str {
            use bytecode::Opcode::*;
            match b {
                x if x == Nop as u8 => "Nop",
                x if x == Mov as u8 => "Mov",
                x if x == LoadConst as u8 => "LoadConst",
                x if x == IAdd as u8 => "IAdd",
                x if x == ISub as u8 => "ISub",
                x if x == LoadStack as u8 => "LoadStack",
                x if x == StoreStack as u8 => "StoreStack",
                x if x == Jmp as u8 => "Jmp",
                x if x == JmpIfZero as u8 => "JmpIfZero",
                x if x == Call as u8 => "Call",
                x if x == Ret as u8 => "Ret",
                _ => "Unknown",
            }
        }

        fn dump_region(code: &[u8], center: usize, radius: usize) -> String {
            let start = center.saturating_sub(radius);
            let end = (center + radius).min(code.len());
            let mut s = String::new();
            for i in start..end {
                if i == center {
                    s.push_str(&format!("-> {:04} {:02X} ({})\n", i, code[i], opcode_name(code[i])));
                } else {
                    s.push_str(&format!("   {:04} {:02X} ({})\n", i, code[i], opcode_name(code[i])));
                }
            }
            s
        }

        let mut ctx = self.build_lowering_context();
        ctx.linear_scan_register_alloc();
        let mut chunk = BytecodeChunk::default();
        let mut backpatch_info = Vec::new();

        for &block in &ctx.block_order {
            ctx.block_offsets.insert(block, chunk.code.len() as u32);
            for &inst in &self.cfg.blocks[block.index()].insts {
                let opcode = &self.dfg.insts[inst.index()].opcode;
                match opcode {
                    Opcode::IConst(val) => {
                        let res = self.dfg.inst_results[&inst][0];
                        if let Some(ValueLocation::Reg(dst)) = ctx.value_locations.get(&res) {
                            chunk.write_u8(bytecode::Opcode::LoadConst as u8);
                            chunk.write_u8(dst.0);
                            let const_idx = chunk.constants.len() as u16;
                            chunk.constants.push(*val);
                            chunk.write_u16(const_idx);
                        }
                    }
                    Opcode::IAdd => {
                        let r_dst = ctx.get_reg(self.dfg.inst_results[&inst][0]);
                        let r_lhs = ctx.get_reg(self.dfg.insts[inst.index()].args[0]);
                        let r_rhs = ctx.get_reg(self.dfg.insts[inst.index()].args[1]);
                        chunk.write_u8(bytecode::Opcode::IAdd as u8);
                        chunk.write_u8(r_dst.0);
                        chunk.write_u8(r_lhs.0);
                        chunk.write_u8(r_rhs.0);
                    }
                    Opcode::ISub => {
                        let r_dst = ctx.get_reg(self.dfg.inst_results[&inst][0]);
                        let r_lhs = ctx.get_reg(self.dfg.insts[inst.index()].args[0]);
                        let r_rhs = ctx.get_reg(self.dfg.insts[inst.index()].args[1]);
                        chunk.write_u8(bytecode::Opcode::ISub as u8);
                        chunk.write_u8(r_dst.0);
                        chunk.write_u8(r_lhs.0);
                        chunk.write_u8(r_rhs.0);
                    }
                    Opcode::Jump(target) => {
                        chunk.write_u8(bytecode::Opcode::Jmp as u8);
                        let pos = chunk.code.len(); // index of first offset byte to be written
                        chunk.write_i16(0); // Placeholder
                        backpatch_info.push((pos, *target));
                        eprintln!(
                            "[lower] wrote Jmp at pos={} (after opcode), block={:?}, code_len(before)={}",
                            pos,
                            block,
                            chunk.code.len()
                        );
                    }
                    Opcode::BranchIf(cond, true_dest, _false_dest) => {
                        let r_cond = ctx.get_reg(*cond);
                        chunk.write_u8(bytecode::Opcode::JmpIfZero as u8);
                        chunk.write_u8(r_cond.0);
                        let pos = chunk.code.len(); // index of first offset byte
                        chunk.write_i16(0); // Placeholder
                        backpatch_info.push((pos, *true_dest));
                        eprintln!(
                            "[lower] wrote JmpIfZero at pos={} (after cond), block={:?}, cond_reg={}, code_len(before)={}",
                            pos,
                            block,
                            r_cond.0,
                            chunk.code.len()
                        );
                    }
                    Opcode::Return(vals) => {
                        chunk.write_u8(bytecode::Opcode::Ret as u8);
                        chunk.write_u8(ctx.get_reg(vals[0]).0);
                    }
                    Opcode::Call(_func_ref, args) => {
                        let r_dst = ctx.get_reg(self.dfg.inst_results[&inst][0]);
                        let mut r_args = [Register(0); 4];
                        for (i, arg) in args.iter().enumerate() {
                            r_args[i] = ctx.get_reg(*arg);
                        }
                        chunk.write_u8(bytecode::Opcode::Call as u8);
                        chunk.write_u8(r_dst.0);
                        chunk.write_u16(0); // func_id placeholder
                        for r_arg in &r_args {
                            chunk.write_u8(r_arg.0);
                        }
                    }

                    _ => panic!("Unsupported opcode during lowering: {:?}", opcode),
                }
            }
        }

        // Summary before patching
        eprintln!("=== Lowering complete ===");
        eprintln!("code length: {}", chunk.code.len());
        eprintln!("constants len: {}", chunk.constants.len());
        eprintln!("block offsets:");
        for (b, off) in ctx.block_offsets.iter() {
            eprintln!("  {:?} -> {}", b, off);
        }
        eprintln!("backpatch entries (inst_pos -> target_block):");
        for (pos, tb) in &backpatch_info {
            eprintln!("  pos={} target={:?}", pos, tb);
        }
        // Show first 128 bytes disassembly for quick view
        let show_len = chunk.code.len().min(128);
        if show_len > 0 {
            eprintln!("code[0..{}] hex/ops:", show_len);
            for i in 0..show_len {
                eprint!("{:02X} ", chunk.code[i]);
                if (i + 1) % 16 == 0 {
                    eprintln!();
                }
            }
            eprintln!("\n---");
        }

        // Backpatch loop with logging
        for (inst_pos, target_block) in backpatch_info {
            let target_offset = ctx.block_offsets[&target_block] as i32;
            let inst_offset = inst_pos as i32;
            // keep existing behavior but log everything
            let rel = target_offset - (inst_offset + 2);
            eprintln!("--- backpatching at pos={} ---", inst_pos);
            eprintln!(" target_block={:?}", target_block);
            eprintln!(" target_offset={} (absolute)", target_offset);
            eprintln!(" inst_offset={} (offset index of first i16 byte)", inst_offset);
            eprintln!(" computed relative (target - (inst + 2)) = {}", rel);

            // sanity checks
            if target_offset < 0 || target_offset as usize > chunk.code.len() {
                eprintln!(
                    "!! warning: target_offset {} outside code bounds (code_len={})",
                    target_offset,
                    chunk.code.len()
                );
            }

            // show surrounding bytes where jump src lives
            let src_center = (inst_pos.saturating_sub(4)).min(chunk.code.len().saturating_sub(1));
            eprintln!(" bytes near source (inst_pos={}):\n{}", inst_pos, dump_region(&chunk.code, src_center, 12));

            // show surrounding bytes where we expect to land
            let tgt_center = (target_offset as usize).saturating_sub(4).min(chunk.code.len().saturating_sub(1));
            eprintln!(" bytes near target (target_offset={}):\n{}", target_offset, dump_region(&chunk.code, tgt_center, 12));

            // apply patch
            chunk.patch_i16(inst_pos, rel as i16);

            // print patched bytes
            let b0 = chunk.code.get(inst_pos).cloned().unwrap_or(0);
            let b1 = chunk.code.get(inst_pos + 1).cloned().unwrap_or(0);
            eprintln!(
                " patched bytes at {}: {:02X} {:02X} -> interpreted i16 = {}",
                inst_pos,
                b0,
                b1,
                i16::from_le_bytes([b0, b1])
            );
        }

        eprintln!("=== Backpatching complete. final code length={} ===", chunk.code.len());
        chunk
    }

    fn build_lowering_context(&self) -> LoweringContext {
        let mut block_order = Vec::new();
        let mut visited = HashSet::new();
        let mut worklist = vec![self.layout.block_entry.unwrap()];
        while let Some(block) = worklist.pop() {
            if visited.insert(block) {
                block_order.push(block);
                let term = self.dfg.insts[self.cfg.blocks[block.index()].insts.last().unwrap().index()].opcode.clone();
                match term {
                    Opcode::Jump(dest) => worklist.push(dest),
                    Opcode::BranchIf(_, t, f) => { worklist.push(f); worklist.push(t); },
                    _ => {}
                }
            }
        }

        let mut inst_positions = HashMap::new();
        let mut current_pos = 0;
        for &block in &block_order {
            for &inst in &self.cfg.blocks[block.index()].insts {
                inst_positions.insert(inst, current_pos);
                current_pos += 1;
            }
        }

        let mut live_intervals = HashMap::new();
        for (inst, &pos) in &inst_positions {
            for &arg in &self.dfg.insts[inst.index()].args {
                let interval = live_intervals.entry(arg).or_insert(LiveInterval { start: pos, end: pos });
                interval.end = interval.end.max(pos);
            }
            if let Some(results) = self.dfg.inst_results.get(inst) {
                for &res in results {
                    let interval = live_intervals.entry(res).or_insert(LiveInterval { start: pos, end: pos });
                    interval.start = pos;
                }
            }
        }

        LoweringContext {
            func: self,
            live_intervals,
            value_locations: HashMap::new(),
            block_order,
            inst_positions,
            block_offsets: HashMap::new(),
        }
    }
}

impl<'a> LoweringContext<'a> {
    fn get_reg(&self, val: Value) -> Register {
        match self.value_locations.get(&val) {
            Some(ValueLocation::Reg(r)) => *r,
            _ => panic!("Value {:?} not in a register", val),
        }
    }

    fn linear_scan_register_alloc(&mut self) {
        let mut intervals: Vec<_> = self.live_intervals.iter().collect();
        intervals.sort_by_key(|(_, int)| int.start);
        let mut active: BTreeMap<u32, Value> = BTreeMap::new();
        let mut free_registers: Vec<_> = (1..NUM_REGISTERS).map(Register).collect();

        // Pre-assign the first argument to r0
        if let Some(arg0) = self.func.signature.params.get(0).map(|_| self.func.dfg.values.iter().position(|v| matches!(v.def, ValueDef::Param { block, param_idx: 0 } if block.index() == 0)).map(|i| Value::new(i))).flatten() {
            self.value_locations.insert(arg0, ValueLocation::Reg(Register(0)));
            active.insert(self.live_intervals[&arg0].end, arg0);
        }

        for (&value, interval) in intervals {
            let mut expired = vec![];
            for (&end, &val) in &active {
                if end >= interval.start { break; }
                expired.push(end);
                if let Some(ValueLocation::Reg(reg)) = self.value_locations.get(&val) {
                    free_registers.push(*reg);
                }
            }
            for end in expired { active.remove(&end); }

            if let Some(reg) = free_registers.pop() {
                self.value_locations.insert(value, ValueLocation::Reg(reg));
                active.insert(interval.end, value);
            } else {
                let slot = self.func.stack_slots.iter().enumerate().find(|(_, _)| true).map(|(i, _)| StackSlot::new(i)).unwrap();
                self.value_locations.insert(value, ValueLocation::Stack(slot));
            }
        }
    }
}
