use bytecode_cl::{Function, FunctionBuilder, Signature, Type, StackSlotKind};

fn main() {
    let mut func = Function {
        name: "stack_demo".to_string(),
        signature: Signature::default(),
        ..Default::default()
    };
    let mut builder = FunctionBuilder::new(&mut func);

    let entry_block = builder.current_block();

    let ss = builder.create_sized_stack_slot(StackSlotKind::Explicit, Type::I64, 8);

    let mut ib = builder.ins();
    let v1 = ib.iconst(Type::I64, 10);
    ib.stack_store(ss, v1);
    let v2 = ib.stack_load(Type::I64, ss);
    let v3 = ib.iconst(Type::I64, 20);
    let res = ib.iadd(v2, v3);
    ib.ret(&[res]);

    println!("{}", func);
}
