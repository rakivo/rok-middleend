use bytecode_cl::{Function, FunctionBuilder, Type, Signature, FunctionRef};
use bytecode_cl::bytecode::{LoweringContext};

fn main() {
    let mut func = Function {
        name: "fib".to_string(),
        signature: Signature {
            params: vec![Type::I64],
            returns: vec![Type::I64],
        },
        ..Default::default()
    };

    let mut builder = FunctionBuilder::new(&mut func);

    let _entry_block = builder.current_block();
    let arg_n = builder.add_block_params(&[Type::I64])[0];

    let recur_block = builder.create_block();
    let ret_n_block = builder.create_block();

    let v1 = builder.ins().iconst(Type::I64, 2);
    let v2 = builder.ins().ilt(arg_n, v1);
    builder.ins().brif(v2, ret_n_block, recur_block);

    builder.switch_to_block(recur_block);
    let v1_minus = builder.ins().iconst(Type::I64, 1);
    let v3 = builder.ins().isub(arg_n, v1_minus);
    let v4 = builder.ins().call(FunctionRef::Name("fib".to_string()), &[v3])[0];
    let v5 = builder.ins().iconst(Type::I64, 2);
    let v6 = builder.ins().isub(arg_n, v5);
    let v7 = builder.ins().call(FunctionRef::Name("fib".to_string()), &[v6])[0];
    let v8 = builder.ins().iadd(v4, v7);
    builder.ins().ret(&[v8]);

    builder.switch_to_block(ret_n_block);
    builder.ins().ret(&[arg_n]);

    println!("Original SSA IR:");
    println!("{}", func);

    let lowerer = LoweringContext::new(&func);
    let lowered_func = lowerer.lower();

    println!("\nLowered Bytecode:");
    bytecode_cl::bytecode::disassemble_chunk(&lowered_func, &func.name);
}
