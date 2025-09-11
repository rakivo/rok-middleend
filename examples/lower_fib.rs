use rok_bytecode::vm::VirtualMachine;
use rok_bytecode::lower::{LoweringContext};
use rok_bytecode::bytecode::disassemble_chunk;
use rok_bytecode::ssa::{FunctionBuilder, Type, Signature, Module};

fn main() {
    let mut module = Module::new();

    let sig = Signature {
        params: vec![Type::I64],
        returns: vec![Type::I64],
    };
    let fib_id = module.declare_function("fib", sig);

    let fib_func = module.get_func_mut(fib_id);
    let mut builder = FunctionBuilder::new(fib_func);
    let result_slot = builder.create_stack_slot(Type::I64, 8);

    let _entry_block = builder.current_block();
    let arg_n = builder.add_block_params(&[Type::I64])[0];

    let recur_block = builder.create_block();
    let ret_n_block = builder.create_block();
    let exit_block = builder.create_block();

    let v1 = builder.ins().iconst(Type::I64, 2);
    let v2 = builder.ins().ilt(arg_n, v1);
    builder.ins().brif(v2, ret_n_block, recur_block);

    builder.switch_to_block(recur_block);
    let v1_minus = builder.ins().iconst(Type::I64, 1);
    let v3 = builder.ins().isub(arg_n, v1_minus);
    let v4 = builder.ins().call(fib_id, &[v3])[0];
    let v5 = builder.ins().iconst(Type::I64, 2);
    let v6 = builder.ins().isub(arg_n, v5);
    let v7 = builder.ins().call(fib_id, &[v6])[0];
    let v8 = builder.ins().iadd(v4, v7);
    builder.ins().stack_store(result_slot, v8);
    builder.ins().jump(exit_block);

    builder.switch_to_block(ret_n_block);
    builder.ins().stack_store(result_slot, arg_n);
    builder.ins().jump(exit_block);

    builder.switch_to_block(exit_block);
    let res = builder.ins().stack_load(Type::I64, result_slot);
    builder.ins().ret(&[res]);

    builder.finalize();
    module.define_function(fib_id);

    println!("Original SSA IR:");
    for func in module.functions.values() {
        println!("{}", func);
    }

    let fib_func = &mut module.functions[fib_id];
    let fib_func_name = fib_func.name.clone();
    let lowerer = LoweringContext::new(fib_func);
    let lowered_func = lowerer.lower();

    println!("\nLowered Bytecode:");
    disassemble_chunk(&lowered_func, &fib_func_name);

    let mut vm = VirtualMachine::new();
    vm.add_function(fib_id, lowered_func.chunk);
    let ret = vm.call_function(fib_id, &[40]);
    println!("{ret:#?}");
}
