use rok_bytecode::vm::VirtualMachine;
use rok_bytecode::lower::{LoweringContext};
use rok_bytecode::bytecode::disassemble_chunk;
use rok_bytecode::ssa::{FunctionBuilder, IntCC, Module, Signature, Type};

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

    let v1 = builder.ins().iconst_with_comment(Type::I64, 2, "load constant 2");
    let v2 = builder.ins().icmp_with_comment(IntCC::UnsignedLessThan, arg_n, v1, "n < 2");
    builder.ins().brif_with_comment(v2, ret_n_block, recur_block, "if n < 2, return n, else recurse");

    builder.switch_to_block(recur_block);
    let v1_minus = builder.ins().iconst_with_comment(Type::I64, 1, "load constant 1");
    let v3 = builder.ins().isub_with_comment(arg_n, v1_minus, "n - 1");
    let v4 = builder.ins().call_with_comment(fib_id, &[v3], "fib(n - 1)")[0];
    let v5 = builder.ins().iconst_with_comment(Type::I64, 2, "load constant 2");
    let v6 = builder.ins().isub_with_comment(arg_n, v5, "n - 2");
    let v7 = builder.ins().call_with_comment(fib_id, &[v6], "fib(n - 2)")[0];
    let v8 = builder.ins().iadd_with_comment(v4, v7, "fib(n - 1) + fib(n - 2)");
    builder.ins().stack_store_with_comment(result_slot, v8, "store result");
    builder.ins().jump_with_comment(exit_block, "jump to exit");

    builder.switch_to_block(ret_n_block);
    builder.ins().stack_store_with_comment(result_slot, arg_n, "store n");
    builder.ins().jump_with_comment(exit_block, "jump to exit");

    builder.switch_to_block(exit_block);
    let res = builder.ins().stack_load_with_comment(Type::I64, result_slot, "load result");
    builder.ins().ret_with_comment(&[res], "return result");

    builder.finalize();
    module.define_function(fib_id);

    println!("Original SSA IR:");
    for func in module.funcs.values() {
        println!("{}", func);
    }

    let fib_func = &mut module.funcs[fib_id];
    let fib_func_name = fib_func.name.clone();
    let lowerer = LoweringContext::new(fib_func);
    let lowered_func = lowerer.lower();

    println!("\nLowered Bytecode:");
    disassemble_chunk(&lowered_func, &fib_func_name);

    let mut vm = VirtualMachine::new();
    vm.add_function(fib_id, &lowered_func.chunk);
    let ret = vm.call_function(fib_id, &[20]);
    println!("{ret:#?}");
}
