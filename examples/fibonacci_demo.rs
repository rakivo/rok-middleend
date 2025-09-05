use bytecode_cl::bytecode::BytecodeFunction;
use bytecode_cl::vm::VM;
use bytecode_cl::{Function, Signature, Type, FunctionBuilder, FunctionRef};

fn main() {
    // Create a new function to build.
    let mut func = Function {
        name: "fib".to_string(),
        signature: Signature {
            params: vec![Type::I64],
            returns: vec![Type::I64],
        },
        ..Default::default()
    };

    // Set up the builder.
    let mut builder = FunctionBuilder::new(&mut func);

    // Create blocks.
    let _entry_block = builder.current_block();
    let base_case_block = builder.create_block();
    let recursive_block = builder.create_block();
    let exit_block = builder.create_block();

    // --- Entry Block ---
    // The function argument `n` is the first parameter of the entry block.
    let n = builder.add_block_params(&[Type::I64])[0];
    let two = builder.ins().iconst(Type::I64, 2);
    builder.ins().bge(n, two, recursive_block, base_case_block);

    // --- Base Case Block ---
    builder.switch_to_block(base_case_block);
    // In the base case, `fib(n) = n`.
    builder.ins().jump(exit_block, &[n]);

    // --- Recursive Block ---
    builder.switch_to_block(recursive_block);
    let one = builder.ins().iconst(Type::I64, 1);

    // Calculate `n - 1` and `n - 2`.
    let n_minus_1 = builder.ins().isub(n, one);
    let n_minus_2 = builder.ins().isub(n_minus_1, one);

    // Recursive calls.
    let call_a = builder.ins().call(FunctionRef::Name("fib".to_string()), &[n_minus_1])[0];
    let call_b = builder.ins().call(FunctionRef::Name("fib".to_string()), &[n_minus_2])[0];

    // Sum the results.
    let result = builder.ins().iadd(call_a, call_b);
    builder.ins().jump(exit_block, &[result]);

    // --- Exit Block ---
    // This block needs to merge the results from the two paths.
    // We use a block parameter (phi node) to do this.
    builder.switch_to_block(exit_block);
    let final_result = builder.add_block_params(&[Type::I64])[0];
    builder.ins().ret(&[final_result]);

    // We need to manually specify which values flow into the phi node.
    // A real compiler would have a more sophisticated way to do this,
    // often involving a pass that resolves phi nodes.
    // For this demo, we'll just print a note.

    let insts = func.lower();

    // --- Execute in VM ---
    let mut vm = VM::new();
    // Set input value for fib(10)
    vm.regs[0] = 10;
    let result = vm.run(&insts);
    println!("fib(10) = {}", result);
}
}
