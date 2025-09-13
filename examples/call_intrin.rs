use std::sync::Arc;

use rok_bytecode::vm::VirtualMachine;
use rok_bytecode::lower::{LoweringContext};
use rok_bytecode::bytecode::disassemble_chunk;
use rok_bytecode::ssa::{FunctionBuilder, IntrinData, Module, Signature};

fn main() {
    let mut module = Module::new();

    let sig = Signature {
        params: vec![],
        returns: vec![],
    };
    let foo_id = module.declare_function("foo", sig);

    let intrinsic_id = module.add_intrinsic(IntrinData {
        name: "bar".into(),
        signature: Signature::default(),
        vm_callback: Arc::new(|_vm, _decoder, _chunk| {
            println!("callback from the VM")
        })
    });

    let foo_func = module.get_func_mut(foo_id);
    let mut builder = FunctionBuilder::new(foo_func);

    builder.ins().call_intrin(intrinsic_id, &[]);
    builder.ins().ret(&[]);

    builder.finalize();
    module.define_function(foo_id);

    println!("Original SSA IR:");
    for func in module.funcs.values() {
        println!("{}", func);
    }

    let foo_func = &mut module.funcs[foo_id];
    let foo_func_name = foo_func.name.clone();
    let lowerer = LoweringContext::new(foo_func);
    let lowered_func = lowerer.lower();

    println!("\nLowered Bytecode:");
    disassemble_chunk(&lowered_func, &foo_func_name);

    let mut vm = VirtualMachine::new();
    vm.load_intrinsics(module.intrinsics);
    vm.add_function(foo_id, &lowered_func.chunk);
    let ret = vm.call_function(foo_id, &[40]);
    println!("{ret:#?}");
}
