# Bytecode-CL: SSA-based Intermediate Representation

A minimal SSA-based intermediate representation (IR) in Rust for a Jai-like interpreter or VM. This project provides a clean, extensible foundation for building compilers and virtual machines.

## Features

### Core Components

1. **Function Structure**
   - Complete function representation with signature, DFG, CFG, layout, and stack slots
   - Support for parameters, return types, and metadata

2. **DataFlowGraph (DFG)**
   - SSA values and instructions tracking
   - Support for various opcodes (arithmetic, memory, control flow, calls)
   - Type-aware value system (I32, I64, F32, F64, Void)

3. **ControlFlowGraph (CFG)**
   - Basic blocks with automatic predecessor/successor tracking
   - Control flow instructions (jump, brif, return)
   - Block ordering and layout management

4. **Stack Slots and VM Layout**
   - Automatic SSA value to stack slot mapping
   - Support for different data types and sizes
   - Placeholder for register allocation

5. **Ergonomic Builder API**
   - `FunctionBuilder` with helper methods for common operations
   - Automatic block linking and instruction insertion
   - Type-safe instruction creation

### Supported Instructions

- **Integer Arithmetic**: `iadd`, `isub`, `imul`, `idiv`, `irem`
- **Floating Point**: `fadd`, `fsub`, `fmul`, `fdiv`
- **Memory Operations**: `load`, `store`
- **Control Flow**: `jump`, `brif`, `return`
- **Function Calls**: `call`
- **Constants**: `iconst`, `fconst`
- **Comparisons**: `icmp`, `fcmp`

## Usage

### Basic Example

```rust
use bytecode_cl::*;

// Create a function
let mut func = Function::new(
    "add_function".to_string(),
    FunctionSignature {
        params: vec![Type::I64, Type::I64],
        return_ty: Type::I64,
    }
);

let mut builder = FunctionBuilder::new(&mut func);

// Add parameters
let a = builder.func.add_param(Type::I64);
let b = builder.func.add_param(Type::I64);

// Create a basic block
let block = builder.append_block();
builder.switch_to_block(block);

// Add instructions
let result = builder.iadd(a, b);
builder.ret(Some(result));
```

### Fibonacci Example

The project includes a complete Fibonacci function implementation demonstrating:

- Control flow with conditional branches
- Recursive function calls
- SSA value management
- Stack slot allocation

Run the demo:

```bash
cargo run --example fibonacci_demo
```

## Architecture

### SSA Form

The IR enforces Static Single Assignment (SSA) form:
- Each value is assigned exactly once
- Values flow through the data flow graph
- Phi nodes can be added for control flow merges

### Type System

- **I32/I64**: Integer types (4/8 bytes)
- **F32/F64**: Floating point types (4/8 bytes)  
- **Void**: No value (for control flow instructions)

### Stack Layout

- SSA values are automatically mapped to stack slots
- Each slot has a type and size
- Layout information tracks instruction and block positions
- Ready for register allocation passes

## Testing

Run the test suite:

```bash
cargo test
```

Run tests with output:

```bash
cargo test -- --nocapture
```

## Dependencies

- `smallvec`: Efficient small vector storage
- `hashbrown`: Fast hash maps and sets

## Future Extensions

The design is prepared for:

- `data_in_function` and `data_in_data` support
- Global values and constants
- More sophisticated register allocation
- Additional instruction types
- Optimization passes

## License

This project is open source and available under the MIT License.
