# Bytecode Virtual Machine Design

This document outlines the design for a simple, efficient bytecode virtual machine (VM). The design is inspired by the clarity of RISC-V and the pragmatism of VMs like Lua's, tailored for a custom Static Single Assignment (SSA) based Intermediate Representation (IR).

## 1. VM Design

The VM is designed for simplicity, speed, and ease of lowering from an SSA form.

### 1.1. Core Components (VM State)

The primary state of the VM is captured in a single `VM` struct:

```rust
struct VM {
    /// Program Counter: A pointer to the current instruction in the bytecode.
    ip: *const u8,

    /// Value Stack: Holds SSA values, function arguments, and return values.
    /// Using a `Vec<u64>` allows us to store any 64-bit value (i64, f64, or pointers).
    /// Smaller values (i32, f32) are zero- or sign-extended.
    stack: Vec<u64>,

    /// Call Stack: Manages function call frames.
    call_stack: Vec<CallFrame>,

    /// Globals: A pre-allocated region for global variables.
    globals: Vec<u64>,

    /// Memory: A simple byte-addressable memory region for loads and stores.
    memory: Vec<u8>,
}

struct CallFrame {
    /// Instruction Pointer to return to after the call.
    return_ip: *const u8,
    /// The base of the current function's stack frame on the main value stack.
    frame_pointer: usize,
}
```

### 1.2. Value Stack and SSA Mapping

The VM is stack-based, but it emulates an infinite register file for SSA values.

-   **SSA-to-Stack Mapping:** During the lowering phase, each unique SSA `Value` is assigned a dedicated slot on the value stack. This mapping is fixed for the duration of a function's execution.
-   **Frame Pointer:** A `frame_pointer` (stored in `CallFrame`) points to the base of the current function's stack frame. SSA values are accessed via `stack[frame_pointer + ssa_slot_index]`.
-   **No Register Allocation:** This design avoids a complex register allocation phase. The "infinite" register set of SSA form maps directly to stack slots, simplifying the lowering process significantly.

### 1.3. Call Stack and Function Calls

Function calls are managed with a dedicated `call_stack`.

**Calling a function (`Call` instruction):**
1.  The caller pushes the arguments onto the top of its *own* value stack.
2.  The `Call` instruction is executed:
    a. The current instruction pointer (`ip`) is saved by pushing a new `CallFrame` to the `call_stack`. This `return_ip` points to the instruction *after* the `Call`.
    b. The `frame_pointer` for the new frame is set to `stack.len() - num_args`.
    c. The `ip` is updated to point to the first instruction of the target function.
3.  The callee now "owns" the arguments pushed by the caller, which are at the base of its new stack frame.

**Returning from a function (`Return` instruction):**
1.  The callee places its return values at the base of its stack frame (where the arguments were).
2.  The `Return` instruction is executed:
    a. The top `CallFrame` is popped from the `call_stack`.
    b. The `ip` is restored from the `return_ip`.
    c. The value stack is truncated to the callee's `frame_pointer`, effectively removing all of the callee's stack slots *except* for the return values.
3.  The caller can now access the return values, which are now at the top of its stack.

### 1.4. Memory and Globals

-   **Globals:** Global values are stored in a simple `Vec<u64>`. They are accessed by a fixed index. A `LoadGlobal` and `StoreGlobal` opcode would be used.
-   **Data Sections:** Future data sections (e.g., for string literals or constants) can be handled similarly. The bytecode can include a read-only data section. Opcodes like `LoadData(offset)` would load data from this section onto the stack.
-   **Memory:** A flat `Vec<u8>` represents the main memory, accessed via `LoadX` and `StoreX` opcodes. These opcodes take a stack slot containing the memory address as an operand.

## 2. Bytecode Format

The bytecode is a simple sequence of bytes. Instructions are variable-width, with the opcode itself encoding the size of its operands.

### 2.1. Instruction Encoding

Each instruction consists of:
1.  **Opcode (1 byte):** The operation to be performed (e.g., `IConst8`, `Add`, `Jump16`).
2.  **Operands (0-N bytes):** SSA value slots (stack indices relative to the frame pointer).
3.  **Immediates (0-8 bytes):** Constant values or jump offsets.

The width of operands and immediates is encoded in the opcode name. For example:
-   `IAdd_8`: Operands are 8-bit indices.
-   `IAdd_16`: Operands are 16-bit indices.
-   `IConst_32`: Immediate is a 32-bit value.

This makes the decoder extremely simple: read the opcode, then read the exact number of bytes for operands and immediates based on a lookup table.

### 2.2. Core Opcode Table

| Opcode          | Operands (Stack Slots) | Immediate      | Description                                            |
|-----------------|------------------------|----------------|--------------------------------------------------------|
| **Constants**   |                        |                |                                                        |
| `IConst8`       | `dst: u8`              | `val: i8`      | `stack[dst] = val`                                     |
| `IConst16`      | `dst: u8`              | `val: i16`     | `stack[dst] = val`                                     |
| `IConst32`      | `dst: u8`              | `val: i32`     | `stack[dst] = val`                                     |
| `IConst64`      | `dst: u8`              | `val: i64`     | `stack[dst] = val`                                     |
| **Arithmetic**  |                        |                |                                                        |
| `Add`           | `dst: u8, a: u8, b: u8`|                | `stack[dst] = stack[a] + stack[b]`                     |
| `Sub`           | `dst: u8, a: u8, b: u8`|                | `stack[dst] = stack[a] - stack[b]`                     |
| `Mul`           | `dst: u8, a: u8, b: u8`|                | `stack[dst] = stack[a] * stack[b]`                     |
| **Memory**      |                        |                |                                                        |
| `Load8`         | `dst: u8, addr: u8`    |                | `stack[dst] = memory[stack[addr]]` (as u8)             |
| `Load16..64`    | `...`                  |                | ...                                                    |
| `Store8`        | `src: u8, addr: u8`    |                | `memory[stack[addr]] = stack[src]` (as u8)             |
| `Store16..64`   | `...`                  |                | ...                                                    |
| **Control Flow**|                        |                |                                                        |
| `Jump16`        |                        | `offset: i16`  | `ip += offset`                                         |
| `Jump32`        |                        | `offset: i32`  | `ip += offset`                                         |
| `BranchIf16`    | `cond: u8`             | `offset: i16`  | `if stack[cond] != 0 { ip += offset }`                 |
| `BranchIf32`    | `...`                  | `offset: i32`  | ...                                                    |
| **Functions**   |                        |                |                                                        |
| `Call`          |                        | `func_id: u32` | Call a function by its ID.                             |
| `Return`        |                        |                | Return from the current function.                      |

*(Note: Operand sizes like `u8` can be widened to `u16` for functions with more than 256 SSA values, e.g., `Add_16`)*

### 2.3. Encoding Examples

**Small Immediate:** `IConst8, dst: 5, val: 10`
-   Byte 0: `OP_ICONST8`
-   Byte 1: `5` (destination stack slot)
-   Byte 2: `10` (8-bit immediate value)
-   **Total: 3 bytes**

**Large Immediate:** `IConst64, dst: 12, val: 0x12345678_9ABCDEF0`
-   Byte 0: `OP_ICONST64`
-   Byte 1: `12` (destination stack slot)
-   Bytes 2-9: `0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12` (little-endian)
-   **Total: 10 bytes**

## 3. Lowering SSA IR to Bytecode

The goal is a fast, single-pass translation from the existing SSA IR to bytecode.

### 3.1. Design Goals

-   **Speed:** The lowering process should be linear in the number of IR instructions. No complex analysis or optimization is needed.
-   **Automation:** Jump targets and CFG edges are resolved automatically. The user of the lowering API does not need to manage them.

### 3.2. Lowering Process

1.  **Assign SSA Slots:** Iterate through all `Value`s in the function's `DataFlowGraph` and assign each a unique stack slot index (e.g., using a `HashMap<Value, u32>`).
2.  **Layout Basic Blocks:** Determine the starting bytecode offset for each `Block`. This can be done by doing a "dry run" pass over the instructions to calculate their byte size.
3.  **Emit Instructions:** Iterate through the basic blocks and their instructions in order:
    -   For each SSA instruction (`IAdd`, `IConst`, etc.), emit the corresponding bytecode opcode. Look up the stack slots for the operand `Value`s and write them as operands.
    -   For terminator instructions (`Jump`, `BranchIf`):
        a. Look up the target `Block`'s bytecode offset.
        b. Calculate the relative jump offset (`target_offset - current_ip_offset`).
        c. Choose the smallest jump instruction that can hold the offset (e.g., `Jump16` vs. `Jump32`).
        d. Emit the jump opcode and the calculated offset.

### 3.3. Example: Lowering a Fibonacci Function

Consider this pseudo-SSA for `fib(n)`:

```
function fib(n: i64) -> i64:
entry(v0: i64):
  v1 = iconst 1
  v2 = iless_than v0, v1  ; n < 1?
  brif v2, .ret_n, .recur

.recur:
  v3 = isub v0, v1         ; n - 1
  v4 = call fib(v3)
  v5 = iconst 2
  v6 = isub v0, v5         ; n - 2
  v7 = call fib(v6)
  v8 = iadd v4, v7
  ret v8

.ret_n:
  ret v0
```

**Lowered Bytecode (Conceptual):**

```
# SSA-to-Slot Mapping:
# v0 -> slot 0 (arg n)
# v1 -> slot 1
# v2 -> slot 2
# v3 -> slot 3
# v4 -> slot 4
# v5 -> slot 5
# v6 -> slot 6
# v7 -> slot 7
# v8 -> slot 8

# --- fib ---
# Block entry:
00: ICONST8   dst: 1, val: 1      # v1 = 1
03: ILESS_THAN dst: 2, a: 0, b: 1   # v2 = v0 < v1
07: BRANCHIF16 cond: 2, offset: +21 # if v2, jump to .ret_n

# Block .recur:
10: ISUB      dst: 3, a: 0, b: 1   # v3 = v0 - v1
14: MOV       dst: 0, src: 3      # Prep for call: move v3 to arg0
17: CALL      fib_id              # v4 = fib(v3)
22: MOV       dst: 4, src: 0      # Move result from arg0 to v4
25: ICONST8   dst: 5, val: 2      # v5 = 2
28: ISUB      dst: 6, a: 0, b: 5   # v6 = v0 - v5
32: MOV       dst: 0, src: 6      # Prep for call: move v6 to arg0
35: CALL      fib_id              # v7 = fib(v6)
40: MOV       dst: 7, src: 0      # Move result from arg0 to v7
43: IADD      dst: 8, a: 4, b: 7   # v8 = v4 + v7
47: MOV       dst: 0, src: 8      # Prep for return: move v8 to arg0
50: RETURN

# Block .ret_n:
51: RETURN                      # Returns arg0 (v0) by default
```
*(Note: `MOV` opcodes are used here to shuffle values for calls and returns. This is a common requirement when mapping SSA to a stack machine.)*

## 4. Interpreter

The interpreter is a simple `loop` that dispatches on the current opcode.

### 4.1. Main Interpreter Loop (Rust Pseudocode)

```rust
fn execute(&mut self) {
    loop {
        // Decode
        let opcode = self.read_byte();

        match opcode {
            OP_ICONST8 => {
                let dst = self.read_byte() as usize;
                let val = self.read_byte() as i8 as u64;
                self.stack[self.fp + dst] = val;
            }
            OP_IADD => {
                let dst = self.read_byte() as usize;
                let a = self.read_byte() as usize;
                let b = self.read_byte() as usize;
                self.stack[self.fp + dst] = self.stack[self.fp + a] + self.stack[self.fp + b];
            }
            OP_JUMP16 => {
                let offset = self.read_i16();
                self.ip = self.ip.offset(offset as isize);
            }
            OP_BRANCHIF16 => {
                let cond_slot = self.read_byte() as usize;
                let offset = self.read_i16();
                if self.stack[self.fp + cond_slot] != 0 {
                    self.ip = self.ip.offset(offset as isize);
                }
            }
            OP_CALL => {
                // ... push call frame, update ip and fp ...
            }
            OP_RETURN => {
                // ... pop call frame, update ip and fp, handle return values ...
                if self.call_stack.is_empty() {
                    return; // Final return from program
                }
            }
            // ... other opcodes ...
            _ => panic!("Unknown opcode"),
        }
    }
}
```

## 5. Efficiency and Design Rationale

### 5.1. Why Width-Specific Opcodes?

-   **Simpler, Faster Decoding:** The decoder does not need to parse complex operand-encoding schemes (like Lua's or Python's). It reads the opcode and immediately knows the instruction's total size. This avoids branching in the decoder and improves instruction dispatch speed.
-   **Code Density:** For simple constants or short jumps, smaller opcodes (`IConst8`, `Jump16`) produce more compact bytecode. The lowerer automatically selects the smallest possible encoding.

### 5.2. Comparison with Other Interpreters

-   **Python/CPython:** Python's VM uses a similar stack-based approach but has more dynamic, high-level opcodes (e.g., `BINARY_ADD`, `LOAD_ATTR`). Its instructions are a fixed size (2 bytes in 3.10), but an `EXTENDED_ARG` prefix instruction allows for larger operands, adding complexity to the decoder. The design here is much lower-level and closer to the hardware.
-   **Lua:** Lua's VM is famously fast and uses a register-based architecture with a fixed 32-bit instruction format. Operands are packed into the instruction word. This is very efficient for execution but requires a register allocation pass during compilation, making the "lowering" phase more complex than the simple SSA-to-stack mapping proposed here.

### 5.3. Balancing Lowering and Execution Speed

This design strikes a balance:

-   **Fast Lowering:** By mapping SSA values directly to stack slots and avoiding register allocation, the compilation from IR to bytecode is extremely fast. This is ideal for a JIT-like environment where compilation speed matters.
-   **Good Execution Speed:** While not as fast as a true register-based VM (which has less memory traffic), it's much faster than a purely interpretive approach. The simple, predictable decoding loop and low-level opcodes allow for efficient execution. The performance bottleneck shifts from instruction decoding to memory access (stack reads/writes), which is a reasonable trade-off for the gained simplicity and lowering speed.
