// TODO(#5): Legalization pass
// TODO(#9): Instruction comments
// TODO(#8): Bug with data
//   for example this:
//   ```
//       bar :: () -> i32 {
//           return 34;
//       }
//       main :: () {
//           foo: Foo;
//           foo.a[0] = bar() + 35;
//           foo.a[3] = 420;
//           printf("foo.a[0] = %d\n\0", foo.a[0]);
//           printf("foo.a[3] = %d\n\0", foo.a[3]);
//       }
//       Foo :: struct {
//           a: [5] i32;
//       }
//       printf :: (fmt: string, ...);
//   ```
//   lowers down to:
//   ```
//       function main() ->
//       Block0:
//         v0:Ptr = stack_addr StackSlot0
//         v1:I64 = call FuncId0 ()
//         v2:I32 = iconst 35
//         v3:I64 = IAdd v1:I64, v2:I32
//         store_no_offset v0:Ptr, v3:I64
//         v4:Ptr = stack_addr StackSlot0
//         v5:I32 = iconst 3
//         v6:I32 = iconst 4
//         v7:I32 = IMul v5:I32, v6:I32
//         v8:Ptr = IAdd v4:Ptr, v7:I32
//         v9:I32 = iconst 420
//         store_no_offset v8:Ptr, v9:I32
//         v10:Ptr = data_addr DataId0
//         v11:Ptr = stack_addr StackSlot0
//         v12:I64 = stack_addr StackSlot1
//         v13:I32 = load_no_offset v11:Ptr:I32, v11:Ptr
//         v14:I64 = call FuncId1 (v10:Ptr, v13:I32)
//         v15:Ptr = data_addr DataId1
//         v16:Ptr = stack_addr StackSlot0
//         v17:I32 = iconst 3
//         v18:I32 = iconst 4
//         v19:I32 = IMul v17:I32, v18:I32
//         v20:Ptr = IAdd v16:Ptr, v19:I32
//         v21:I64 = stack_addr StackSlot2
//         v22:I32 = load_no_offset v20:Ptr:I32, v20:Ptr
//         v23:I64 = call FuncId1 (v15:Ptr, v22:I32)
//         return
//   ```
//   which lowers down to:
//   ```
//       Frame size: 64 bytes
//         s0: Ptr at FP+0 (size: 16)
//         s1: I64 at FP+16 (size: 4)
//         s2: I64 at FP+24 (size: 4)
//         s3: I64 at FP+32 (size: 8)
//         s4: Ptr at FP+48 (size: 8)
//       00000 FRAME_SETUP     64
//       00005 FP_ADDR         v8      , FP+0
//       0000E FP_STORE64      FP+32   , v9
//       00017 FP_STORE64      FP+48   , v8
//       00020 CALL            F0
//       00025 MOV             v9      , v0
//       0002E FP_LOAD64       v8      , FP+48
//       00037 ICONST32        v10     , 35_i32
//       00040 IADD            v11     , v9      , v10
//       0004D STORE64         v8      , v11
//       00056 FP_ADDR         v8      , FP+0
//       0005F ICONST32        v9      , 3_i32
//       00068 ICONST32        v10     , 4_i32
//       00071 IMUL            v11     , v9      , v10
//       0007E IADD            v9      , v8      , v11
//       0008B ICONST32        v8      , 420_i32
//       00094 STORE32         v9      , v8
//       0009D LOAD_DATA_ADDR  v8      , D0
//       000A6 FP_ADDR         v9      , FP+0
//       000AF FP_ADDR         v10     , FP+16
//       000B8 LOAD32          v10     , v9
//       000C1 MOV             v8      , v8
//       000CA MOV             v9      , v10
//       000D3 CALL            F1
//       000D8 MOV             v9      , v0
//       000E1 LOAD_DATA_ADDR  v8      , D1
//       000EA FP_ADDR         v9      , FP+0
//       000F3 ICONST32        v10     , 3_i32
//       000FC ICONST32        v11     , 4_i32
//       00105 IMUL            v12     , v10     , v11
//       00112 IADD            v10     , v9      , v12
//       0011F FP_ADDR         v9      , FP+24
//       00128 LOAD32          v9      , v10
//       00131 MOV             v8      , v8
//       0013A MOV             v9      , v9
//       00143 CALL            F1
//       00148 MOV             v10     , v0
//       00151 FRAME_TEARDOWN
//       00152 RETURN
//   ```
//   and when you run in the VM it prints this:
//   ```
//   foo.a[0] = 69
//   oo.a[3] = 420
//   ```
//   which is not particularly correct, I suspect that the data offsets might overlap
//   and cause this, because the data we insert into the `.datas` is 100% correct.
// TODO(#7): Unreachable (trap) instruction
// TODO(#4): Structure operations
// TODO(#3): extend/truncate operations
// TODO(#1): VM callbacks (intrinsics)
//   something like that:
//   ```rust
//       vm.add_callback(|vm, ..| unsafe {
//           // do zero return registers
//           ptr::write_bytes(self.registers.as_mut_ptr(), 0, 8);
//       });
//
//       // in vm
//       // id = parse [4 byte callback ID],
//       // callback = vm.callback(id)
//       // callback(vm)
//   ```

#![warn(
    clippy::all,
    clippy::pedantic,
    dead_code
)]
#![allow(
    clippy::multiple_crate_versions,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::used_underscore_binding,
    clippy::nonstandard_macro_braces,
    clippy::used_underscore_items,
    clippy::enum_glob_use,
    clippy::match_same_arms,
    clippy::too_many_lines,
    clippy::unnested_or_patterns,
    clippy::blocks_in_conditions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
)]

#[macro_use]
mod macros;

pub mod vm;
pub mod ssa;
pub mod util;
pub mod iter;
pub mod keys;
pub mod lower;
pub mod entity;
pub mod primary;
pub mod bytecode;
pub mod boxed_slice;
