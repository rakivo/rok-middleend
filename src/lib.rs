// TODO(#5): Legalization pass
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

