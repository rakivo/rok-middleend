#![warn(
    clippy::all,
    clippy::pedantic,
    dead_code
)]
#![allow(
    clippy::wildcard_imports,
    clippy::missing_transmute_annotations,
    clippy::items_after_statements,
    clippy::cast_lossless,
    clippy::cast_ptr_alignment,
    clippy::inline_always,
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
