#![feature(linkage)]
#![feature(once_cell)]
#![feature(link_llvm_intrinsics)]
#![doc = include_str!("../README.md")]

/// Interesting values that can be used during mutations
mod dictionary;
/// Main fuzzing driver/entrypoint code
mod driver;
/// Exports for interfacing with Fazi via FFI
pub mod exports;
/// Main mutation logic
mod mutations;
/// Runtime configuration options
mod options;
/// SanitizerCoverage callbacks
mod sancov;
/// Signal handling code
mod signal;
/// Module for weak imports pulled from the Rust standard library
mod weak;
/// Weakly linked imports
mod weak_imports;
/// Main Fazi state management code
mod fazi;

pub use fazi::*;
