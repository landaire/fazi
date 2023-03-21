#![feature(linkage)]
#![feature(link_llvm_intrinsics)]
#![feature(core_intrinsics)]
#![doc = include_str!("../README.md")]

/// Interesting values that can be used during mutations
mod dictionary;
/// Main fuzzing driver/entrypoint code
mod driver;
/// Exports for interfacing with Fazi via FFI
pub mod exports;
/// Main Fazi state management code
mod fazi;
/// Function hooks for builtin functions
mod hooks;
/// Contains the public mutation API
mod mutate;
/// Runtime configuration options
mod options;
mod protobuf;
/// SanitizerCoverage callbacks
mod sancov;
/// Signal handling code
mod signal;
/// Module for weak imports pulled from the Rust standard library
mod weak;
/// Weakly linked imports
mod weak_imports;

pub use crate::mutate::mutator::Mutable;
pub use fazi::*;

#[doc(hidden)]
pub use rand;
use rand::rngs::StdRng;

#[cfg(feature = "protobuf")]
pub fn set_protobuf_mutate_callback(callback: fn(&[u8], &mut Fazi<StdRng>) -> Vec<u8>) {
    let mut fazi = crate::driver::FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.protobuf_mutate_callback = Some(callback);
}
