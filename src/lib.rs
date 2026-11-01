#![cfg_attr(
    feature = "sancov",
    feature(linkage, link_llvm_intrinsics, core_intrinsics)
)]
#![doc = include_str!("../README.md")]

/// Comparison operand tables shared by the SanCov callbacks, the embedder
/// API and the mutators
mod cmp;
/// Interesting values that can be used during mutations
mod dictionary;
/// Main fuzzing driver/entrypoint code
mod driver;
/// Fuzzing targets whose execution the host does not instrument (emulators,
/// interpreters)
#[cfg(feature = "embed")]
pub mod embed;
/// Exports for interfacing with Fazi via FFI
pub mod exports;
/// Main Fazi state management code
mod fazi;
/// Function hooks for builtin functions
#[cfg(feature = "sancov")]
mod hooks;
/// Contains the public mutation API
mod mutate;
/// Runtime configuration options
mod options;
mod protobuf;
/// SanitizerCoverage callbacks
#[cfg(feature = "sancov")]
mod sancov;
/// Signal handling code
mod signal;
/// Module for weak imports pulled from the Rust standard library
#[cfg(feature = "sancov")]
mod weak;
/// Weakly linked imports
#[cfg(feature = "sancov")]
mod weak_imports;

pub use crate::mutate::mutator::Mutable;
pub use fazi::*;

#[doc(hidden)]
pub use rand;
use rand::rngs::StdRng;

#[cfg(feature = "structured_fuzzing")]
pub fn set_structured_fuzzing_mutate_callback(
    callback: fn(&[u8], &mut Fazi<StdRng>) -> Result<Vec<u8>, ()>,
) {
    let mut fazi = crate::driver::FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.structured_fuzzing_mutate_callback = Some(callback);
}
