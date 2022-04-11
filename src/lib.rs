#![feature(linkage)]
#![feature(once_cell)]
#![feature(link_llvm_intrinsics)]
#![doc = include_str!("../README.md")]

use std::{collections::BTreeMap, fs, path::Path, sync::Arc};

use crate::options::RuntimeOptions;

use driver::{update_coverage, poison_input, unpoison_input};
use mutations::MutationStrategy;
use rand::{prelude::*, SeedableRng};
use sha2::{Digest, Sha256};

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

#[derive(Debug, Default)]
pub(crate) struct Dictionary {
    u8dict: BTreeMap<usize, u8>,
    u16dict: BTreeMap<usize, u16>,
    u32dict: BTreeMap<usize, u32>,
    u64dict: BTreeMap<usize, u64>,
}

/// Main Fazi structure that holds our state.
#[derive(Debug)]
pub struct Fazi<R: Rng> {
    rng: R,
    /// Current input
    input: Arc<Vec<u8>>,
    /// Dictionary of SanCov comparison operands we've observed
    dictionary: Dictionary,
    /// All inputs in our fuzzer corpus
    corpus: Vec<Arc<Vec<u8>>>,
    /// Our runtime configuration
    options: RuntimeOptions,
    /// Number of fuzz iterations performed
    iterations: usize,
    /// The smallest an input should be based off of when the target stops
    /// telling us it needs more data
    min_input_size: Option<usize>,
    /// All of the inputs which have not yet been run through recoverage
    recoverage_queue: Vec<Arc<Vec<u8>>>,
    /// How many times the current input has been mutated
    current_mutation_depth: usize,
    /// Mutations applied to the current input
    mutations: Vec<MutationStrategy>,
    /// Hard stop upper bound for an input size
    max_input_size: usize,
    /// The maximum input length at this time
    current_max_mutation_len: usize,
    /// Counter for when we last updated the max input length
    last_corpus_update_run: usize,
}

impl Default for Fazi<StdRng> {
    fn default() -> Self {
        Fazi {
            rng: StdRng::from_entropy(),
            input: Default::default(),
            dictionary: Default::default(),
            corpus: Default::default(),
            options: Default::default(),
            iterations: 0,
            min_input_size: None,
            recoverage_queue: Default::default(),
            current_mutation_depth: 0,
            mutations: Default::default(),
            max_input_size: 4,
            last_corpus_update_run: 0,
            current_max_mutation_len: 0,
        }
    }
}

impl Fazi<StdRng> {
    /// Set Fazi's runtime options. This may re-initialize the RNG if a seed
    /// is present
    pub fn set_options(&mut self, options: RuntimeOptions) {
        if let Some(seed) = options.seed {
            let mut hasher = Sha256::new();
            hasher.update(seed.to_be_bytes());
            let result = hasher.finalize();
            self.rng = StdRng::from_seed(
                result
                    .try_into()
                    .expect("failed to convert seed hash input to 32-byte array"),
            )
        }

        self.options = options;
    }
}

impl<R: Rng + SeedableRng> Fazi<R> {
    /// Create a new instance of Fazi with default settings. This differs from
    /// the [`Fazi::default()`] implementation only when the backing RNG is not
    /// a [`StdRng`].
    pub fn new() -> Self {
        Fazi {
            rng: R::from_entropy(),
            input: Default::default(),
            dictionary: Default::default(),
            corpus: Default::default(),
            options: Default::default(),
            iterations: 0,
            min_input_size: None,
            recoverage_queue: Default::default(),
            current_mutation_depth: 0,
            mutations: Default::default(),
            max_input_size: 4,
            last_corpus_update_run: 0,
            current_max_mutation_len: 0,
        }
    }

    /// Load inputs from disk
    pub fn restore_inputs(&mut self) {
        let input_paths: [&Path; 1] = [self.options.corpus_dir.as_ref()];
        for &path in &input_paths {
            if !path.exists() || !path.is_dir() {
                continue;
            }

            for dirent in fs::read_dir(path).expect("failed to read input directory") {
                if let Ok(dirent) = dirent {
                    let input_file_path = dirent.path();
                    if input_file_path.is_dir() {
                        continue;
                    }

                    self.corpus.push(Arc::new(
                        fs::read(input_file_path).expect("failed to read input file"),
                    ));
                }
            }
        }

        self.recoverage_queue = self.corpus.clone();
    }

    /// Iterate over the inputs read from disk and replay them back.
    pub fn perform_recoverage(&mut self, callback: impl Fn(&[u8])) {
        for input in self.recoverage_queue.drain(..) {
            update_coverage();

            poison_input(&input);

            (callback)(input.as_slice());

            unpoison_input(&input);
        }
    }
}