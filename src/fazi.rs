use std::{
    collections::BTreeMap,
    fs, panic,
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc},
};

use crate::{dictionary::Dictionary, options::RuntimeOptions};

use crate::driver::{
    poison_input, unpoison_input, update_coverage, COMPARISON_OPERANDS, COVERAGE, FAZI_INITIALIZED,
    PC_INFO, U8_COUNTERS,
};
use crate::mutations::MutationStrategy;
use crate::signal::death_callback;
use rand::{prelude::*, SeedableRng};
use sha2::{Digest, Sha256};

/// Main Fazi structure that holds our state.
#[derive(Debug)]
pub struct Fazi<R: Rng> {
    pub(crate) rng: R,
    /// Current input
    pub(crate) input: Arc<Vec<u8>>,
    /// Dictionary of SanCov comparison operands we've observed
    pub(crate) dictionary: Dictionary,
    /// All inputs in our fuzzer corpus
    pub(crate) corpus: Vec<Arc<Vec<u8>>>,
    /// Our runtime configuration
    pub(crate) options: RuntimeOptions,
    /// Number of fuzz iterations performed
    pub(crate) iterations: usize,
    /// The smallest an input should be based off of when the target stops
    /// telling us it needs more data
    pub(crate) min_input_size: Option<usize>,
    /// All of the inputs which have not yet been run through recoverage
    pub(crate) recoverage_queue: Vec<Arc<Vec<u8>>>,
    /// How many times the current input has been mutated
    pub(crate) current_mutation_depth: usize,
    /// Mutations applied to the current input
    pub(crate) mutations: Vec<MutationStrategy>,
    /// Hard stop upper bound for an input size
    pub(crate) max_input_size: usize,
    /// The maximum input length at this time
    pub(crate) current_max_mutation_len: usize,
    /// Counter for when we last updated the max input length
    pub(crate) last_corpus_update_run: usize,
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
            poison_input(&input);

            (callback)(input.as_slice());

            unpoison_input(&input);
        }

        update_coverage();
    }

    /// Iterate over the inputs read from disk and replay them back.
    pub fn fuzz(&mut self, callback: impl Fn(&[u8])) {
        // Ensure we update our coverage numbers to avoid misattributing any noise
        // that may have occurred before we started fuzzing
        update_coverage();

        loop {
            self.start_iteration();

            (callback)(&self.input.as_slice());

            self.end_iteration(false);

            if let Some(max_iters) = self.options.max_iters {
                if self.iterations >= max_iters {
                    break;
                }
            }
        }
    }

    /// Initialize the globals required for Fazi to work correctly
    pub fn initialize_globals(&self) {
        if FAZI_INITIALIZED.load(Ordering::Relaxed) {
            return;
        }

        COMPARISON_OPERANDS
            .set(Default::default())
            .expect("CONSTANTS already initialized");
        COVERAGE
            .set(Default::default())
            .expect("COVERAGE already initialized");
        U8_COUNTERS
            .set(Default::default())
            .expect("U8_COUNTERS already initialized");
        PC_INFO
            .set(Default::default())
            .expect("PC_INFO already initialized");

        FAZI_INITIALIZED.store(true, Ordering::Relaxed);
    }
}

pub struct FaziBuilder<'a, R: Rng = StdRng> {
    rng: Option<R>,
    perform_recoverage: bool,
    perform_fuzzing: bool,
    harness_callback: Option<&'a dyn Fn(&[u8])>,
    options: RuntimeOptions,
    handle_signals: bool,
    handle_panics: bool,
}

impl<'a, R: Rng> Default for FaziBuilder<'a, R> {
    fn default() -> Self {
        Self {
            rng: None,
            perform_recoverage: false,
            perform_fuzzing: false,
            harness_callback: None,
            options: Default::default(),
            handle_signals: false,
            handle_panics: false,
        }
    }
}

impl<'a, R: Rng> FaziBuilder<'a, R> {
    /// Creates a new RNG with the specified seed
    pub fn seed(mut self, seed: u64) -> Self {
        self.options.seed = Some(seed);

        self
    }

    /// Sets the RNG Fazi will use
    pub fn rng(mut self, rng: R) -> Self {
        self.rng = Some(rng);

        self
    }

    /// Path at which crashes will be saved
    pub fn crashes_dir(mut self, path: PathBuf) -> Self {
        self.options.crashes_dir = path;

        self
    }

    /// Path at which the inputs that discover new covearge will be saved
    pub fn corpus_dir(mut self, path: PathBuf) -> Self {
        self.options.corpus_dir = path;

        self
    }

    /// Sets the fuzzing harness. This will also be used for recoverage
    pub fn harness(mut self, callback: &'a dyn Fn(&[u8])) -> Self {
        self.harness_callback = Some(callback);

        self
    }

    /// The fuzzer will perform recoverage before fuzzing
    pub fn do_recoverage(mut self) -> Self {
        self.perform_recoverage = true;

        self
    }

    /// The fuzzer will do fuzzing
    pub fn do_fuzzing(mut self) -> Self {
        self.perform_fuzzing = true;

        self
    }

    /// Sets the maximum number of iterations the fuzzer should perform before
    /// exiting
    pub fn max_iters(mut self, iters: usize) -> Self {
        self.options.max_iters = Some(iters);

        self
    }

    /// Sets the maximum number of consecutive mutations to perform on an input
    /// before trying a different item in the corpus
    pub fn max_mutation_depth(mut self, depth: usize) -> Self {
        self.options.max_mutation_depth = depth;

        self
    }

    /// Sets the maximum size an input can be
    pub fn max_input_len(mut self, len: usize) -> Self {
        self.options.max_input_len = len;

        self
    }

    /// Handle signals from the system as crashes
    pub fn handle_signals(mut self) -> Self {
        self.handle_signals = true;

        self
    }

    /// Treat panics as a crash
    pub fn handle_panics(mut self) -> Self {
        self.handle_panics = true;

        self
    }

    /// Build the Fazi instance and perform the requested tasks
    pub fn run(self) {
        if self.harness_callback.is_none() {
            panic!("harness_callback is not set. Ensure you called FaziBuilder::harness()");
        }

        if !self.perform_fuzzing && !self.perform_recoverage {
            panic!("The harness was configured to do neither fuzzing nor coverage. Ensure you have called FaziBuilder::do_fuzzing() or FaziBuilder::do_recoverage()");
        }

        let mut fazi = Fazi::default();
        fazi.options = self.options;

        if self.handle_signals {
            fazi.setup_signal_handler();
        }

        if self.handle_panics {
            fazi.setup_panic_hook();
        }

        fazi.initialize_globals();
        fazi.restore_inputs();

        let callback = self.harness_callback.unwrap();

        if self.perform_recoverage {
            fazi.perform_recoverage(&callback);
        }

        if self.perform_fuzzing {
            fazi.fuzz(&callback);
        }
    }
}
