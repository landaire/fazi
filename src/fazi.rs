use std::{
    collections::BinaryHeap,
    fs, panic,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

use crate::{
    dictionary::{Dictionary, DictionaryEntry},
    driver::TESTCASE_COVERAGE,
    options::RuntimeOptions,
};

use crate::driver::{
    clear_coverage, poison_input, unpoison_input, update_coverage, COMPARISON_OPERANDS, COVERAGE,
    COV_THREADS, FAZI_INITIALIZED, PC_INFO, U8_COUNTERS,
};
use crate::mutate::MutationStrategy;

use rand::{prelude::*, SeedableRng};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub(crate) struct Input {
    pub coverage: usize,
    pub data: Arc<Vec<u8>>,
}

impl Eq for Input {}

impl PartialEq for Input {
    fn eq(&self, other: &Self) -> bool {
        self.coverage == other.coverage
    }
}

impl PartialOrd for Input {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.coverage.partial_cmp(&other.coverage)
    }
}

impl Ord for Input {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.coverage.cmp(&other.coverage)
    }
}

/// Main Fazi structure that holds our state.
pub struct Fazi<R: Rng> {
    pub(crate) rng: R,
    /// Current input
    pub(crate) input: Arc<Vec<u8>>,
    /// Dictionary of SanCov comparison operands we've observed for the current session
    pub(crate) dictionary: Dictionary,
    /// Dictionary of SanCov comparison operands we've observed for the current input
    pub(crate) last_dictionary_input: Option<DictionaryEntry>,
    /// All inputs in our fuzzer corpus
    pub(crate) corpus: BinaryHeap<Input>,
    /// All inputs that we've read from disk. These items will move into `corpus`
    /// upon the first fuzzer iteration.
    pub(crate) restored_corpus: Vec<Input>,
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
    /// The maximum input length at this time
    pub(crate) current_max_input_len: usize,
    /// Counter for when we last updated the max input length
    pub(crate) last_corpus_update_run: usize,
    /// The last item that was run through recoverage
    pub(crate) last_recoverage_input: Option<Arc<Vec<u8>>>,
    #[cfg(feature = "protobuf")]
    pub(crate) protobuf_mutate_callback: Option<fn(&[u8], &mut Fazi<R>) -> Vec<u8>>,
}

impl<R: Rng + std::fmt::Debug> std::fmt::Debug for Fazi<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fazi")
            .field("rng", &self.rng)
            .field("input", &self.input)
            .field("dictionary", &self.dictionary)
            .field("last_dictionary_input", &self.last_dictionary_input)
            .field("corpus", &self.corpus)
            .field("restored_corpus", &self.restored_corpus)
            .field("options", &self.options)
            .field("iterations", &self.iterations)
            .field("min_input_size", &self.min_input_size)
            .field("recoverage_queue", &self.recoverage_queue)
            .field("current_mutation_depth", &self.current_mutation_depth)
            .field("mutations", &self.mutations)
            .field("current_max_input_len", &self.current_max_input_len)
            .field("last_corpus_update_run", &self.last_corpus_update_run)
            .field("last_recoverage_input", &self.last_recoverage_input)
            .finish()
        //field("protobuf_mutate_callback", &self.protobuf_mutate_callback.map_or("None", |_| "Some(callback)"))
    }
}

impl Default for Fazi<StdRng> {
    fn default() -> Self {
        Fazi {
            rng: StdRng::from_entropy(),
            input: Default::default(),
            dictionary: Default::default(),
            last_dictionary_input: None,
            corpus: Default::default(),
            restored_corpus: Vec::new(),
            options: Default::default(),
            iterations: 0,
            min_input_size: None,
            recoverage_queue: Default::default(),
            current_mutation_depth: 4,
            mutations: Default::default(),
            last_corpus_update_run: 0,
            current_max_input_len: 4,
            last_recoverage_input: None,
            #[cfg(feature = "protobuf")]
            protobuf_mutate_callback: None,
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

const MAX_MUTATION_DEPTH: usize = 100;
const MAX_LEAF_FIELDS: usize = 10;
pub(crate) static MUTATION_DEPTH: AtomicUsize = AtomicUsize::new(0);
pub(crate) static LEAF_FIELDS_MUTATED: AtomicUsize = AtomicUsize::new(0);
pub(crate) static STOP_MUTATING: AtomicBool = AtomicBool::new(false);
pub struct MutationGuard {
    is_primitive_type: bool,
}

impl MutationGuard {
    fn try_new<R: Rng>(is_primitive_type: bool, fazi: &mut Fazi<R>) -> Option<MutationGuard> {
        // Check if we've satisfied the number of primitives we've wanted to mutate
        let fields_mutated = LEAF_FIELDS_MUTATED.load(Ordering::SeqCst);
        if fields_mutated == MAX_LEAF_FIELDS {
            STOP_MUTATING.store(true, Ordering::SeqCst);
            return None;
        }

        if is_primitive_type {
            LEAF_FIELDS_MUTATED.fetch_add(1, Ordering::SeqCst);
        }

        let mutate_this_field = fazi.rng.gen::<bool>();
        let stop_mutating = if fazi.rng.gen_bool(0.001) {
            STOP_MUTATING.store(true, Ordering::SeqCst);
            true
        } else if mutate_this_field {
            STOP_MUTATING.load(Ordering::SeqCst)
        } else {
            mutate_this_field
        };

        let guard = MutationGuard { is_primitive_type };

        if MUTATION_DEPTH.fetch_add(1, Ordering::SeqCst) > MAX_MUTATION_DEPTH || stop_mutating {
            None
        } else {
            Some(guard)
        }
    }
}

impl Drop for MutationGuard {
    fn drop(&mut self) {
        let value = MUTATION_DEPTH.fetch_sub(1, Ordering::SeqCst);
        if value == 1 {
            STOP_MUTATING.store(false, Ordering::SeqCst);
            LEAF_FIELDS_MUTATED.store(0, Ordering::SeqCst);
        }
    }
}

impl<R: Rng> Fazi<R> {
    /// Create a new instance of Fazi with default settings. This differs from
    /// the [`Fazi::default()`] implementation only when the backing RNG is not
    /// a [`StdRng`].
    pub fn new(rng: R) -> Self {
        Fazi {
            rng,
            input: Default::default(),
            dictionary: Default::default(),
            last_dictionary_input: None,
            corpus: Default::default(),
            restored_corpus: Vec::new(),
            options: Default::default(),
            iterations: 0,
            min_input_size: None,
            recoverage_queue: Default::default(),
            current_mutation_depth: 0,
            mutations: Default::default(),
            last_corpus_update_run: 0,
            current_max_input_len: 4,
            last_recoverage_input: None,
            #[cfg(feature = "protobuf")]
            protobuf_mutate_callback: None,
        }
    }

    pub fn before_mutate(&mut self, is_primitive_type: bool) -> Option<MutationGuard> {
        MutationGuard::try_new(is_primitive_type, self)
    }

    pub fn rng_mut(&mut self) -> &mut R {
        &mut self.rng
    }

    /// Load inputs from disk
    pub fn restore_inputs(&mut self) {
        let input_paths: [&Path; 1] = [self.options.corpus_dir.as_ref()];
        for &path in &input_paths {
            if !path.exists() || !path.is_dir() {
                panic!("???");
            }

            for dirent in fs::read_dir(path).expect("failed to read input directory") {
                if let Ok(dirent) = dirent {
                    let input_file_path = dirent.path();
                    if input_file_path.is_dir() {
                        continue;
                    }

                    self.restored_corpus.push(Input {
                        coverage: 0,
                        data: Arc::new(
                            fs::read(input_file_path).expect("failed to read input file"),
                        ),
                    });
                }
            }
        }

        // Sort so that smaller testcases are preferred
        self.restored_corpus
            .sort_by(|a, b| a.data.len().cmp(&b.data.len()));
        self.recoverage_queue = self
            .restored_corpus
            .iter()
            .map(|input| input.data.clone())
            .collect();

        if !self.restored_corpus.is_empty() {
            self.input = Arc::clone(&self.restored_corpus[0].data);
        }
    }

    /// Iterate over the inputs read from disk and replay them back.
    pub fn perform_recoverage(&mut self, callback: impl Fn(&[u8])) {
        while let Some(input) = self.recoverage_queue.pop() {
            self.last_recoverage_input = Some(Arc::clone(&input));

            poison_input(&input);

            (callback)(input.as_slice());

            unpoison_input(&input);

            self.recoverage_testcase_end();
        }
        self.recoverage_testcase_end();
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

    pub fn clear_coverage(&mut self) {
        clear_coverage();
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
        TESTCASE_COVERAGE
            .set(Default::default())
            .expect("TESTCASE_COVERAGE already initialized");
        U8_COUNTERS
            .set(Default::default())
            .expect("U8_COUNTERS already initialized");
        PC_INFO
            .set(Default::default())
            .expect("PC_INFO already initialized");
        COV_THREADS
            .set(Default::default())
            .expect("COV_THREADS already initialized");

        FAZI_INITIALIZED.store(true, Ordering::Relaxed);
    }

    /// Updates the coverage for the item we just ran through recoverage
    pub fn recoverage_testcase_end(&mut self) {
        if let Some(recoverage_input) = self.last_recoverage_input.take() {
            for input in &mut self.restored_corpus {
                if input.data.as_ptr() == recoverage_input.as_ptr() {
                    let (_, _, input_coverage) = update_coverage();

                    input.coverage = input_coverage;
                    break;
                }
            }
        }

        if self.recoverage_queue.is_empty() {
            self.corpus.extend(
                self.restored_corpus
                    .drain(..)
                    .filter(|item| item.coverage > 0),
            );
        }
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

    /// Sets the minimum size an input can be
    pub fn min_input_len(mut self, len: usize) -> Self {
        self.options.min_input_len = len;

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
