use rand::{
    prelude::{IteratorRandom, StdRng},
    Rng,
};
use sha1::{Digest, Sha1};

use crate::{
    exports::fazi_initialize,
    options::RuntimeOptions,
    sancov::{CoverageMap, PcEntry},
    weak_imports::*,
    Fazi,
};
use std::io;
use std::{
    collections::HashSet,
    lazy::SyncOnceCell,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
};

use clap::StructOpt;

use crate::options::Command;

/// Global map of comparison operands from SanCov instrumentation
pub(crate) static COMPARISON_OPERANDS: SyncOnceCell<Mutex<CoverageMap>> = SyncOnceCell::new();
/// Set of PCs that the fuzzer has reached
pub(crate) static COVERAGE: SyncOnceCell<Mutex<HashSet<usize>>> = SyncOnceCell::new();
/// The global [`Fazi`] instance. We need to keep a global pointer as the SanCov and
/// other C FFI entrypoints know nothing about us, but we need to access our
/// current state
pub(crate) static FAZI: SyncOnceCell<Mutex<Fazi<StdRng>>> = SyncOnceCell::new();
/// Indicator if Fazi has been initialized already to avoid accidentally performing
/// initialization tasks multiple times
pub(crate) static FAZI_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Inline 8bit counters used for PC coverage.
pub(crate) static mut U8_COUNTERS: Option<&'static [AtomicU8]> = None;
/// PC info corresponding to the U8 counters.
pub(crate) static mut PC_INFO: Option<&'static [PcEntry]> = None;

#[cfg(feature = "main_entrypoint")]
#[no_mangle]
extern "C" fn main() {
    fazi_initialize();

    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.set_options(RuntimeOptions::parse());
    let f = libfuzzer_runone_fn();

    match fazi.options.command.as_ref() {
        Some(Command::Repro { file_path }) => {
            eprintln!("Reproducing crash: {:?}", file_path);
            fazi.input = Arc::new(std::fs::read(file_path).expect("failed to open input file"));
            fazi.start_iteration();

            unsafe { f(fazi.input.as_ptr(), fazi.input.len()) };

            eprintln!("Input did not reproduce crash!");
            return;
        }
        None => {
            eprintln!("Performing recoverage");
            for input in fazi.recoverage_queue.drain(..) {
                unsafe {
                    f(input.as_ptr(), input.len());
                }
            }

            update_coverage();
        }
    }

    eprintln!("Performing fuzzing");
    loop {
        fazi.start_iteration();

        let res = unsafe { f(fazi.input.as_ptr(), fazi.input.len()) };

        fazi.end_iteration(res != 0);

        if let Some(max_iters) = fazi.options.max_iters {
            if max_iters == fazi.iterations {
                eprintln!("Maximum number of iterations reached");
                break;
            }
        }
    }

    eprintln!("Done fuzzing!");
}

impl<R: Rng> Fazi<R> {
    /// Performs necessary tasks before sending the testcase off to the target
    pub fn start_iteration(&mut self) {
        self.poison_input();
        self.update_max_size();
    }

    /// Updates the maximum length that we can extend the input to
    pub(crate) fn update_max_size(&mut self) {
        if self.options.len_control > 0 && self.current_max_mutation_len < self.max_input_size {
            let max_mutation_len_f64: f64 = self.max_input_size as f64;
            let len_control: f64 = self
                .options
                .len_control
                .try_into()
                .expect("failed to convert len_control");
            let factor = (len_control * max_mutation_len_f64.log10()).trunc() as usize;
            if self.iterations - self.last_corpus_update_run > factor {
                let max_mutation_len = self.max_input_size;
                let new_max_mutation_len =
                    max_mutation_len + (max_mutation_len_f64.log10() as usize);
                self.max_input_size = std::cmp::min(new_max_mutation_len, self.options.max_input_len);
            }
        }

        self.current_max_mutation_len = std::cmp::max(self.input.len(), self.max_input_size);
    }

    /// Performs tasks necessary immediately after an input has been passed off
    /// to a target. For example, we need to unpoison the allocated but unused
    /// bytes in the current input, update coverage, save the input if new
    /// coverage has been reached, and perform mutation for the next iteration.
    pub fn end_iteration(&mut self, need_more_data: bool) {
        self.unpoison_input();

        let (new_coverage, old_coverage) = update_coverage();

        if !need_more_data {
            let min_input_size = if let Some(min_input_size) = self.min_input_size {
                std::cmp::min(self.input.len(), min_input_size)
            } else {
                self.input.len()
            };

            self.min_input_size = Some(min_input_size);
        }

        let can_request_more_data = !self.min_input_size.is_some();

        if old_coverage != new_coverage {
            eprintln!(
                "old coverage: {}, new coverage: {}, mutations: {:?}",
                old_coverage, new_coverage, self.mutations
            );

            self.corpus.push(self.input.clone());

            let input = self.input.clone();
            let corpus_dir = self.options.corpus_dir.clone();
            std::thread::spawn(move || {
                save_input(corpus_dir.as_ref(), input.as_slice());
            });

            self.current_mutation_depth = 0;
            self.mutations.clear();

            let mut constants = COMPARISON_OPERANDS
                .get()
                .expect("failed to get CONSTANTS")
                .lock()
                .expect("failed to lock CONSTANTS");
            constants.clear();
        } else if self.current_mutation_depth == self.options.max_mutation_depth
            && (!need_more_data || !can_request_more_data)
        {
            if let Some(input) = self
                .corpus
                .iter()
                .filter(|input| input.len() >= self.min_input_size.unwrap_or(0))
                .choose(&mut self.rng)
            {
                self.input = input.clone();
                self.current_mutation_depth = 0;
                self.mutations.clear();

                let mut constants = COMPARISON_OPERANDS
                    .get()
                    .expect("failed to get CONSTANTS")
                    .lock()
                    .expect("failed to lock CONSTANTS");
                constants.clear();
            }
        }

        let mutation = if need_more_data && can_request_more_data {
            self.extend_input()
        } else {
            self.mutate_input()
        };
        self.mutations.push(mutation);
        self.current_mutation_depth += 1;

        self.iterations += 1;

        if self.iterations % 1000 == 0 {
            eprintln!("iter: {}", self.iterations);
        }
    }

    /// Marks all bytes of the input buffer's allocated data as addressable
    pub(crate) fn unpoison_input(&mut self) {
        let input_ptr = self.input.as_ptr();

        if let Some(asan_unpoison) = asan_unpoison_memory_region_fn() {
            unsafe {
                asan_unpoison(input_ptr, self.input.capacity());
            }
        }

        if let Some(msan_unpoison) = msan_unpoison_memory_region_fn() {
            unsafe {
                msan_unpoison(input_ptr, self.input.capacity());
            }
        }
    }

    /// Marks the difference between the input's buffer's length and capacity as
    /// unaddressable
    pub(crate) fn poison_input(&mut self) {
        let unaddressable_bytes = self.input.capacity() - self.input.len();
        let unaddressable_start = unsafe { self.input.as_ptr().offset(self.input.len() as isize) };

        if let Some(asan_poison) = asan_poison_memory_region_fn() {
            unsafe {
                asan_poison(unaddressable_start, unaddressable_bytes);
            }
        }

        if let Some(msan_unpoison) = msan_poison_memory_region_fn() {
            unsafe {
                msan_unpoison(unaddressable_start, unaddressable_bytes);
            }
        }
    }
}

pub(crate) fn update_coverage() -> (usize, usize) {
    let mut coverage = COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE");

    let old_coverage = coverage.len();
    for (idx, counter) in unsafe { U8_COUNTERS.as_ref().unwrap().iter().enumerate() } {
        if counter.load(Ordering::Relaxed) > 0 {
            // Grab the PC corresponding tot his entry
            let pc_info = unsafe { &PC_INFO.as_ref().unwrap()[idx] };

            coverage.insert(pc_info.pc);
        }
    }

    (coverage.len(), old_coverage)
}

pub(crate) fn handle_crash(crashes_dir: &Path, input: &[u8]) {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    let filename = hex::encode(result.as_slice());
    let crash_file_path = crashes_dir.join(format!("crash-{}", filename));

    eprintln!("Received SIGABRT -- saving crash to {:?}", crash_file_path);
    ensure_parent_dir_exists(crash_file_path.as_ref());

    std::fs::write(crash_file_path, input).expect("failed to save crash file!");
}

pub(crate) fn save_input(corpus_dir: &Path, input: &[u8]) {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    let filename = hex::encode(result.as_slice());
    let corpus_file_path = corpus_dir.join(format!("input-{}", filename));

    eprintln!("Saving corpus input to {:?}", corpus_file_path);
    ensure_parent_dir_exists(corpus_file_path.as_ref());

    std::fs::write(corpus_file_path, input).expect("failed to save corpus input file!");
}

/// Ensures that the parent directory of `path` exists. If it does not, we will
/// create it.
fn ensure_parent_dir_exists(path: &Path) {
    let parent = path.parent().expect("path has no parent directory?");
    if !parent.exists() {
        std::fs::create_dir_all(parent).expect("failed to create_dir_all on parent directory");
    }
}
