use rand::{
    prelude::{IteratorRandom, StdRng},
    Rng,
};
use sha1::{Digest, Sha1};

use crate::{
    dictionary::DictionaryEntry,
    exports::fazi_initialize,
    ipc::IpcMessage,
    options::RuntimeOptions,
    sancov::{ComparisonOperandMap, PcEntry},
    weak_imports::*,
    Fazi, Input,
};
use std::{
    collections::HashSet,
    ffi::CString,
    lazy::SyncOnceCell,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
};

use clap::StructOpt;

use crate::options::Command;

/// Global map of comparison operands from SanCov instrumentation
pub(crate) static COMPARISON_OPERANDS: SyncOnceCell<Mutex<ComparisonOperandMap>> =
    SyncOnceCell::new();
/// Set of PCs that the fuzzer has reached
pub(crate) static COVERAGE: SyncOnceCell<Mutex<HashSet<usize>>> = SyncOnceCell::new();
/// Set of PCs that the fuzzer has reached for this testcase
pub(crate) static TESTCASE_COVERAGE: SyncOnceCell<Mutex<HashSet<usize>>> = SyncOnceCell::new();
/// The global [`Fazi`] instance. We need to keep a global pointer as the SanCov and
/// other C FFI entrypoints know nothing about us, but we need to access our
/// current state
pub(crate) static FAZI: SyncOnceCell<Mutex<Fazi<StdRng>>> = SyncOnceCell::new();
/// Indicator if Fazi has been initialized already to avoid accidentally performing
/// initialization tasks multiple times
pub(crate) static FAZI_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Inline 8bit counters used for PC coverage.
pub(crate) static U8_COUNTERS: SyncOnceCell<Mutex<Vec<&'static [AtomicU8]>>> = SyncOnceCell::new();
/// PC info corresponding to the U8 counters.
pub(crate) static PC_INFO: SyncOnceCell<Mutex<Vec<&'static [PcEntry]>>> = SyncOnceCell::new();
pub(crate) static IPC_QUEUE: SyncOnceCell<crossbeam_channel::Sender<IpcMessage>> =
    SyncOnceCell::new();
/// The most recent input that was used for fuzzing.
/// SAFETY: This value should only ever be read from the [`signal::death_callback()`],
/// at which point we are about to exit and the fuzzer loop should not be running,
/// so there should be no chance of a race condition.
pub(crate) static mut LAST_INPUT: Option<Arc<Vec<u8>>> = None;
pub(crate) static mut CRASHES_DIR: Option<PathBuf> = None;
pub(crate) static mut INPUTS_DIR: Option<PathBuf> = None;
pub(crate) static mut INPUTS_EXTENSION: Option<String> = None;

#[cfg(feature = "main_entrypoint")]
#[no_mangle]
extern "C" fn main() {
    fazi_initialize();

    let run_input = libfuzzer_runone_fn();
    let user_initialize = libfuzzer_initialize_fn();
    if let Some(user_initialize) = user_initialize {
        let program_name = CString::new(std::env::args().next().unwrap()).unwrap();
        let args = [program_name.as_ptr()];
        let mut argv = &args;
        let mut argc_len = argv.len() as std::os::raw::c_int;
        unsafe {
            user_initialize(
                &mut argc_len as *mut _,
                (&mut argv as *mut _) as *mut *const *const libc::c_char,
            );
        }
    }

    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.set_options(RuntimeOptions::parse());
    fazi.restore_inputs();
    fazi.setup_signal_handler();

    match fazi.options.command.as_ref() {
        Some(Command::Repro { file_path }) => {
            eprintln!("Reproducing crash: {:?}", file_path);
            fazi.input = Arc::new(std::fs::read(file_path).expect("failed to open input file"));
            fazi.start_iteration();

            unsafe { run_input(fazi.input.as_ptr(), fazi.input.len()) };

            eprintln!("Input did not reproduce crash!");
            return;
        }
        None => {
            eprintln!("Performing recoverage");

            fazi.perform_recoverage(|input| {
                unsafe {
                    run_input(input.as_ptr(), input.len());
                }
            });
        }
    }

    eprintln!("Performing fuzzing");

    fazi.fuzz(|input| {
        let input_ptr = input.as_ptr();
        let len = input.len();
        unsafe { run_input(input_ptr, len) };
    });

    eprintln!("Done fuzzing!");
}

impl<R: Rng> Fazi<R> {
    /// Performs necessary tasks before sending the testcase off to the target
    pub fn start_iteration(&mut self) {
        poison_input(self.input.as_ref());
        self.update_max_size();
        unsafe {
            LAST_INPUT = Some(self.input.clone());
        }
        update_coverage();
    }

    /// Updates the maximum length that we can extend the input to
    pub(crate) fn update_max_size(&mut self) {
        if self.options.len_control > 0 && self.current_max_input_len < self.options.max_input_len {
            let max_mutation_len: usize = self.current_max_input_len;
            let len_control: u32 = self
                .options
                .len_control;

            fn log(val: u32) -> u32 {
                ((std::mem::size_of_val(&val) * 8) as u32) - val.leading_zeros() - 1
            }
            let factor = (len_control * log(max_mutation_len as u32)) as usize;
            if self.iterations - self.last_corpus_update_run > factor {
                let new_max_mutation_len =
                    max_mutation_len + (log(max_mutation_len as u32) as usize);
                self.current_max_input_len =
                    std::cmp::min(new_max_mutation_len, self.options.max_input_len);
                self.last_corpus_update_run = self.iterations;
            }
        }

        self.current_max_input_len = std::cmp::max(self.input.len(), self.current_max_input_len);
    }

    /// Performs tasks necessary immediately after an input has been passed off
    /// to a target. For example, we need to unpoison the allocated but unused
    /// bytes in the current input, update coverage, save the input if new
    /// coverage has been reached, and perform mutation for the next iteration.
    pub fn end_iteration(&mut self, need_more_data: bool) {
        unpoison_input(self.input.as_ref());

        let (new_coverage, old_coverage, input_coverage, new_pcs) = update_coverage();

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

            // Check if this new coverage was the result of a dictionary entry
            if let Some(entry) = self.last_dictionary_input.take() {
                match entry {
                    DictionaryEntry::U8(offset, val) => {
                        self.dictionary.u8dict.insert(offset, val);
                    }
                    DictionaryEntry::U16(offset, val) => {
                        self.dictionary.u16dict.insert(offset, val);
                    }
                    DictionaryEntry::U32(offset, val) => {
                        self.dictionary.u32dict.insert(offset, val);
                    }
                    DictionaryEntry::U64(offset, val) => {
                        self.dictionary.u64dict.insert(offset, val);
                    }
                    DictionaryEntry::Binary(offset, val) => {
                        self.dictionary.binary_dict.insert(offset, val);
                    }
                }
            }

            self.corpus.push(Input {
                coverage: input_coverage,
                data: self.input.clone(),
            });

            let input = self.input.clone();
            let corpus_dir: &Path = unsafe { INPUTS_DIR.as_ref().expect("INPUTS_DIR not initialized") };
            let extension: Option<&String> = unsafe { INPUTS_EXTENSION.as_ref() };
            let extension = extension.map(|e| e.as_ref());

            std::thread::spawn(move || {
                let filename = save_input(corpus_dir.as_ref(), extension, input.as_slice());

                if let Some(ipc_sender) = IPC_QUEUE.get() {
                    ipc_sender
                        .send(IpcMessage::NewCoverage(filename, input_coverage, new_pcs))
                        .expect("failed to add to IPC queue");
                }
            });

            self.current_mutation_depth = 0;
            self.mutations.clear();
        } else if self.current_mutation_depth == self.options.max_mutation_depth
            && !(need_more_data && can_request_more_data)
        {
            let next_input = if self.rng.gen() {
                self.corpus.peek()
            } else {
                self.corpus
                    .iter()
                    .filter(|input| input.data.len() >= self.min_input_size.unwrap_or(0))
                    .choose(&mut self.rng)
            };

            if let Some(input) = next_input {
                self.input = input.data.clone();
                self.current_mutation_depth = 0;
                self.mutations.clear();

                // Clear the mutations here before we mutate this input -- we do this
                // to avoid mixing offsets from the last testase with this one.
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

        let mut constants = COMPARISON_OPERANDS
            .get()
            .expect("failed to get CONSTANTS")
            .lock()
            .expect("failed to lock CONSTANTS");
        constants.clear();
        drop(constants);

        self.mutations.push(mutation);
        self.current_mutation_depth += 1;

        self.iterations += 1;

        let iteration_modulo = match self.iterations {
            0..=100_000 => 1000,
            100_001..=1_000_000 => 100_000,
            _ => 1_000_000,
        };
        if self.iterations % iteration_modulo == 0 {
            eprintln!("iter: {}", self.iterations);
        }
    }
}

pub(crate) fn update_coverage() -> (usize, usize, usize, Vec<usize>) {
    let mut coverage = coverage_map().lock().expect("failed to lock coverage map");
    let mut testcase_coverage = TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE");

    let mut input_coverage = testcase_coverage.len();
    let old_coverage = coverage.len();
    let u8_counters = U8_COUNTERS
        .get()
        .expect("U8_COUNTERS not initialized")
        .lock()
        .expect("failed to lock U8_COUNTERS");
    let module_pc_info = PC_INFO
        .get()
        .expect("PC_INFO not initialize")
        .lock()
        .expect("failed to lock PC_INFO");
    let mut new_pcs = vec![];
    for (module_idx, module_counters) in u8_counters.iter().enumerate() {
        for (counter_idx, counter) in module_counters.iter().enumerate() {
            if counter.load(Ordering::Relaxed) > 0 {
                let pc_info = &module_pc_info[module_idx][counter_idx];
                if coverage.insert(pc_info.pc) {
                    new_pcs.push(pc_info.pc);
                }

                counter.store(0, Ordering::Relaxed);
                input_coverage += 1;
            }
        }
    }

    for pc in testcase_coverage.drain() {
        if coverage.insert(pc) {
            new_pcs.push(pc);
        }
    }

    (coverage.len(), old_coverage, input_coverage, new_pcs)
}

pub(crate) fn handle_crash(crashes_dir: &Path, extension: Option<&str>, input: &[u8]) {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    let filename = hex::encode(result.as_slice());
    let mut crash_file_path = crashes_dir.join(format!("crash-{}", filename));
    if let Some(extension) = extension {
        crash_file_path.set_extension(extension);
    }

    eprintln!("Saving crash to {:?}", crash_file_path);
    ensure_parent_dir_exists(crash_file_path.as_ref());

    std::fs::write(crash_file_path, input).expect("failed to save crash file!");
}

pub(crate) fn save_input(corpus_dir: &Path, extension: Option<&str>, input: &[u8]) -> PathBuf {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    let filename = hex::encode(result.as_slice());
    let mut corpus_file_path = corpus_dir.join(format!("input-{}", filename));
    if let Some(extension) = extension {
        corpus_file_path.set_extension(extension);
    }

    eprintln!("Saving corpus input to {:?}", corpus_file_path);
    ensure_parent_dir_exists(corpus_file_path.as_ref());

    std::fs::write(&corpus_file_path, input).expect("failed to save corpus input file!");

    corpus_file_path
}

/// Ensures that the parent directory of `path` exists. If it does not, we will
/// create it.
fn ensure_parent_dir_exists(path: &Path) {
    let parent = path.parent().expect("path has no parent directory?");
    if !parent.exists() {
        std::fs::create_dir_all(parent).expect("failed to create_dir_all on parent directory");
    }
}

/// Marks all bytes of the input buffer's allocated data as addressable
pub(crate) fn unpoison_input(input: &Vec<u8>) {
    let input_ptr = input.as_ptr();

    if let Some(asan_unpoison) = asan_unpoison_memory_region_fn() {
        unsafe {
            asan_unpoison(input_ptr, input.capacity());
        }
    }

    if let Some(msan_unpoison) = msan_unpoison_memory_region_fn() {
        unsafe {
            msan_unpoison(input_ptr, input.capacity());
        }
    }
}

/// Marks the difference between the input's buffer's length and capacity as
/// unaddressable
pub(crate) fn poison_input(input: &Vec<u8>) {
    let unaddressable_bytes = input.capacity() - input.len();
    let unaddressable_start = unsafe { input.as_ptr().offset(input.len() as isize) };

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

pub(crate) fn coverage_map() -> &'static Mutex<HashSet<usize>> {
    COVERAGE.get().expect("COVERAGE_MAP")
}

pub(crate) fn try_insert_coverage_pc(pc: usize) {
    if let Ok(mut coverage_map) = coverage_map().try_lock() {
        coverage_map.insert(pc);
    }
}
