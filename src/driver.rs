use once_cell::sync::OnceCell;
use rand::{
    prelude::{IteratorRandom, StdRng},
    Rng,
};
use serde::{Deserialize, Serialize};
use sha1::{
    digest::{generic_array::GenericArray, Output},
    Digest, Sha1,
};

use crate::{
    dictionary::DictionaryEntry,
    sancov::{ComparisonOperandMap, PcEntry},
    weak_imports::*,
    CorpusMetadata, Fazi, Input,
};
use std::{
    collections::{HashMap, HashSet},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex, OnceLock, RwLock,
    },
    time::{Instant, SystemTime},
};

/// Global map of comparison operands from SanCov instrumentation
pub(crate) static COMPARISON_OPERANDS: OnceCell<Mutex<ComparisonOperandMap>> = OnceCell::new();
/// Set of PCs that the fuzzer has reached and the counter for that PC
pub(crate) static COVERAGE: OnceCell<Mutex<HashMap<usize, usize>>> = OnceCell::new();
/// Set of PCs that the fuzzer has reached for this testcase
pub(crate) static TESTCASE_COVERAGE: OnceCell<Mutex<HashSet<usize>>> = OnceCell::new();
/// The global [`Fazi`] instance. We need to keep a global pointer as the SanCov and
/// other C FFI entrypoints know nothing about us, but we need to access our
/// current state
pub(crate) static FAZI: OnceCell<Mutex<Fazi<StdRng>>> = OnceCell::new();
/// Indicator if Fazi has been initialized already to avoid accidentally performing
/// initialization tasks multiple times
pub(crate) static FAZI_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Inline 8bit counters used for PC coverage.
pub(crate) static U8_COUNTERS: OnceCell<Mutex<Vec<&'static [AtomicU8]>>> = OnceCell::new();
/// PC info corresponding to the U8 counters.
pub(crate) static PC_INFO: OnceCell<Mutex<Vec<&'static [PcEntry]>>> = OnceCell::new();
/// Restricts coverage updates to specified threads.  Empty set will allow all threads.
pub(crate) static COV_THREADS: OnceCell<RwLock<HashSet<usize>>> = OnceCell::new();
pub(crate) static ENABLE_COUNTERS: AtomicBool = AtomicBool::new(true);
/// The most recent input that was used for fuzzing.
/// SAFETY: This value should only ever be read from the [`signal::death_callback()`],
/// at which point we are about to exit and the fuzzer loop should not be running,
/// so there should be no chance of a race condition.
pub(crate) static LAST_INPUT: OnceLock<Mutex<Option<Arc<Vec<u8>>>>> = OnceLock::new();
pub(crate) static CRASHES_DIR: OnceLock<PathBuf> = OnceLock::new();
pub(crate) static INPUTS_DIR: OnceLock<PathBuf> = OnceLock::new();
pub(crate) static FAZI_STATS_FILE: OnceLock<PathBuf> = OnceLock::new();
pub(crate) static INPUTS_EXTENSION: OnceLock<String> = OnceLock::new();
pub(crate) static PERFORMING_RECOVERAGE: AtomicBool = AtomicBool::new(false);
pub(crate) static CORPUS_METADATA: OnceLock<Mutex<CorpusMetadata>> = OnceLock::new();
const STATUS_UPDATE_FREQ_SECS: u64 = 10;

#[cfg(feature = "main_entrypoint")]
#[no_mangle]
extern "C" fn main() {
    use std::ffi::CString;

    use clap::Parser;

    use crate::{
        exports::fazi_initialize,
        options::{Command, RuntimeOptions},
    };

    fazi_initialize();

    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.set_options(RuntimeOptions::parse());
    drop(fazi);

    let run_input = libfuzzer_runone_fn();
    let user_initialize = libfuzzer_initialize_fn();
    if let Some(user_initialize) = user_initialize {
        println!("calling user initialize");
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
    } else {
        println!("no user initialize provided?");
    }

    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    crate::fazi::set_corpus_dir(&fazi.options.corpus_dir);
    crate::fazi::set_crashes_dir(&fazi.options.crashes_dir);
    fazi.load_corpus_metadata();
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

            let bar = indicatif::ProgressBar::new(fazi.recoverage_queue.len() as u64);
            fazi.perform_recoverage(|input| unsafe {
                bar.inc(1);

                run_input(input.as_ptr(), input.len());
            });
            bar.finish();
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
        *LAST_INPUT.get().unwrap().lock().unwrap() = Some(self.input.clone());
        update_coverage();
    }

    /// Updates the maximum length that we can extend the input to
    pub(crate) fn update_max_size(&mut self) {
        if self.options.len_control > 0 && self.current_max_input_len < self.options.max_input_len {
            let max_mutation_len: usize = self.current_max_input_len;
            let len_control: u32 = self.options.len_control;

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
    /// coverage has been reached, save the fuzzing stats, and perform mutation 
    /// for the next iteration.
    pub fn end_iteration(&mut self, need_more_data: bool) {
        unpoison_input(self.input.as_ref());

        let UpdateCoverageResult {
            new_pc_count: new_coverage,
            old_pc_count: old_coverage,
            input_cov: input_coverage,
            old_cov_hash,
            new_cov_hash,
        } = update_coverage();

        if !need_more_data {
            let min_input_size = if let Some(min_input_size) = self.min_input_size {
                std::cmp::min(self.input.len(), min_input_size)
            } else {
                self.input.len()
            };

            self.min_input_size = Some(min_input_size);
        }

        let only_replay = self
            .options
            .replay_percentage
            .map(|p| p >= 1.0)
            .unwrap_or(false);

        if !only_replay && old_cov_hash != new_cov_hash {
            eprintln!(
                "old coverage: {}, new coverage: {}, mutations: {:?}",
                old_coverage,
                new_coverage,
                self.mutations.len()
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
            let corpus_dir: &Path = INPUTS_DIR
                .get()
                .as_ref()
                .expect("INPUTS_DIR not initialized");
            let extension: Option<&String> = INPUTS_EXTENSION.get();
            let extension = extension.map(|e| e.as_ref());

            std::thread::spawn(move || {
                save_input(corpus_dir.as_ref(), extension, input.as_slice());
            });

            self.current_mutation_depth = 0;
            self.mutations.clear();
        } else if only_replay
            || ((self.current_mutation_depth == self.options.max_mutation_depth
                || self
                    .options
                    .replay_percentage
                    .map(|p| self.rng.gen_bool(p))
                    .unwrap_or(false))
                || need_more_data)
        {
            let next_input = self
                .corpus
                .iter()
                .filter(|input| input.data.len() >= self.min_input_size.unwrap_or(0))
                .choose(&mut self.rng);

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

        let mutation = if !only_replay && need_more_data {
            Some(self.extend_input())
        } else {
            if let Some(replay_chance) = self.options.replay_percentage {
                if replay_chance >= 1.0 || self.rng.gen_bool(replay_chance) {
                    None
                } else {
                    Some(self.mutate_input())
                }
            } else {
                Some(self.mutate_input())
            }
        };

        let mut constants = COMPARISON_OPERANDS
            .get()
            .expect("failed to get CONSTANTS")
            .lock()
            .expect("failed to lock CONSTANTS");
        constants.clear();
        drop(constants);

        if let Some(mutation) = mutation {
            self.mutations.push(mutation);
        }
        self.current_mutation_depth += 1;

        self.iterations += 1;

        if self.last_update_time.elapsed().as_secs() >= STATUS_UPDATE_FREQ_SECS {
            let fazi_stats = crate::fazi::FaziStats {
                iterations: self.iterations,
                corpus: self.corpus.len(),
                current_mutation_depth: self.current_mutation_depth,
                current_max_input_len: self.current_max_input_len,
                coverage: new_coverage,
                last_update_time: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(), 
            };

            eprintln!("stats: {:?}", fazi_stats);
            std::thread::spawn(move || {
                write_fazi_stats(&fazi_stats);
            });
            self.last_update_time = Instant::now();
        }
    }
}

pub(crate) fn clear_coverage() {
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .clear();

    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .clear();
    let u8_counters = U8_COUNTERS
        .get()
        .expect("U8_COUNTERS not initialized")
        .lock()
        .expect("failed to lock U8_COUNTERS");
    let _module_pc_info = PC_INFO
        .get()
        .expect("PC_INFO not initialize")
        .lock()
        .expect("failed to lock PC_INFO");
    for module_counters in u8_counters.iter() {
        for counter in module_counters.iter() {
            counter.store(0, Ordering::Relaxed);
        }
    }
}

pub struct UpdateCoverageResult {
    pub new_pc_count: usize,
    pub old_pc_count: usize,
    pub input_cov: usize,
    pub old_cov_hash: Output<Sha1>,
    pub new_cov_hash: Output<Sha1>,
}

fn coverage_hash(cov: &HashMap<usize, usize>) -> Output<Sha1> {
    let mut hash = Sha1::new();
    for (key, value) in cov {
        hash.update(key.to_be_bytes().as_slice());
        hash.update(value.to_be_bytes().as_slice());
    }

    hash.finalize()
}

pub(crate) fn update_coverage() -> UpdateCoverageResult {
    let mut coverage = COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE");

    let old_cov_hash = coverage_hash(&coverage);

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

    // coverage.clear();

    // Skip the counters when updating coverage if limiting coverage to specific threads
    // These in-lined counters have no callback, which makes it impossible to determine the thread that hit the counter.
    // Can get same info (with small perf hit) by enabling -fsanitize-coverage=trace-pc-guard and/or -fsanitize-coverage=trace-pc
    if ENABLE_COUNTERS.load(Ordering::Relaxed) {
        for (module_idx, module_counters) in u8_counters.iter().enumerate() {
            for (counter_idx, counter) in module_counters.iter().enumerate() {
                let count = counter.load(Ordering::Relaxed);
                if count > 0 {
                    let pc_info = &module_pc_info[module_idx][counter_idx];
                    *coverage.entry(pc_info.pc).or_default() = 1;
                    counter.store(0, Ordering::Relaxed);
                    input_coverage += 1;
                }
            }
        }
    }

    for pc in testcase_coverage.drain() {
        if let None = coverage.get(&pc) {
            coverage.insert(pc, 1);
        }
    }

    let new_cov_hash = coverage_hash(&coverage);

    UpdateCoverageResult {
        new_pc_count: coverage.len(),
        old_pc_count: old_coverage,
        input_cov: input_coverage,
        old_cov_hash: old_cov_hash,
        new_cov_hash: new_cov_hash,
    }
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

    if PERFORMING_RECOVERAGE.load(Ordering::Relaxed) {
        if let Some(metadata) = CORPUS_METADATA.get() {
            if let Ok(mut metadata) = metadata.try_lock() {
                metadata
                    .ignore_input_hashes
                    .insert(result.as_slice().to_vec());

                if let Ok(mut output) = std::fs::File::create("corpus_metadata.json") {
                    let _ = serde_json::to_writer(&mut output, &*metadata);
                }
            }
        }
    }
}


fn write_fazi_stats(stats: &crate::fazi::FaziStats) {
    let stats_file: &Path  = FAZI_STATS_FILE.get().as_ref().expect("FAZI_STATS_FILE not initialized"); 
    let json = serde_json::to_string(&stats).unwrap();
    println!("saving stats to: {}", stats_file.to_str().unwrap());
    std::fs::write(&stats_file, json).expect("failed to write fuzzer stats file!");
}

pub(crate) fn save_input(corpus_dir: &Path, extension: Option<&str>, input: &[u8]) {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    let filename = hex::encode(result.as_slice());
    let mut corpus_file_path = corpus_dir.join(format!("input-{}", filename));
    if let Some(extension) = extension {
        corpus_file_path.set_extension(extension);
    }

    eprintln!("Saving corpus input to {:?}", corpus_file_path);

    write_input(&corpus_file_path, input);
}

pub(crate) fn write_input(path: &Path, input: &[u8]) {
    ensure_parent_dir_exists(path);
    std::fs::write(path, input).expect("failed to save corpus input file!");
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
