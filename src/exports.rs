use std::{
    ffi::CStr,
    hint::black_box,
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc, Mutex},
};

use clap::StructOpt;
use rand::Rng;
use sha1::Digest;

use crate::{
    driver::{
        save_input, update_coverage, write_input, COMPARISON_OPERANDS, COV_THREADS, CRASHES_DIR,
        ENABLE_COUNTERS, FAZI, FAZI_INITIALIZED, INPUTS_DIR, INPUTS_EXTENSION,
    },
    options::RuntimeOptions,
    sancov::reset_pc_guards,
    Fazi,
};

#[no_mangle]
/// Main function for initializing the Fazi global state
pub extern "C" fn fazi_initialize() {
    if FAZI_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    let fazi = Fazi::default();

    fazi.initialize_globals();

    FAZI.set(Mutex::new(fazi))
        .expect("FAZI already initialized");
}

#[no_mangle]
/// Sets up Fazi's signal handlers
pub extern "C" fn fazi_init_signal_handler() {
    let fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.setup_signal_handler();
}

#[no_mangle]
/// Sets up Fazi's corpus/crash artifact extension
pub extern "C" fn fazi_set_artifact_extension(extension: *const libc::c_char) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    let extension = unsafe { CStr::from_ptr(extension) };
    let extension = extension.to_string_lossy().into_owned();
    INPUTS_EXTENSION
        .set(extension.clone())
        .expect("input extension has already been set");

    fazi.options.artifact_extension = extension.into();
}

#[no_mangle]
/// Gets the next testcase in the recoverage queue. If there's no remaining item
/// in the queue, the `data` pointer will be null and `len` set to 0.
pub extern "C" fn fazi_next_recoverage_testcase(data: *mut *const u8, len: *mut usize) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.recoverage_testcase_end();

    // TODO: lifetime issues if the corpus entries are dropped before the caller
    // finishes using the data. This shouldn't happen because technically the corpus
    // entires are "static" (i.e. lifetime of the fazi object)
    if let Some(input) = fazi.recoverage_queue.pop() {
        fazi.last_recoverage_input = Some(input.clone());

        unsafe {
            data.write(input.as_ptr());
            len.write(input.len());
        }
    } else {
        fazi.recoverage_testcase_end();

        unsafe {
            data.write(std::ptr::null_mut());
            len.write(0);
        }
    }

    // .next_iteration(|input| {
    //     let f = libfuzzer_runone_fn();
    //     unsafe {
    //         f(input.as_ptr(), input.len());
    //     }
    // })
}

#[no_mangle]
/// Perform necessary pre-iteration tasks and sets the `data` and `len` fields
/// to the current testcase and its size, respectively.
pub extern "C" fn fazi_start_iteration(data: *mut *const u8, len: *mut usize) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.start_iteration();

    unsafe {
        data.write(fazi.input.as_ptr());
        len.write(fazi.input.len());
    }
}

#[no_mangle]
/// Signal to end the current iteration. This performs the necessary steps for
/// gathering new coverage and setting up the input state for the next
/// iteration
pub extern "C" fn fazi_end_iteration(need_more_data: bool) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.end_iteration(need_more_data);
}

#[no_mangle]
/// Sets the corpus output directory
pub extern "C" fn fazi_set_corpus_dir(dir: *const libc::c_char) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    let dir = unsafe { CStr::from_ptr(dir) };
    let path: PathBuf = dir.to_string_lossy().into_owned().into();

    std::fs::create_dir_all(&path).expect("failed to make corpus dir");

    INPUTS_DIR
        .set(path.clone())
        .expect("corpus dir has already been set");

    fazi.options.corpus_dir = path;
}

#[no_mangle]
/// Sets the crashes output directory
pub extern "C" fn fazi_set_crashes_dir(dir: *const libc::c_char) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    let dir = unsafe { CStr::from_ptr(dir) };

    let path: PathBuf = dir.to_string_lossy().into_owned().into();

    std::fs::create_dir_all(&path).expect("failed to make crashes dir");

    CRASHES_DIR
        .set(path.clone())
        .expect("crashes dir has already been set");

    fazi.options.crashes_dir = path;
}

#[no_mangle]
/// Adds binary data to the Fazi dictionary
pub extern "C" fn fazi_dictionary_add(
    a: *const libc::c_char,
    alen: usize,
    b: *const libc::c_char,
    blen: usize,
) {
    let constants = COMPARISON_OPERANDS
        .get()
        .expect("constants global not initialized");

    if let Ok(mut constants) = constants.try_lock() {
        match (a == std::ptr::null(), b == std::ptr::null()) {
            (true, false) => {
                let dictionary_data = unsafe { std::slice::from_raw_parts(b as *const u8, blen) };
                constants
                    .binary
                    .insert((Vec::with_capacity(0), dictionary_data.to_vec()));
            }
            (false, true) => {
                let dictionary_data = unsafe { std::slice::from_raw_parts(a as *const u8, alen) };
                constants
                    .binary
                    .insert((Vec::with_capacity(0), dictionary_data.to_vec()));
            }
            (false, false) => {
                let a_dict = unsafe { std::slice::from_raw_parts(a as *const u8, alen) };
                let b_dict = unsafe { std::slice::from_raw_parts(b as *const u8, blen) };
                constants.binary.insert((a_dict.to_vec(), b_dict.to_vec()));
            }
            (true, true) => {
                // Do nothing, we got passed bad input
            }
        }
    }
}

#[no_mangle]
/// Enables RUST_BACKTRACE=full for debugging issues with Fazi
pub extern "C" fn fazi_enable_rust_backtrace() {
    std::env::set_var("RUST_BACKTRACE", "full");
}

#[no_mangle]
/// Parses args from the command line
pub extern "C" fn fazi_read_cli_args() {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.set_options(RuntimeOptions::parse());
}

#[no_mangle]
/// Parses args from the command line
pub extern "C" fn fazi_restore_inputs() {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.restore_inputs();
}

#[no_mangle]
/// Parses args from the command line
pub extern "C" fn fazi_enable_replay_mode(percentage: std::os::raw::c_float) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.options.replay_percentage = Some(percentage.into());
}

#[no_mangle]
/// Parses args from the command line
pub extern "C" fn fazi_add_corpus_entry(data: *const u8, len: usize) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    if let Some(corpus_dir) = INPUTS_DIR.get() {
        let data = unsafe { std::slice::from_raw_parts(data, len) };
        let data: Arc<Vec<u8>> = Arc::new(data.into());
        let extension: Option<&String> = INPUTS_EXTENSION.get();
        let extension = extension.map(|e| e.as_ref());
        save_input(corpus_dir, extension, data.as_ref());

        fazi.corpus.push(crate::Input {
            coverage: 1,
            data: Arc::clone(&data),
        });

        if fazi.input.is_empty() && fazi.corpus.len() == 1 {
            fazi.input = data;
        }
    } else {
        eprintln!("fazi_add_corpus_entry: INPUTS_DIR not initialized");
    }
}

#[no_mangle]
/// Set the max size an input can reach
pub extern "C" fn fazi_set_max_input_len(len: usize) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.options.max_input_len = len;
}

#[no_mangle]
/// Set the max size an input can reach
pub extern "C" fn fazi_set_min_input_len(len: usize) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.min_input_size = Some(len);
    fazi.options.min_input_len = len;
}

#[no_mangle]
/// Add thread to set of threads allowed to contribute to coverage
pub extern "C" fn fazi_add_coverage_thread(thread_id: usize) {
    COV_THREADS
        .get()
        .expect("Failed to get COV_THREADS")
        .write()
        .expect("Failed to lock COV_THREADS")
        .insert(thread_id);
}

#[no_mangle]
/// Add thread to set of threads allowed to contribute to coverage
pub extern "C" fn fazi_add_coverage_current_thread() {
    COV_THREADS
        .get()
        .expect("Failed to get COV_THREADS")
        .write()
        .expect("Failed to lock COV_THREADS")
        .insert(thread_id::get());
}

#[no_mangle]
/// Clear set of threads coverage limited to.  Will allow all threads to contribute to coverage
pub extern "C" fn fazi_clear_coverage_threads() {
    COV_THREADS
        .get()
        .expect("Failed to get COV_THREADS")
        .write()
        .expect("Failed to lock COV_THREADS")
        .clear();
}

#[no_mangle]
/// Disable inlined counters adding to coverage
/// Have no way of knowing which thread called these as there is no callback, the counter is inlined to the function.
pub extern "C" fn fazi_disable_cov_counters() {
    ENABLE_COUNTERS.store(false, Ordering::Relaxed);
}

#[no_mangle]
/// Re-enable inlined counters counting towards fazi coverage if previously disabled
pub extern "C" fn fazi_enable_cov_counters() {
    ENABLE_COUNTERS.store(true, Ordering::Relaxed);
}

#[no_mangle]
/// Reset guard variables sent in user defined callback that measures code coverage
/// Reset fazi internal coverage as well
pub extern "C" fn fazi_reset_coverage() {
    reset_pc_guards();
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");
    fazi.clear_coverage();
}

#[no_mangle]
pub extern "C" fn fazi_set_max_mutation_depth(depth: usize) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");
    fazi.options.max_mutation_depth = depth;
}

#[no_mangle]
pub extern "C" fn fazi_gen_bool_with_probability(probability: f64) -> bool {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.rng_mut().gen_bool(probability)
}

#[no_mangle]
pub extern "C" fn fazi_has_backtrace_been_seen(depth: usize) -> bool {
    // Grab a backtrace
    let mut hasher = sha1::Sha1::new();
    let mut curr_depth = 0;
    backtrace::trace(|frame| {
        hasher.update((frame.ip() as usize).to_be_bytes());

        if curr_depth == depth {
            false
        } else {
            curr_depth += 1;
            true
        }
    });

    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.backtrace_set
        .insert(hasher.finalize().as_slice().try_into().unwrap())
}

#[no_mangle]
pub extern "C" fn fazi_write_last_message(data: *const u8, len: usize) {
    let fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    if let Some(corpus_dir) = INPUTS_DIR.get() {
        let mut corpus_file_path = corpus_dir.join("input-last");
        if let Some(extension) = INPUTS_EXTENSION.get() {
            corpus_file_path.set_extension(extension);
        }

        let input = unsafe { std::slice::from_raw_parts(data, len) };

        write_input(&corpus_file_path, input)
    } else {
        eprintln!("fazi_write_last_message: INPUTS_DIR not initialized");
    }
}
