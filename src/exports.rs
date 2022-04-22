use std::{
    ffi::CStr,
    sync::{atomic::Ordering, Mutex},
};

use clap::StructOpt;

use crate::{
    driver::{update_coverage, FAZI, FAZI_INITIALIZED, COMPARISON_OPERANDS},
    Fazi, options::RuntimeOptions,
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

    fazi.options.corpus_dir = dir.to_string_lossy().into_owned().into();
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

    fazi.options.crashes_dir = dir.to_string_lossy().into_owned().into();
}

#[no_mangle]
/// Adds binary data to the Fazi dictionary
pub extern "C" fn fazi_dictionary_add(a: *const libc::c_char, alen: usize, b: *const libc::c_char, blen: usize) {
    let constants = COMPARISON_OPERANDS
        .get()
        .expect("constants global not initialized");

    if let Ok(mut constants) = constants.try_lock() {
        match (a == std::ptr::null(), b == std::ptr::null()) {
            (true, false) => {
                let dictionary_data = unsafe { std::slice::from_raw_parts(b as *const u8, blen) };
                constants.binary.insert((Vec::with_capacity(0), dictionary_data.to_vec()));
            }
            (false, true) => {
                let dictionary_data = unsafe { std::slice::from_raw_parts(a as *const u8, alen) };
                constants.binary.insert((Vec::with_capacity(0), dictionary_data.to_vec()));
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