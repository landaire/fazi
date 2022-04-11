use std::{
    ffi::CStr,
    sync::{atomic::Ordering, Mutex},
};

use crate::{
    driver::{update_coverage, COMPARISON_OPERANDS, COVERAGE, FAZI, FAZI_INITIALIZED, U8_COUNTERS, PC_INFO},
    Fazi,
};

#[no_mangle]
/// Main function for initializing the Fazi global state
pub extern "C" fn fazi_initialize() {
    if FAZI_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    COMPARISON_OPERANDS
        .set(Default::default())
        .expect("CONSTANTS already initialized");
    COVERAGE
        .set(Default::default())
        .expect("COVERAGE already initialized");
    U8_COUNTERS.set(Default::default())
        .expect("U8_COUNTERS already initialized");
    PC_INFO.set(Default::default())
        .expect("PC_INFO already initialized");

    let mut fazi = Fazi::default();

    fazi.restore_inputs();
    fazi.setup_signal_handler();

    FAZI.set(Mutex::new(fazi))
        .expect("FAZI already initialized");

    FAZI_INITIALIZED.store(true, Ordering::Relaxed);
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

    update_coverage();

    // TODO: lifetime issues if the corpus entries are dropped before the caller
    // finishes using the data. This shouldn't happen because technically the corpus
    // entires are "static" (i.e. lifetime of the fazi object)
    if let Some(input) = fazi.recoverage_queue.pop() {
        unsafe {
            data.write(input.as_ptr());
            len.write(input.len());
        }
    } else {
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
