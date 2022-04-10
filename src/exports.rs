use std::{
    ffi::CStr,
    sync::{atomic::Ordering, Mutex},
};

use crate::{
    driver::{update_coverage, CONSTANTS, COVERAGE, FAZI, FAZI_INITIALIZED, LAST_INPUT},
    Fazi,
};

#[repr(C)]
pub struct FaziInput {
    data: *const u8,
    size: usize,
}

#[no_mangle]
pub extern "C" fn fazi_initialize() {
    if FAZI_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    CONSTANTS
        .set(Default::default())
        .expect("CONSTANTS already initialized");
    COVERAGE
        .set(Default::default())
        .expect("COVERAGE already initialized");
    LAST_INPUT
        .set(Default::default())
        .expect("LAST_INPUT already initialized");

    let mut fazi = Fazi::default();

    fazi.restore_inputs();
    fazi.setup_signal_handler();

    FAZI.set(Mutex::new(fazi))
        .expect("FAZI already initialized");

    FAZI_INITIALIZED.store(true, Ordering::Relaxed);
}

#[no_mangle]
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
pub extern "C" fn fazi_end_iteration(need_more_data: bool) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.end_iteration(need_more_data);
}

#[no_mangle]
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
pub extern "C" fn fazi_set_crashes_dir(dir: *const libc::c_char) {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    let dir = unsafe { CStr::from_ptr(dir) };

    fazi.options.crashes_dir = dir.to_string_lossy().into_owned().into();
}
