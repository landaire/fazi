use std::{
    ffi::CStr,
    sync::{
        atomic::{Ordering},
        Arc, Mutex,
    },
};

use rand::{prelude::IteratorRandom, prelude::SliceRandom, Rng};

use crate::{
    driver::{CONSTANTS, COVERAGE, COVERAGE_BEFORE_ITERATION, FAZI, FAZI_INITIALIZED, LAST_INPUT}, signal, Fazi,
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
pub extern "C" fn fazi_next_recoverage_testcase() -> FaziInput {
    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    let coverage = COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE");
    let new_coverage = coverage.len();
    COVERAGE_BEFORE_ITERATION.store(new_coverage, Ordering::Relaxed);

    // TODO: lifetime issues if the corpus entries are dropped before the caller
    // finishes using the data. This shouldn't happen because technically the corpus
    // entires are "static" (i.e. lifetime of the fazi object)
    if let Some(input) = fazi.recoverage_queue.pop() {
        FaziInput {
            data: input.as_ptr(),
            size: input.len(),
        }
    } else {
        FaziInput {
            data: std::ptr::null(),
            size: 0,
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
pub extern "C" fn fazi_start_testcase() -> FaziInput {
    let fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    FaziInput {
        data: fazi.input.as_ptr(),
        size: fazi.input.len(),
    }
    // .next_iteration(|input| {
    //     let f = libfuzzer_runone_fn();
    //     unsafe {
    //         f(input.as_ptr(), input.len());
    //     }
    // })
}

#[no_mangle]
pub extern "C" fn fazi_end_testcase(need_more_data: bool) {
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

impl<R: Rng> Fazi<R> {
    pub(crate) fn update_max_size(&mut self) {
        // Update the max length
        if self.options.len_control > 0 && self.current_max_mutation_len < self.max_input_size {
            let max_mutation_len_f64: f64 = self.max_input_size as f64;
            let len_control: f64 = self
                .options
                .len_control
                .try_into()
                .expect("failed to convert len_control");
            let factor = (len_control * max_mutation_len_f64.log10()).trunc() as usize;
            // println!("factor: {}", factor);
            if self.iterations - self.last_corpus_update_run > factor {
                let max_mutation_len = self.max_input_size;
                let new_max_mutation_len =
                    max_mutation_len + (max_mutation_len_f64.log10() as usize);
                self.max_input_size = new_max_mutation_len;
                // println!("Updating max length from {max_mutation_len} to {new_max_mutation_len}")
            }
        }

        self.current_max_mutation_len = std::cmp::max(self.input.len(), self.max_input_size);
    }
    pub(crate) fn end_iteration(&mut self, need_more_data: bool) {
        let coverage = COVERAGE
            .get()
            .expect("failed to get COVERAGE")
            .lock()
            .expect("failed to lock COVERAGE");
        let new_coverage = coverage.len();
        drop(coverage);

        // println!("iter: {}", self.iterations);

        if !need_more_data {
            let min_input_size = if let Some(min_input_size) = self.min_input_size {
                std::cmp::min(self.input.len(), min_input_size)
            } else {
                self.input.len()
            };

            self.min_input_size = Some(min_input_size);
        }

        let can_request_more_data = !self.min_input_size.is_some();

        let old_coverage = COVERAGE_BEFORE_ITERATION.load(Ordering::Relaxed);
        if old_coverage != new_coverage {
            println!(
                "old coverage: {}, new coverage: {}, mutations: {:?}",
                old_coverage, new_coverage, self.mutations
            );

            self.corpus.push(self.input.clone());

            let input = self.input.clone();
            let corpus_dir = self.options.corpus_dir.clone();
            std::thread::spawn(move || {
                signal::save_input(corpus_dir.as_ref(), input.as_slice());
            });
            COVERAGE_BEFORE_ITERATION.store(new_coverage, Ordering::Relaxed);

            self.current_mutation_depth = 0;
            self.mutations.clear();

            let mut constants = CONSTANTS
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

                let mut constants = CONSTANTS
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

        let mut last_input = LAST_INPUT
            .get()
            .expect("LAST_INPUT not initialized")
            .lock()
            .expect("failed to lock LAST_INPUT");
        *last_input = Arc::clone(&self.input);
        drop(last_input);

        self.iterations += 1;

        if self.iterations % 1000 == 0 {
            println!("iter: {}", self.iterations);
        }
    }
}
