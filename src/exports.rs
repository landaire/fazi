use std::sync::{Arc, Mutex, atomic::Ordering};

use rand::{prelude::SliceRandom, Rng};

use crate::{
    driver::{CONSTANTS, COVERAGE, FAZI, LAST_INPUT, COVERAGE_BEFORE_ITERATION},
    libfuzzer_runone_fn, signal, Fazi,
};

#[repr(C)]
pub struct FaziInput {
    data: *const u8,
    size: usize,
}

pub extern "C" fn fazi_initialize() {
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
}

pub extern "C" fn fazi_start_testcase() -> FaziInput {
    let fazi = FAZI.get()
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

pub extern "C" fn fazi_end_testcase() {
    let mut fazi = FAZI.get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.end_iteration();
}

impl<R: Rng> Fazi<R> {
    pub(crate) fn end_iteration(&mut self) {
        let coverage = COVERAGE
            .get()
            .expect("failed to get COVERAGE")
            .lock()
            .expect("failed to lock COVERAGE");
        let new_coverage = coverage.len();
        drop(coverage);

        let old_coverage = COVERAGE_BEFORE_ITERATION.load(Ordering::Relaxed);
        if old_coverage != new_coverage {
            eprintln!(
                "old coverage: {}, new coverage: {}",
                old_coverage, new_coverage
            );

            self.corpus.push(self.input.clone());

            let input = self.input.clone();
            let corpus_dir = self.options.corpus_dir.clone();
            std::thread::spawn(move || {
                signal::save_input(corpus_dir.as_ref(), input.as_slice());
            });
            COVERAGE_BEFORE_ITERATION.store(new_coverage, Ordering::Relaxed);
        } else {
            self.input = self
                .corpus
                .as_slice()
                .choose(&mut self.rng)
                .expect("corpus is empty")
                .clone();
        }

        self.mutate_input();
        let mut last_input = LAST_INPUT
            .get()
            .expect("LAST_INPUT not initialized")
            .lock()
            .expect("failed to lock LAST_INPUT");
        *last_input = Arc::clone(&self.input);
        drop(last_input);

        self.iterations += 1;

        if self.iterations % 1000 == 0 {
            eprintln!("iter: {}", self.iterations);
        }
    }
}
