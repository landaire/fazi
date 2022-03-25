use rand::prelude::{SliceRandom, StdRng};

use crate::{coverage::CoverageMap, signal, weak::weak, Fazi};
use std::{
    collections::{BTreeSet, HashSet},
    lazy::SyncOnceCell,
    sync::{Arc, Mutex},
};

pub(crate) static CONSTANTS: SyncOnceCell<Mutex<CoverageMap>> = SyncOnceCell::new();
pub(crate) static COVERAGE: SyncOnceCell<Mutex<HashSet<usize>>> = SyncOnceCell::new();
pub(crate) static LAST_INPUT: SyncOnceCell<Mutex<Arc<Vec<u8>>>> = SyncOnceCell::new();

#[no_mangle]
extern "C" fn main() {
    // Initialize the global CONSANTS
    {
        CONSTANTS
            .set(Default::default())
            .expect("CONSTANTS already initialized");
        COVERAGE
            .set(Default::default())
            .expect("COVERAGE already initialized");
        LAST_INPUT
            .set(Default::default())
            .expect("LAST_INPUT already initialized");
    }

    let mut fazi = Fazi::default();
    fazi.restore_inputs();

    weak!(fn LLVMFuzzerTestOneInput(*const u8, usize) -> std::os::raw::c_int);

    let f = LLVMFuzzerTestOneInput
        .get()
        .expect("failed to get LLVMFuzzerTestOneInput");
    fazi.setup_signal_handler();

    eprintln!("Performing recoverage");
    for input in &fazi.corpus {
        unsafe {
            f(input.as_ptr(), input.len());
        }
    }

    eprintln!("Performing fuzzing");

    let mut iter = 0usize;
    loop {
        let coverage = COVERAGE
            .get()
            .expect("failed to get COVERAGE")
            .lock()
            .expect("failed to lock COVERAGE");
        let old_coverage = coverage.len();
        drop(coverage);

        unsafe {
            f(fazi.input.as_ptr(), fazi.input.len());
        }

        let coverage = COVERAGE
            .get()
            .expect("failed to get COVERAGE")
            .lock()
            .expect("failed to lock COVERAGE");
        let new_coverage = coverage.len();
        drop(coverage);

        if old_coverage != new_coverage {
            eprintln!(
                "old coverage: {}, new coverage: {}",
                old_coverage, new_coverage
            );

            fazi.corpus.push(fazi.input.clone());

            let input = fazi.input.clone();
            let corpus_dir = fazi.options.corpus_dir.clone();
            std::thread::spawn(move || {
                signal::save_input(corpus_dir.as_ref(), input.as_slice());
            });
        } else {
            fazi.input = fazi
                .corpus
                .as_slice()
                .choose(&mut fazi.rng)
                .expect("corpus is empty")
                .clone();
        }

        fazi.mutate_input();
        let mut last_input = LAST_INPUT
            .get()
            .expect("LAST_INPUT not initialized")
            .lock()
            .expect("failed to lock LAST_INPUT");
        *last_input = Arc::clone(&fazi.input);
        drop(last_input);

        iter += 1;

        if iter % 1000 == 0 {
            eprintln!("iter: {iter}");
        }
    }
}
