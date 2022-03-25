use rand::prelude::StdRng;

use crate::{weak::weak, Fazi, coverage::CoverageMap};
use std::{lazy::SyncOnceCell, sync::Mutex, collections::{BTreeSet, HashSet}};

pub(crate) static CONSTANTS: SyncOnceCell<Mutex<CoverageMap>> = SyncOnceCell::new();
pub(crate) static COVERAGE: SyncOnceCell<Mutex<HashSet<usize>>> = SyncOnceCell::new();

#[no_mangle]
extern "C" fn main() {
    // Initialize the global CONSANTS
    CONSTANTS.set(Default::default()).expect("CONSTANTS already initialized");
    COVERAGE.set(Default::default()).expect("COVERAGE already initialized");

    let mut fazi = Fazi::default();

    weak!(fn LLVMFuzzerTestOneInput(*const u8, usize) -> std::os::raw::c_int);

    let f = LLVMFuzzerTestOneInput.get().expect("failed to get LLVMFuzzerTestOneInput");
    let mut iter = 0usize;
    let mut corpus: Vec<Vec<u8>> = Vec::new();
    loop {
        let coverage = COVERAGE.get().expect("failed to get COVERAGE").lock().expect("failed to lock COVERAGE");
        let old_coverage = coverage.len();
        drop(coverage);

        unsafe {
            f(fazi.input.as_ptr(), fazi.input.len());
        }

        let coverage = COVERAGE.get().expect("failed to get COVERAGE").lock().expect("failed to lock COVERAGE");
        let new_coverage = coverage.len();
        drop(coverage);

        if old_coverage != new_coverage {
            eprintln!("old coverage: {}, new coverage: {}", old_coverage, new_coverage);
            corpus.push(fazi.input.clone());
        } else {
            fazi.input = corpus.last().unwrap().clone();
        }

        fazi.mutate_input();
        iter += 1;

        if iter % 1000 == 0 {
            eprintln!("iter: {iter}");
        }

    }
}