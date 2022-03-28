use rand::prelude::{SliceRandom, StdRng};

use crate::{coverage::CoverageMap, signal, weak::weak, Fazi, exports::fazi_initialize};
use std::{
    collections::{BTreeSet, HashSet},
    lazy::SyncOnceCell,
    sync::{Arc, Mutex, atomic::{AtomicUsize, AtomicBool}},
};

pub(crate) static CONSTANTS: SyncOnceCell<Mutex<CoverageMap>> = SyncOnceCell::new();
pub(crate) static COVERAGE: SyncOnceCell<Mutex<HashSet<usize>>> = SyncOnceCell::new();
pub(crate) static LAST_INPUT: SyncOnceCell<Mutex<Arc<Vec<u8>>>> = SyncOnceCell::new();
pub(crate) static FAZI: SyncOnceCell<Mutex<Fazi<StdRng>>> = SyncOnceCell::new();
pub(crate) static COVERAGE_BEFORE_ITERATION: AtomicUsize = AtomicUsize::new(0);
pub(crate) static FAZI_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "main_entrypoint")]
#[no_mangle]
extern "C" fn main() {
    use std::sync::atomic::Ordering;

    fazi_initialize();

    let mut fazi = FAZI.get().expect("FAZI not initialized").lock().expect("could not lock FAZI");

    eprintln!("Performing recoverage");
    let f = crate::libfuzzer_runone_fn();
    for input in fazi.recoverage_queue.drain(..) {
        unsafe {
            f(input.as_ptr(), input.len());
        }
    }

    let coverage = COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE");
    let new_coverage = coverage.len();
    COVERAGE_BEFORE_ITERATION.store(new_coverage, Ordering::Relaxed);
    drop(coverage);

    eprintln!("Performing fuzzing");
    loop {
        let res = unsafe {
            f(fazi.input.as_ptr(), fazi.input.len())
        };

        fazi.end_iteration(res != 0);
    }
}
