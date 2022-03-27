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
    fazi_initialize();

    let mut fazi = FAZI.get().expect("FAZI not initialized").lock().expect("could not lock FAZI");

    eprintln!("Performing recoverage");
    let f = crate::libfuzzer_runone_fn();
    for input in fazi.corpus.iter().cloned().collect::<Vec<_>>() {
        unsafe {
            f(input.as_ptr(), input.len());
        }

        fazi.end_iteration(false);
    }

    eprintln!("Performing fuzzing");
    loop {
        unsafe {
            f(fazi.input.as_ptr(), fazi.input.len());
        }

        fazi.end_iteration(false);
    }
}
