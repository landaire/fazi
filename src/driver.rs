use rand::prelude::StdRng;

use crate::{exports::fazi_initialize, sancov::{CoverageMap, PcEntry}, Fazi, options::RuntimeOptions};
use std::{
    collections::HashSet,
    lazy::SyncOnceCell,
    sync::{
        atomic::{AtomicBool, AtomicU8, AtomicUsize},
        Arc, Mutex,
    },
};

pub(crate) static CONSTANTS: SyncOnceCell<Mutex<CoverageMap>> = SyncOnceCell::new();
pub(crate) static COVERAGE: SyncOnceCell<Mutex<HashSet<usize>>> = SyncOnceCell::new();
pub(crate) static LAST_INPUT: SyncOnceCell<Mutex<Arc<Vec<u8>>>> = SyncOnceCell::new();
pub(crate) static FAZI: SyncOnceCell<Mutex<Fazi<StdRng>>> = SyncOnceCell::new();
pub(crate) static FAZI_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(crate) static mut U8_COUNTERS: Option<&'static [AtomicU8]> = None;
pub(crate) static mut PC_INFO: Option<&'static [PcEntry]> = None;

#[cfg(feature = "main_entrypoint")]
#[no_mangle]
extern "C" fn main() {
    use std::sync::atomic::Ordering;

    use clap::StructOpt;

    use crate::{weak_imports::libfuzzer_runone_fn, exports::update_coverage};

    fazi_initialize();

    let mut fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");

    fazi.set_options(RuntimeOptions::parse());

    eprintln!("Performing recoverage");
    let f = libfuzzer_runone_fn();
    for input in fazi.recoverage_queue.drain(..) {
        unsafe {
            f(input.as_ptr(), input.len());
        }
    }

    update_coverage();

    eprintln!("Performing fuzzing");
    loop {
        fazi.start_iteration();

        let res = unsafe { f(fazi.input.as_ptr(), fazi.input.len()) };

        fazi.end_iteration(res != 0);
    }
}