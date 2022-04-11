use std::{thread, path::Path};

use libc::SIGABRT;
use rand::Rng;
use signal_hook::iterator::Signals;

use crate::{
    driver::{handle_crash, save_input, FAZI},
    Fazi, weak_imports::sanitizer_set_death_callback_fn,
};

impl<R: Rng> Fazi<R> {
    /// Sets up the signal handling routine which will be used for ensuring
    /// crashing inputs are saved.
    pub(crate) fn setup_signal_handler(&self) {
        let mut signals = Signals::new(&[SIGABRT]).expect("failed to setup signal handler");

        if let Some(set_death_callback) = sanitizer_set_death_callback_fn() {
            unsafe {
                set_death_callback(death_callback);
            }
        }

        thread::spawn(move || {
            for sig in signals.forever() {
                if sig == SIGABRT {
                    death_callback();
                }
            }
        });
    }
}

extern "C" fn death_callback() {
    let fazi = FAZI
        .get()
        .expect("FAZI not initialized")
        .lock()
        .expect("could not lock FAZI");
        
    let crashes_dir: &Path = fazi.options.crashes_dir.as_ref();
    let corpus_dir: &Path = fazi.options.corpus_dir.as_ref();
    let last_input = fazi.input.clone();
    handle_crash(crashes_dir.as_ref(), last_input.as_slice());
    save_input(corpus_dir.as_ref(), last_input.as_slice());

    std::process::abort();
}
