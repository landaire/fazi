use std::thread;

use libc::SIGABRT;
use rand::Rng;
use sha1::Digest;
use signal_hook::iterator::Signals;

use crate::{
    driver::{handle_crash, save_input, FAZI},
    Fazi,
};

impl<R: Rng> Fazi<R> {
    pub(crate) fn setup_signal_handler(&self) {
        let mut signals = Signals::new(&[SIGABRT]).expect("failed to setup signal handler");

        let crashes_dir = self.options.crashes_dir.clone();
        let corpus_dir = self.options.corpus_dir.clone();
        thread::spawn(move || {
            for sig in signals.forever() {
                if sig == SIGABRT {
                    let fazi = FAZI
                        .get()
                        .expect("FAZI not initialized")
                        .lock()
                        .expect("could not lock FAZI");
                    let last_input = fazi.input.clone();
                    handle_crash(crashes_dir.as_ref(), last_input.as_slice());
                    save_input(corpus_dir.as_ref(), last_input.as_slice());
                }
            }
        });
    }
}
