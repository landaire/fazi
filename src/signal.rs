use std::{path::Path, thread};

use libc::SIGABRT;
use rand::Rng;
use sha1::{Digest, Sha1};
use signal_hook::iterator::Signals;

use crate::{
    driver::{handle_crash, save_input, LAST_INPUT},
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
                    let last_input = LAST_INPUT
                        .get()
                        .expect("LAST_INPUT not initialized")
                        .lock()
                        .expect("could not lock LAST_INPUT");
                    handle_crash(crashes_dir.as_ref(), last_input.as_slice());
                    save_input(corpus_dir.as_ref(), last_input.as_slice());
                }
            }
        });
    }
}
