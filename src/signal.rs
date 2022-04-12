use std::{thread, path::Path, panic::{self, PanicInfo}};

use libc::{SIGABRT};
use rand::Rng;
use signal_hook::iterator::Signals;

use crate::{
    driver::{handle_crash, save_input, LAST_INPUT, CRASHES_DIR, INPUTS_DIR},
    Fazi, weak_imports::sanitizer_set_death_callback_fn,
};

impl<R: Rng> Fazi<R> {
    /// Sets up the signal handling routine which will be used for ensuring
    /// crashing inputs are saved.
    pub fn setup_signal_handler(&self) {
        let mut signals = Signals::new(&[SIGABRT]).expect("failed to setup signal handler");

        unsafe { CRASHES_DIR = Some(self.options.crashes_dir.clone()) };
        unsafe { INPUTS_DIR = Some(self.options.corpus_dir.clone()) };

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

    pub fn setup_panic_hook(&self) {
        panic::set_hook(Box::new(|panic_info| {
            let thread = thread::current();
            let name = thread.name().unwrap_or("<unnamed>");
            let location = panic_info.location().unwrap();
            let msg = match panic_info.payload().downcast_ref::<&'static str>() {
                Some(s) => *s,
                None => match panic_info.payload().downcast_ref::<String>() {
                    Some(s) => &s[..],
                    None => "Box<dyn Any>",
                },
            };
            eprintln!("thread '{name}' panicked at '{msg}', {location}");

            death_callback();
        }));
    }
}

pub(crate) extern "C" fn death_callback() {
    let crashes_dir: &Path = unsafe { CRASHES_DIR.as_ref().expect("CRASHES_DIR not initialized") };
    let corpus_dir: &Path = unsafe { INPUTS_DIR.as_ref().expect("INPUTS_DIR not initialized") };

    if let Some(last_input) = unsafe { LAST_INPUT.take() } {
        handle_crash(crashes_dir.as_ref(), last_input.as_slice());
        save_input(corpus_dir.as_ref(), last_input.as_slice());
    }

    std::process::abort();
}
