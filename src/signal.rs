use std::{
    panic::{self},
    path::Path,
    thread,
};

use libc::{SIGABRT, SIGSEGV};
use rand::Rng;
use signal_hook::iterator::Signals;

use crate::{
    driver::{handle_crash, save_input, CRASHES_DIR, INPUTS_DIR, INPUTS_EXTENSION, LAST_INPUT},
    weak_imports::sanitizer_set_death_callback_fn,
    Fazi,
};

impl<R: Rng> Fazi<R> {
    /// Sets up the signal handling routine which will be used for ensuring
    /// crashing inputs are saved.
    pub fn setup_signal_handler(&self) {
        let mut signals = Signals::new(&[SIGABRT]).expect("failed to setup signal handler");

        if let Some(set_death_callback) = sanitizer_set_death_callback_fn() {
            eprintln!("Setting death callback");
            unsafe {
                set_death_callback(death_callback);
            }
        }

        thread::spawn(move || {
            for sig in signals.forever() {
                // death_callback();
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
    eprintln!("Death callback called");
    let crashes_dir: &Path = CRASHES_DIR.get().expect("CRASHES_DIR not initialized");
    let extension: Option<&String> = INPUTS_EXTENSION.get();
    let extension = extension.map(|e| e.as_ref());

    if let Some(last_input) = LAST_INPUT.get().unwrap().lock().unwrap().take() {
        handle_crash(crashes_dir.as_ref(), extension, last_input.as_slice());
    }

    std::process::abort();
}
