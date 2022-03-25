use std::{path::{PathBuf, Path}, thread};

use libc::{SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGINT, SIGSEGV};
use rand::Rng;
use sha1::{Digest, Sha1};
use signal_hook::iterator::Signals;

use crate::{Fazi, driver::LAST_INPUT};

impl<R: Rng> Fazi<R> {
    pub(crate) fn setup_signal_handler(&self) {
        let mut signals = Signals::new(&[SIGABRT]).expect("failed to setup signal handler");

        let crashes_dir = self.options.crashes_dir.clone();
        let corpus_dir = self.options.corpus_dir.clone();
        thread::spawn(move || {
            for sig in signals.forever() {
                if sig == SIGABRT {
                let last_input = LAST_INPUT.get().expect("LAST_INPUT not initialized").lock().expect("could not lock LAST_INPUT");
                    handle_crash(crashes_dir.as_ref(), last_input.as_slice());
                    save_input(corpus_dir.as_ref(), last_input.as_slice());
                }
            }
        });
    }
}

pub(crate) fn handle_crash(crashes_dir: &Path, input: &[u8]) {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    let filename = hex::encode(result.as_slice());
    let crash_file_path = crashes_dir.join(&filename);

    eprintln!("Received SIGABRT -- saving crash to {:?}", crash_file_path);
    ensure_parent_dir_exists(crash_file_path.as_ref());

    std::fs::write(crash_file_path, input).expect("failed to save crash file!");
}

pub(crate) fn save_input(corpus_dir: &Path, input: &[u8]) {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    let filename = hex::encode(result.as_slice());
    let corpus_file_path = corpus_dir.join(&filename);

    eprintln!("Saving corpus input to {:?}", corpus_file_path);
    ensure_parent_dir_exists(corpus_file_path.as_ref());

    std::fs::write(corpus_file_path, input).expect("failed to save corpus input file!");
}

fn ensure_parent_dir_exists(path: &Path) {
    let parent = path.parent().expect("path has no parent directory?");
    if !parent.exists() {
        std::fs::create_dir_all(parent).expect("failed to create_dir_all on parent directory");
    }
}