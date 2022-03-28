#![feature(linkage)]
#![feature(once_cell)]
#![feature(link_llvm_intrinsics)]

use std::{collections::{BTreeSet, BTreeMap}, fs, path::Path, sync::Arc};

use crate::options::RuntimeOptions;
use crate::weak::weak;
use clap::StructOpt;
use mutations::MutationStrategy;
use rand::{distributions::Standard, prelude::*, SeedableRng};

mod coverage;
mod driver;
mod mutations;
mod options;
mod signal;
mod weak;
pub mod exports;

// extern "C" {
//     #[linkage = "weak"]
//     fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> std::os::raw::c_int;
// }

#[derive(Debug, Default)]
pub(crate) struct Dictionary {
    u8dict: BTreeMap<usize, u8>,
    u16dict: BTreeMap<usize, u16>,
    u32dict: BTreeMap<usize, u32>,
    u64dict: BTreeMap<usize, u64>,
}

#[derive(Debug)]
pub struct Fazi<R: Rng> {
    rng: R,
    input: Arc<Vec<u8>>,
    dictionary: Dictionary,
    corpus: Vec<Arc<Vec<u8>>>,
    options: RuntimeOptions,
    iterations: usize,
    min_input_size: Option<usize>,
    recoverage_queue: Vec<Arc<Vec<u8>>>,
    current_mutation_depth: usize,
    mutations: Vec<MutationStrategy>,
    max_input_size: usize,
    current_max_mutation_len: usize,
    last_corpus_update_run: usize,
}

impl Default for Fazi<StdRng> {
    fn default() -> Self {
        Fazi {
            rng: StdRng::from_entropy(),
            input: Default::default(),
            dictionary: Default::default(),
            corpus: Default::default(),
            options: Default::default(),
            iterations: 0,
            min_input_size: None,
            recoverage_queue: Default::default(),
            current_mutation_depth: 0,
            mutations: Default::default(),
            max_input_size: 4,
            last_corpus_update_run: 0,
            current_max_mutation_len: 0,
        }
    }
}

impl<R: Rng + SeedableRng> Fazi<R> {
    pub fn new() -> Self {
        Fazi {
            rng: R::from_entropy(),
            input: Default::default(),
            dictionary: Default::default(),
            corpus: Default::default(),
            options: Default::default(),
            iterations: 0,
            min_input_size: None,
            recoverage_queue: Default::default(),
            current_mutation_depth: 0,
            mutations: Default::default(),
            max_input_size: 4,
            last_corpus_update_run: 0,
            current_max_mutation_len: 0,
        }
    }

    pub fn new_from_seed(seed: R::Seed) -> Self {
        Fazi {
            rng: R::from_seed(seed),
            input: Default::default(),
            dictionary: Default::default(),
            corpus: Default::default(),
            options: Default::default(),
            iterations: 0,
            min_input_size: None,
            recoverage_queue: Default::default(),
            current_mutation_depth: 0,
            mutations: Default::default(),
            max_input_size: 4,
            last_corpus_update_run: 0,
            current_max_mutation_len: 0,
        }
    }

    pub fn options_from_os_args(&mut self) {
        self.options = RuntimeOptions::parse();
    }

    pub fn restore_inputs(&mut self) {
        let input_paths: [&Path; 1] = [self.options.corpus_dir.as_ref()];
        for &path in &input_paths {
            if !path.exists() || !path.is_dir() {
                continue;
            }

            for dirent in fs::read_dir(path).expect("failed to read input directory") {
                if let Ok(dirent) = dirent {
                    let input_file_path = dirent.path();
                    if input_file_path.is_dir() {
                        continue;
                    }

                    self.corpus.push(Arc::new(
                        fs::read(input_file_path).expect("failed to read input file"),
                    ));
                }
            }
        }

        self.recoverage_queue = self.corpus.clone();
    }
}

pub(crate) fn libfuzzer_runone_fn() -> unsafe extern "C" fn(*const u8, usize) -> std::os::raw::c_int
{
    weak!(fn LLVMFuzzerTestOneInput(*const u8, usize) -> std::os::raw::c_int);

    LLVMFuzzerTestOneInput
        .get()
        .expect("failed to get LLVMFuzzerTestOneInput")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let mut fazi = Fazi::default();
        for i in 0..30 {
            fazi.mutate_input();
            println!("{:?}", fazi.input);
        }
    }
}
