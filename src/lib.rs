#![feature(once_cell)]

use std::collections::BTreeSet;

use rand::{distributions::Standard, prelude::*, SeedableRng};

mod coverage;
mod mutations;
mod driver;
mod weak;

// extern "C" {
//     #[linkage = "weak"]
//     fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> std::os::raw::c_int;
// }

#[derive(Debug)]
pub struct Fazi<R: Rng> {
    rng: R,
    input: Vec<u8>,
    dictionary: Vec<Vec<u8>>,
}

impl Default for Fazi<StdRng> {
    fn default() -> Self {
        Fazi {
            rng: StdRng::from_entropy(),
            input: vec![],
            dictionary: vec![],
        }
    }
}

impl<R: Rng + SeedableRng> Fazi<R> {
    pub fn new() -> Self {
        Fazi {
            rng: R::from_entropy(),
            input: vec![],
            dictionary: vec![],
        }
    }

    pub fn new_from_seed(seed: R::Seed) -> Self {
        Fazi {
            rng: R::from_seed(seed),
            input: vec![],
            dictionary: vec![],
        }
    }
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
