use fazi::{Fazi, FaziBuilder};
use rand::prelude::StdRng;

fn main() {
    FaziBuilder::<StdRng>::default()
        .handle_panics() // Ensure that we treat panics as crashes
        .handle_signals() // Ensure that we catch certain system signals that should be treated as crashes
        .do_recoverage() // Rerun existing inputs before fuzzing
        .do_fuzzing() // Run the fuzzer after doing recoverage
        .harness(&buggy_function) // Our target function
        .run();
}

fn buggy_function(input: &[u8]) {
    if input.len() >= 5
        && input[0] == b'h'
        && input[1] == b'e'
        && input[2] == b'l'
        && input[3] == b'l'
        && input[4] == b'o'
    {
        panic!("fuzzer has succeded at finding our bug");
    }
}
