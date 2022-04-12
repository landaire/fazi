use std::env;

use fazi::{FaziBuilder};
use rand::prelude::StdRng;

fn main() {
    let fazi = FaziBuilder::<StdRng>::default()
        .handle_signals() // Ensure that we catch certain system signals that should be treated as crashes
        .do_recoverage() // Rerun existing inputs before fuzzing
        .do_fuzzing() // Run the fuzzer after doing recoverage
        .harness(&buggy_function) // Our target function
        ;
    let handle_panics = if let Some(env_var_value) = env::var_os("FAZI_PANIC_HANDLER") {
        env_var_value != "off"
    } else {
        true
    };
    if handle_panics {
        fazi.handle_panics()
    } else {
        fazi
    }
    .run();
}

#[inline(never)]
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
