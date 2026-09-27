use std::sync::Arc;

#[cfg(feature = "protobuf")]
use protobuf::Message;
use rand::Rng;

use crate::Fazi;
#[cfg(feature = "structured_fuzzing")]
impl<R: Rng> Fazi<R> {
    /// Returns true when the callback produced a structured mutation. A false
    /// return (no callback, or the callback declined) leaves the input
    /// untouched so the caller can fall back to byte mutations.
    pub(crate) fn mutate_structured_fuzzing_input(&mut self) -> bool {
        if let Some(callback) = self.structured_fuzzing_mutate_callback.as_ref() {
            let input = Arc::clone(&self.input);
            match callback(input.as_slice(), self) {
                Ok(result) => {
                    self.input = Arc::new(result);
                    true
                }
                Err(()) => false,
            }
        } else {
            false
        }
    }
}
