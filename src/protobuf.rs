use std::sync::Arc;

#[cfg(feature = "protobuf")]
use protobuf::Message;
use rand::Rng;

use crate::Fazi;
#[cfg(feature = "structured_fuzzing")]
impl<R: Rng> Fazi<R> {
    pub(crate) fn mutate_structured_fuzzing_input(&mut self) -> bool {
        if let Some(callback) = self.structured_fuzzing_mutate_callback.as_ref() {
            let input = Arc::clone(&self.input);
            let result = callback(input.as_slice(), self);
            self.input = Arc::new(result);
            true
        } else {
            false
        }
    }
}
