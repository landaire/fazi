use std::sync::Arc;

use once_cell::sync::OnceCell;
#[cfg(feature = "protobuf")]
use protobuf::{CodedOutputStream, Message};
use rand::Rng;

use crate::{Fazi, Mutable};
#[cfg(feature = "protobuf")]
impl<R: Rng> Fazi<R> {
    pub(crate) fn mutate_protobuf_input(&mut self) -> bool {
        if let Some(callback) = self.protobuf_mutate_callback.as_ref() {
            let input = Arc::clone(&self.input);
            let result = callback(input.as_slice(), self);
            self.input = Arc::new(result);
            true
        } else {
            false
        }
    }
}
