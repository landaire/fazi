/// Main mutation logic
pub(crate) mod mutations;
/// Mutator API for third-parties to do structured or smart fuzzing based on the
/// current input
pub(crate) mod mutator;

pub(crate) use self::mutations::*;
pub(crate) use self::mutator::*;
