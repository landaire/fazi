use std::{
    sync::Arc,
};

use rand::{
    prelude::{IteratorRandom, SliceRandom},
    Rng,
};

use crate::{driver::COMPARISON_OPERANDS, Fazi};

type MutationResult = Result<(), ()>;

/// Represents a mutation strategy to take. Any newly added variants must also
/// be added to the vector in the [`MutationStrategy::random`] function
#[derive(Debug, Copy, Clone)]
pub(crate) enum MutationStrategy {
    /// Erase random bytes
    EraseBytes,
    /// Insert a random byte
    InsertByte,
    /// Insert a random byte N times
    InsertBytes,
    /// Change a single byte
    ChangeByte,
    /// Change a single bit
    ChangeBit,
    /// Shuffle some bytes of the input
    ShuffleBytes,
    /// Find an ASCII integer in the input and change it
    ChangeAsciiInt,
    /// Cast a byte range as an integer type and change it
    ChangeBinInt,
    /// Copy part of some data to another location
    CopyPart,
    /// TODO: ????
    CrossOver,
    InsertDictionaryValue,
    UseCmpValue,
}

impl MutationStrategy {
    /// Selects a mutation strategy
    pub fn random(rng: &mut impl Rng) -> MutationStrategy {
        enum MutationGroup {
            ChangeData,
            ModifySize,
            Any,
        }
        let _mutation_group = if rng.gen_bool(0.90) {
            MutationGroup::ChangeData
        } else if rng.gen() {
            MutationGroup::ModifySize
        } else {
            MutationGroup::Any
        };

        let change_data_group = [
            MutationStrategy::ChangeByte,
            MutationStrategy::ChangeBit,
            MutationStrategy::UseCmpValue,
            MutationStrategy::ShuffleBytes,
            MutationStrategy::ChangeAsciiInt,
            MutationStrategy::ChangeBinInt,
        ];
        let modify_size_group = [
            MutationStrategy::EraseBytes,
            MutationStrategy::InsertByte,
            MutationStrategy::InsertBytes,
            MutationStrategy::InsertDictionaryValue,
            MutationStrategy::CopyPart,
        ];
        // Missing:
        // MutationStrategy::CrossOver,

        let mutation_group = MutationGroup::Any;
        match mutation_group {
            MutationGroup::ChangeData => change_data_group.as_slice().choose(rng).unwrap().clone(),
            MutationGroup::ModifySize => modify_size_group.as_slice().choose(rng).unwrap().clone(),
            MutationGroup::Any => modify_size_group
                .iter()
                .chain(change_data_group.iter())
                .choose(rng)
                .unwrap()
                .clone(),
        }
    }

    /// Selects a mutation strategy that cannot fail if the input has at least
    /// 1 byte
    pub fn random_nonfailing_strategy(rng: &mut impl Rng) -> MutationStrategy {
        let options = [
            MutationStrategy::InsertByte,
            MutationStrategy::InsertBytes,
            MutationStrategy::ChangeByte,
            MutationStrategy::ChangeBit,
            MutationStrategy::ShuffleBytes,
            MutationStrategy::ChangeBinInt,
            // MutationStrategy::CopyPart,
            // MutationStrategy::CrossOver,
        ];

        options
            .as_slice()
            .choose(rng)
            .expect("mutation options are empty?")
            .clone()
    }
}

impl<R: Rng> Fazi<R> {
    /// Selects a strategy that will extend the input
    pub(crate) fn extend_input(&mut self) -> MutationStrategy {
        self.insert_bytes(true).expect("could not extend input");

        MutationStrategy::InsertBytes
    }

    /// Perform a random mutation strategy on the current input
    pub(crate) fn mutate_input(&mut self) -> MutationStrategy {
        let mut mutation_strategy = MutationStrategy::random(&mut self.rng);

        // println!("before: {:x?}", self.input);
        loop {
            let mutation_result = match mutation_strategy {
                MutationStrategy::EraseBytes => self.erase_bytes(),
                MutationStrategy::InsertByte => self.insert_byte(),
                MutationStrategy::InsertBytes => self.insert_bytes(false),
                MutationStrategy::ChangeByte => self.change_byte(),
                MutationStrategy::ChangeBit => self.change_bit(),
                MutationStrategy::ShuffleBytes => self.shuffle_bytes(),
                MutationStrategy::ChangeAsciiInt => self.change_ascii_int(),
                MutationStrategy::ChangeBinInt => self.change_bin_int(),
                MutationStrategy::CopyPart => self.copy_part(),
                MutationStrategy::CrossOver => self.cross_over(),
                MutationStrategy::InsertDictionaryValue => self.insert_dictionary_value(),
                MutationStrategy::UseCmpValue => self.use_value_from_cmp_instruction(),
            };

            if mutation_result.is_ok() {
                // println!("Selected mutation strategy: {:?}", mutation_strategy);
                break;
            }

            // We need to loop again and select a different mutation strategy
            // if the previously selected strategy can't work on the provided
            // input
            mutation_strategy = if self.input.is_empty() {
                MutationStrategy::InsertByte
            } else {
                MutationStrategy::random_nonfailing_strategy(&mut self.rng)
            };
        }
        // println!("after: {:x?}", self.input);

        mutation_strategy
    }

    /// Select a random index and length to remove input bytes from
    fn erase_bytes(&mut self) -> MutationResult {
        // We don't have enough data to perform this mutation
        if self.input.is_empty() {
            return Err(());
        }

        let start_index: usize = self.rng.gen_range(0..self.input.len());
        let mut end_index: usize = self.rng.gen_range(start_index..self.input.len());
        if self.input.len() - (end_index - start_index) < self.min_input_size.unwrap_or(0) {
            // the selected range would make this testcase smaller than our minimum size.
            end_index = start_index + (self.input.len() - self.min_input_size.unwrap());
        }

        if end_index - start_index == 0 {
            return Err(());
        }

        let input = self.input_mut();
        let draining_it = input.drain(start_index..end_index);
        // Drop the iterator right away so that the elements are removed
        drop(draining_it);

        // We need to copy to a new vector to ensure that ASAN detects out-of-bounds
        // accesses
        let mut new_vec = Vec::with_capacity(input.len());
        new_vec.extend(input.iter());

        *self.input_mut() = new_vec;

        Ok(())
    }

    /// Inserts a single random byte in the input
    fn insert_byte(&mut self) -> MutationResult {
        if self.input.len() == self.current_max_mutation_len {
            return Err(());
        }

        let index: usize = self.rng.gen_range(0..=self.input.len());
        let byte = self.rng.gen();

        let input = self.input_mut();

        if index == input.len() {
            input.push(byte);
        } else {
            input.insert(index, byte);
        }

        Ok(())
    }

    /// Inserts multiple random bytes in the input. These bytes may be
    /// repeated or all random.
    fn insert_bytes(&mut self, ignore_max: bool) -> MutationResult {
        if !ignore_max && self.input.len() == self.current_max_mutation_len {
            return Err(());
        }

        let index: usize = if self.input.is_empty() {
            0
        } else {
            self.rng.gen_range(0..=self.input.len())
        };

        let max_count = if ignore_max {
            std::cmp::max(4, self.max_input_size)
        } else {
            std::cmp::min(self.max_input_size, 128)
        };

        let count: usize = self.rng.gen_range(2..max_count);

        let byte_iter: Box<dyn Iterator<Item = u8>> = if self.rng.gen() {
            Box::new(std::iter::repeat(self.rng.gen()).take(count))
        } else {
            Box::new(std::iter::from_fn(|| self.rng.gen()).take(count))
        };

        let input = Arc::make_mut(&mut self.input);

        // Reserve the number of bytes necessary
        input.reserve(count);

        if index == input.len() {
            input.extend(byte_iter);
        } else {
            // TODO: optimize. could use a repeating iterator here probably
            for byte in byte_iter {
                input.insert(index, byte);
            }
        }

        Ok(())
    }

    /// Grabs a dictionary entry and applies it to the current input.
    fn insert_dictionary_value(&mut self) -> MutationResult {
        #[derive(Clone)]
        enum IntegerWidth {
            U8,
            U16,
            U32,
            U64,
        }

        // We loop until we find an integer width that fits the size of the input
        let choices = [
            IntegerWidth::U8,
            IntegerWidth::U16,
            IntegerWidth::U32,
            IntegerWidth::U64,
        ];
        let mut choice = choices
            .as_slice()
            .choose(&mut self.rng)
            .expect("empty choices?")
            .clone();
        macro_rules! insert_dict {
            ($ty:ty, $dictmap:ident, $next_choice:expr) => {
                if let Some((&offset, &value)) =
                    self.dictionary.$dictmap.iter().choose(&mut self.rng)
                {
                    let input_len = self.input.len();
                    let ty_size = std::mem::size_of::<$ty>();
                    let is_big_endian_input = self.rng.gen();
                    let offset = if self.input.len() > offset && self.rng.gen() {
                        offset
                    } else {
                        self.rng.gen_range(0..self.input.len())
                    };

                    let insert_byte = self.rng.gen();
                    let input = self.input_mut();
                    let new_value = if is_big_endian_input {
                        value.to_be_bytes()
                    } else {
                        value.to_le_bytes()
                    };

                    if insert_byte || offset + ty_size > input_len {
                        for &b in new_value.iter().rev() {
                            input.insert(offset, b);
                        }
                    } else {
                        input[offset..offset + ty_size].copy_from_slice(new_value.as_slice());
                    }

                    return Ok(());
                } else {
                    if let Some(next) = $next_choice {
                        choice = next;
                        continue;
                    } else {
                        return Err(());
                    }
                }
            };
        }
        loop {
            match choice {
                IntegerWidth::U8 => insert_dict!(u8, u8dict, None),
                IntegerWidth::U16 => insert_dict!(u16, u16dict, Some(IntegerWidth::U8)),
                IntegerWidth::U32 => insert_dict!(u32, u32dict, Some(IntegerWidth::U16)),
                IntegerWidth::U64 => insert_dict!(u64, u64dict, Some(IntegerWidth::U32)),
            }
        }
    }

    /// Selects a random byte index and sets it to a random byte>
    fn change_byte(&mut self) -> MutationResult {
        if self.input.is_empty() {
            return Err(());
        }

        let index: usize = self.rng.gen_range(0..self.input.len());
        let byte = self.rng.gen();

        let input = self.input_mut();
        input[index] = byte;

        Ok(())
    }

    /// Toggles a random bit in the input
    fn change_bit(&mut self) -> MutationResult {
        if self.input.is_empty() {
            return Err(());
        }

        let byte_index: usize = self.rng.gen_range(0..self.input.len());
        let bit_index: usize = self.rng.gen_range(0..8);

        let input = self.input_mut();
        input[byte_index] = input[byte_index] ^ (1 << bit_index);

        Ok(())
    }

    /// Selects a byte range from the current input and shuffles the
    /// bytes around.
    fn shuffle_bytes(&mut self) -> MutationResult {
        // We need at least 2 bytes to shuffle
        if self.input.len() <= 1 {
            return Err(());
        }

        let index: usize = self.rng.gen_range(0..self.input.len());
        let max_count = std::cmp::min(self.input.len() - index, 8);
        let count: usize = self.rng.gen_range(0..=max_count);

        let input = Arc::make_mut(&mut self.input);
        let byte_range = &mut input[index..index + count];

        byte_range.shuffle(&mut self.rng);

        Ok(())
    }

    /// Tries to find an ASCII int in the current input and changes it to a
    /// different ASCII int.
    fn change_ascii_int(&mut self) -> MutationResult {
        if self.input.is_empty() {
            return Err(());
        }

        // Find an ASCII int
        if let Some(position) = self
            .input
            .iter()
            .position(|&byte| byte >= b'0' && byte <= b'9')
        {
            let new_int = self.rng.gen_range(b'0'..=b'9');
            let input = self.input_mut();
            input[position] = new_int;
        } else {
            // There's no ASCII in the input
            return Err(());
        }

        Ok(())
    }

    /// Uses a value from the [`COMPARISON_OPERANDS`] generated via SanCov
    /// instrumentation and attempts to:
    /// 1. Find the position of the non-const operand in the current input
    /// 2. If a position is found, insert a new dictionary entry with that
    /// position's index and comparison operand
    /// 3. Replace the integer at that offset with the comparison operand. The
    /// integer width is either 64, 32, 16, or 8 bits depending on how large
    /// the comparison operands were.
    fn use_value_from_cmp_instruction(&mut self) -> MutationResult {
        if self.input.is_empty() {
            return Err(());
        }

        #[derive(Clone)]
        enum IntegerWidth {
            U8,
            U16,
            U32,
            U64,
        }

        // We loop until we find an integer width that fits the size of the input
        let choices = [
            IntegerWidth::U8,
            IntegerWidth::U16,
            IntegerWidth::U32,
            IntegerWidth::U64,
        ];
        let mut choice = choices
            .as_slice()
            .choose(&mut self.rng)
            .expect("empty choices?")
            .clone();

        let mut constants = COMPARISON_OPERANDS
            .get()
            .expect("failed to get CONSTANTS")
            .lock()
            .expect("failed to lock CONSTANTS");

        macro_rules! change_int {
            ($ty:ty, $covmap:ident, $dictmap:ident, $next_choice:expr) => {
                let ty_size = std::mem::size_of::<$ty>();
                if constants.$covmap.is_empty() {
                    if let Some(next_choice) = $next_choice {
                        choice = next_choice;
                        continue;
                    } else {
                        // We don't have any constants to use
                        return Err(());
                    }
                }

                // Select a random pair
                let cmp_pair = constants
                    .$covmap
                    .iter()
                    .filter(|c| c.0.is_dynamic() || c.1.is_dynamic())
                    .choose(&mut self.rng)
                    .expect("u8cov empty?");

                let is_big_endian_input = self.rng.gen();
                // Randomly select an index from the input to start our search
                // at.
                let index_sampler =
                    rand::seq::index::sample(&mut self.rng, self.input.len(), self.input.len())
                        .into_iter();
                let mut found_index = None;
                let cmp_target = if cmp_pair.0.is_dynamic() {
                    cmp_pair.0.inner()
                } else {
                    cmp_pair.1.inner()
                };

                for idx in index_sampler {
                    if self.input.len() - idx < ty_size {
                        continue;
                    }

                    let value = if is_big_endian_input {
                        <$ty>::from_be_bytes(
                            self.input[idx..idx + ty_size]
                                .try_into()
                                .expect("failed to convert byte window to array"),
                        )
                    } else {
                        <$ty>::from_le_bytes(
                            self.input[idx..idx + ty_size]
                                .try_into()
                                .expect("failed to convert byte window to array"),
                        )
                    };

                    if value == cmp_target {
                        found_index = Some(idx);
                        break;
                    }
                }
                if let Some(idx) = found_index {
                    let input = self.input_mut();
                    let const_value = if cmp_pair.0.is_const() {
                        cmp_pair.0.inner()
                    } else {
                        cmp_pair.1.inner()
                    };

                    let new_value = if is_big_endian_input {
                        const_value.to_be_bytes()
                    } else {
                        const_value.to_le_bytes()
                    };

                    input[idx..idx + ty_size].copy_from_slice(new_value.as_slice());

                    self.dictionary.$dictmap.insert(idx, const_value);

                    let cmp_pair = cmp_pair.clone();
                    constants.$covmap.remove(&cmp_pair);

                    return Ok(());
                } else {
                    if let Some(next_choice) = $next_choice {
                        choice = next_choice;
                        continue;
                    } else {
                        return Err(());
                    }
                }
            };
        }
        loop {
            match choice {
                IntegerWidth::U8 => {
                    change_int!(u8, u8cov, u8dict, None);
                }
                IntegerWidth::U16 => {
                    change_int!(u16, u16cov, u16dict, Some(IntegerWidth::U8));
                }
                IntegerWidth::U32 => {
                    change_int!(u32, u32cov, u32dict, Some(IntegerWidth::U16));
                }
                IntegerWidth::U64 => {
                    change_int!(u64, u64cov, u64dict, Some(IntegerWidth::U32));
                }
            }
        }
    }

    /// Selects a random integer size, selects a random integer index, and
    /// generates a new integer of the appropriate width.
    fn change_bin_int(&mut self) -> MutationResult {
        if self.input.is_empty() {
            return Err(());
        }

        #[derive(Clone)]
        enum IntegerWidth {
            U8,
            U16,
            U32,
            U64,
        }

        #[derive(Clone)]
        enum SubStrategy {
            InterestingNumber,
            Add,
            Replace,
        }

        let mut index = self.rng.gen_range(0..self.input.len());

        // We loop until we find an integer width that fits the size of the input
        let integer_width_choices = [
            IntegerWidth::U8,
            IntegerWidth::U16,
            IntegerWidth::U32,
            IntegerWidth::U64,
        ];
        let mut integer_width_choice = integer_width_choices
            .as_slice()
            .choose(&mut self.rng)
            .expect("empty choices?")
            .clone();

        let sub_strategy_choices = [
            SubStrategy::InterestingNumber,
            SubStrategy::Add,
            SubStrategy::Replace,
        ];

        let sub_strategy_choice = sub_strategy_choices
            .as_slice()
            .choose(&mut self.rng)
            .expect("empty choices?")
            .clone();

        macro_rules! change_int {
            ($ty:ty, $next_choice:expr) => {
                const BIT_WIDTH: usize = std::mem::size_of::<$ty>();
                if self.input.len() < BIT_WIDTH {
                    integer_width_choice = IntegerWidth::U8;
                    continue;
                }

                // The selected index doesn't have enough bytes left for us
                // to manipulate. We need to adjust the index backwards
                let remaining_bytes = self.input.len() - index;
                if remaining_bytes < BIT_WIDTH {
                    index -= BIT_WIDTH - remaining_bytes;
                }

                // Treat this as a different endian from the host endian
                let input = Arc::make_mut(&mut self.input);
                let input_range = &mut input[index..index + BIT_WIDTH];
                let is_different_endianness = self.rng.gen();

                let mut new_bytes = [0u8; BIT_WIDTH];

                match sub_strategy_choice {
                    SubStrategy::InterestingNumber => crate::dictionary::rand_interesting_number(
                        &mut self.rng,
                        BIT_WIDTH,
                        new_bytes.as_mut_slice(),
                    ),
                    SubStrategy::Add => {
                        let mut input_as_int = if is_different_endianness {
                            <$ty>::from_be_bytes(
                                input_range
                                    .try_into()
                                    .expect("failed to convert input slice to an array"),
                            )
                        } else {
                            <$ty>::from_le_bytes(
                                input_range
                                    .try_into()
                                    .expect("failed to convert input slice to an array"),
                            )
                        };
                        let add: $ty = self.rng.gen_range(0..10);
                        if add == 0 {
                            // negate this number
                            input_as_int = (!input_as_int).wrapping_add(1);
                        } else {
                            input_as_int = input_as_int.wrapping_add(add);
                        }

                        new_bytes.copy_from_slice(input_as_int.to_ne_bytes().as_slice());
                    }
                    SubStrategy::Replace => {
                        new_bytes = self.rng.gen();
                    }
                }

                if is_different_endianness {
                    new_bytes.reverse()
                } else {
                    new_bytes.reverse()
                }

                input_range.copy_from_slice(new_bytes.as_slice());
            };
        }
        loop {
            match integer_width_choice {
                IntegerWidth::U8 => {
                    let add: u8 = self.rng.gen_range(0..10);
                    let input = self.input_mut();
                    if add == 0 {
                        input[index] = (!input[index]).wrapping_add(1);
                    } else {
                        input[index] = input[index].wrapping_add(add);
                    }
                }
                IntegerWidth::U16 => {
                    change_int!(u16, IntegerWidth::U8);
                }
                IntegerWidth::U32 => {
                    change_int!(u16, IntegerWidth::U16);
                }
                IntegerWidth::U64 => {
                    change_int!(u16, IntegerWidth::U32);
                }
            }

            break;
        }

        Ok(())
    }

    /// Copy part of the input to another position in the current input.
    fn copy_part(&mut self) -> MutationResult {
        let original_input = self.input.clone();
        let new_input = Arc::make_mut(&mut self.input);
        copy_helper(
            &original_input,
            new_input,
            &mut self.rng,
            self.current_max_mutation_len,
        )
    }

    /// Copy part of a different input into this one.
    fn cross_over(&mut self) -> MutationResult {
        if self.corpus.len() < 2 {
            return Err(());
        }

        let target_input = Arc::make_mut(&mut self.input);
        let original_input = self
            .corpus
            .choose(&mut self.rng)
            .expect("could not choose item from corpus");

        copy_helper(
            &original_input,
            target_input,
            &mut self.rng,
            self.current_max_mutation_len,
        )
    }

    /// Get a mutable reference to the current input. This may perform a clone
    /// operation depending on how many references to the input exist. In most
    /// cases, this would result in a clone *if* the input has already been used
    /// in a test run that resulted in more coverage since we add it to a global
    /// list of inputs. However, if that's not the case and there's only the single
    /// reference on the [`Fazi`] instance, then this will return a mutable
    /// reference to the underlying data as it's safe to do so.
    fn input_mut(&mut self) -> &mut Vec<u8> {
        Arc::make_mut(&mut self.input)
    }
}

/// Helper function for [`copy_part()`] and [`cross_over()`].
fn copy_helper(
    original: &[u8],
    target: &mut Vec<u8>,
    rng: &mut impl Rng,
    max_mutation_len: usize,
) -> MutationResult {
    if original.is_empty() {
        return Err(());
    }

    let copy_from = rng.gen_range(0..original.len());
    let mut copy_len = rng.gen_range(1..=(original.len() - copy_from));
    let copy_to = rng.gen_range(0..=target.len());

    if target.len() + copy_len > max_mutation_len {
        let delta = max_mutation_len.saturating_sub(target.len());
        if delta == 0 {
            return Err(());
        }

        copy_len = delta;
    }

    let data_to_copy = &original[copy_from..(copy_from + copy_len)];
    for &byte in data_to_copy.iter().rev() {
        target.insert(copy_to, byte);
    }

    Ok(())
}
