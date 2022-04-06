use std::sync::Arc;

use rand::{
    prelude::{IteratorRandom, SliceRandom},
    Rng,
};

use crate::{driver::CONSTANTS, Fazi};

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
    pub(crate) fn extend_input(&mut self) -> MutationStrategy {
        self.insert_bytes(true)
            .expect("could not extend input");

        MutationStrategy::InsertBytes
    }

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
            std::cmp::min(self.max_input_size as usize, 128)
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

    fn insert_dictionary_value(&mut self) -> MutationResult {
        if let Some((&offset, &value)) = self.dictionary.u8dict.iter().choose(&mut self.rng) {
            let offset = if self.input.len() > offset && self.rng.gen() {
                offset
            } else {
                self.rng.gen_range(0..self.input.len())
            };

            let insert_byte = self.rng.gen();
            let input = self.input_mut();
            if insert_byte {
                input.insert(offset, value);
            } else {
                input[offset] = value;
            }

            Ok(())
        } else {
            return Err(());
        }
    }

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

        let mut index = self.rng.gen_range(0..self.input.len());

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

        choice = IntegerWidth::U8;

        macro_rules! change_int {
            ($ty:ty, $next_choice:expr) => {
                let bit_width = std::mem::size_of::<$ty>();
                if self.input.len() < bit_width {
                    choice = IntegerWidth::U8;
                    continue;
                }

                let add: $ty = self.rng.gen_range(0..21);
                let add = add.wrapping_sub(10);

                // The selected index doesn't have enough bytes left for us
                // to manipulate. We need to adjust the index
                let remaining_bytes = self.input.len() - index;
                if remaining_bytes < bit_width {
                    index -= bit_width - remaining_bytes;
                }

                // Treat this as a different endian from the host endian
                let input = Arc::make_mut(&mut self.input);
                let input_range = &mut input[index..index + bit_width];
                let is_different_endianness = self.rng.gen();
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

                if add == 0 {
                    // negate this number
                    input_as_int = (!input_as_int).wrapping_add(1);
                } else {
                    input_as_int = input_as_int.wrapping_add(add);
                }

                let new_bytes = if is_different_endianness {
                    input_as_int.to_be_bytes()
                } else {
                    input_as_int.to_le_bytes()
                };

                for (i, &new_byte) in new_bytes.iter().enumerate() {
                    input_range[i] = new_byte;
                }
            };
        }
        let mut constants = CONSTANTS
            .get()
            .expect("failed to get CONSTANTS")
            .lock()
            .expect("failed to lock CONSTANTS");
        loop {
            match choice {
                IntegerWidth::U8 => {
                    if constants.u8cov.is_empty() {
                        // We don't have any constants to use
                        return Err(());
                    }

                    // Select a random pair
                    let cmp_pair = constants
                        .u8cov
                        .iter()
                        .filter(|c| c.0.is_dynamic() || c.1.is_dynamic())
                        .choose(&mut self.rng)
                        .expect("u8cov empty?");

                    // Randomly select an index from the input to start our search
                    // at.
                    let start_idx = self.rng.gen_range(0..self.input.len());
                    let (start, end) = self.input.split_at(start_idx);
                    if let Some(idx) = end.iter().chain(start.iter()).position(|&b| {
                        // We need to select a "dynamic" value since const
                        // values would have been hardcoded into the target
                        b == if cmp_pair.0.is_dynamic() {
                            cmp_pair.0.inner()
                        } else {
                            cmp_pair.1.inner()
                        }
                    }) {
                        //if let Some(idx) = self.input.iter().position(|&b| b == cmp_pair.0 || b == cmp_pair.1) {
                        let input = self.input_mut();
                        let const_value = if cmp_pair.0.is_const() {
                            cmp_pair.0.inner()
                        } else {
                            cmp_pair.1.inner()
                        };

                        input[idx] = const_value;

                        self.dictionary.u8dict.insert(index, const_value);

                        let cmp_pair = cmp_pair.clone();
                        constants.u8cov.remove(&cmp_pair);

                        return Ok(());
                    } else {
                        return Err(());
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

    fn copy_part(&mut self) -> MutationResult {
        if self.input.is_empty() {
            return Err(());
        }

        let copy_from = self.rng.gen_range(0..self.input.len());
        let mut copy_len = self.rng.gen_range(1..=(self.input.len() - copy_from));
        let copy_to = self.rng.gen_range(0..=self.input.len());

        if self.input.len() + copy_len > self.current_max_mutation_len {
            let delta = self
                .current_max_mutation_len
                .saturating_sub(self.input.len());
            if delta == 0 {
                return Err(());
            }

            copy_len = delta;
        }

        let original_input = Arc::clone(&self.input);
        let data_to_copy = &original_input[copy_from..(copy_from + copy_len)];
        let input = self.input_mut();
        for &byte in data_to_copy.iter().rev() {
            input.insert(copy_to, byte);
        }

        Ok(())
    }

    fn cross_over(&mut self) -> MutationResult {
        Ok(())
    }

    fn input_mut(&mut self) -> &mut Vec<u8> {
        Arc::make_mut(&mut self.input)
    }
}
