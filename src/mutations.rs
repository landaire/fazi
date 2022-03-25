use rand::{prelude::{SliceRandom, IteratorRandom}, Rng};

use crate::{Fazi, driver::CONSTANTS};

type MutationResult = Result<(), ()>;

/// Represents a mutation strategy to take. Any newly added variants must also
/// be added to the vector in the [`MutationStrategy::random`] function
#[derive(Debug, Copy, Clone)]
enum MutationStrategy {
    /// Erase random bytes
    EraseBytes,
    /// Insert a random byte
    InsertByte,
    /// Insert a random byte N times
    InsertRepeatedBytes,
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
}

impl MutationStrategy {
    /// Selects a mutation strategy
    pub fn random(rng: &mut impl Rng) -> MutationStrategy {
        let options = [
            MutationStrategy::EraseBytes,
            MutationStrategy::InsertByte,
            MutationStrategy::InsertRepeatedBytes,
            MutationStrategy::ChangeByte,
            MutationStrategy::ChangeBit,
            MutationStrategy::ShuffleBytes,
            MutationStrategy::ChangeAsciiInt,
            MutationStrategy::ChangeBinInt,
            MutationStrategy::CopyPart,
            MutationStrategy::CrossOver,
        ];

        options
            .as_slice()
            .choose(rng)
            .expect("mutation options are empty?")
            .clone()
    }

    /// Selects a mutation strategy that cannot fail if the input has at least
    /// 1 byte
    pub fn random_nonfailing_strategy(rng: &mut impl Rng) -> MutationStrategy {
        let options = [
            MutationStrategy::InsertByte,
            MutationStrategy::InsertRepeatedBytes,
            MutationStrategy::ChangeByte,
            MutationStrategy::ChangeBit,
            MutationStrategy::ShuffleBytes,
            MutationStrategy::ChangeBinInt,
            MutationStrategy::CopyPart,
            MutationStrategy::CrossOver,
        ];

        options
            .as_slice()
            .choose(rng)
            .expect("mutation options are empty?")
            .clone()
    }
}

impl<R: Rng> Fazi<R> {
    pub fn mutate_input(&mut self) {
        let mut mutation_strategy = MutationStrategy::random(&mut self.rng);

        loop {
            let mutation_result = match mutation_strategy {
                MutationStrategy::EraseBytes => self.erase_bytes(),
                MutationStrategy::InsertByte => self.insert_byte(),
                MutationStrategy::InsertRepeatedBytes => self.insert_repeated_bytes(),
                MutationStrategy::ChangeByte => self.change_byte(),
                MutationStrategy::ChangeBit => self.change_bit(),
                MutationStrategy::ShuffleBytes => self.shuffle_bytes(),
                MutationStrategy::ChangeAsciiInt => self.change_ascii_int(),
                MutationStrategy::ChangeBinInt => self.change_bin_int(),
                MutationStrategy::CopyPart => self.copy_part(),
                MutationStrategy::CrossOver => self.cross_over(),
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
    }

    fn erase_bytes(&mut self) -> MutationResult {
        // We don't have enough data to perform this mutation
        if self.input.is_empty() {
            return Err(());
        }

        let start_index: usize = self.rng.gen_range(0..self.input.len());
        let end_index: usize = self.rng.gen_range(start_index..self.input.len());

        let draining_it = self.input.drain(start_index..end_index);
        // Drop the iterator right away so that the elements are removed
        drop(draining_it);

        // We need to copy to a new vector to ensure that ASAN detects out-of-bounds
        // accesses
        let mut new_vec = Vec::with_capacity(self.input.len());
        new_vec.extend(self.input.iter());

        self.input = new_vec;

        Ok(())
    }

    fn insert_byte(&mut self) -> MutationResult {
        let index: usize = self.rng.gen_range(0..=self.input.len());
        let mut byte = None;
        if self.rng.gen_bool(0.30) {
            let constants = CONSTANTS.get().expect("CONSTANTS not initialized").lock().expect("failed to lock CONSTANTS");
            if !constants.u8cov.is_empty() {
                byte = Some(constants.u8cov.iter().choose(&mut self.rng).expect("empty u8 constants").clone());
            }
        }

        let byte = if byte.is_none() {
            self.rng.gen()
        } else {
            byte.unwrap()
        };

        self.input.reserve_exact(1);
        if index == self.input.len() {
            self.input.push(byte);
        } else {
            self.input.insert(index, byte);
        }

        Ok(())
    }

    fn insert_repeated_bytes(&mut self) -> MutationResult {
        let index: usize = if self.input.is_empty() {
            0
        } else {
            self.rng.gen_range(0..=self.input.len())
        };

        let count: usize = self.rng.gen_range(1..128);
        let mut byte = None;
        if self.rng.gen_bool(0.30) {
            let constants = CONSTANTS.get().expect("CONSTANTS not initialized").lock().expect("failed to lock CONSTANTS");
            if !constants.u8cov.is_empty() {
                byte = Some(constants.u8cov.iter().choose(&mut self.rng).expect("empty u8 constants").clone());
            }
        }

        let byte = if byte.is_none() {
            self.rng.gen()
        } else {
            byte.unwrap()
        };

        // Reserve the number of bytes necessary
        self.input.reserve_exact(count);

        if index == self.input.len() {
            self.input.extend(std::iter::repeat(byte).take(count));
        } else {
            // TODO: optimize. could use a repeating iterator here probably
            for _ in 0..count {
                self.input.insert(index, byte);
            }
        }

        Ok(())
    }

    fn change_byte(&mut self) -> MutationResult {
        if self.input.is_empty() {
            return Err(());
        }

        let index: usize = self.rng.gen_range(0..self.input.len());
        let mut byte = None;

        if self.rng.gen_bool(0.30) {
            let constants = CONSTANTS.get().expect("CONSTANTS not initialized").lock().expect("failed to lock CONSTANTS");
            if !constants.u8cov.is_empty() {
                byte = Some(constants.u8cov.iter().choose(&mut self.rng).expect("empty u8 constants").clone());
            }
        }

        let byte = if byte.is_none() {
            self.rng.gen()
        } else {
            byte.unwrap()
        };

        self.input[index] = byte;

        Ok(())
    }

    fn change_bit(&mut self) -> MutationResult {
        if self.input.is_empty() {
            return Err(());
        }

        let byte_index: usize = self.rng.gen_range(0..self.input.len());
        let bit_index: usize = self.rng.gen_range(0..8);

        self.input[byte_index] = self.input[byte_index] ^ (1 << bit_index);

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
        let byte_range = &mut self.input[index..index + count];

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
            self.input[position] = new_int;
        } else {
            // There's no ASCII in the input
            return Err(());
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
                let input_range = &mut self.input[index..index + bit_width];
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
        loop {
            match choice {
                IntegerWidth::U8 => {
                    let add: u8 = self.rng.gen_range(0..21);
                    let add = add.wrapping_sub(10);
                    if add == 0 {
                        self.input[index] = (!self.input[index]).wrapping_add(1);
                    } else {
                        self.input[index] = self.input[index].wrapping_add(add);
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
        Ok(())
    }

    fn cross_over(&mut self) -> MutationResult {
        Ok(())
    }
}
