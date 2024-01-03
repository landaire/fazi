use std::fmt::Debug;


#[cfg(feature = "protobuf")]
use protobuf::EnumOrUnknown;

use rand::prelude::{SliceRandom};
use rand::Rng;

use crate::driver::COMPARISON_OPERANDS;
use crate::Fazi;
use paste::paste;

pub trait Mutable {
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>);
}

fn generate_char<R: Rng>(rng: &mut R) -> char {
    #[derive(Clone)]
    enum CharMode {
        Ascii,
        RandLowerSection,
        ProgrammingLanguage,
        TrickyUnicode,
        TrickyUnicode2,
        Random,
    }

    let choices = [
        CharMode::Ascii,
        CharMode::RandLowerSection,
        CharMode::ProgrammingLanguage,
        CharMode::TrickyUnicode,
        CharMode::TrickyUnicode2,
        CharMode::Random,
    ];
    let choice = choices
        .as_slice()
        .choose(rng)
        .expect("empty choices?")
        .clone();

    match choice {
        CharMode::Ascii => rng.gen_range(0..=0x7F) as u8 as char,
        CharMode::RandLowerSection => {
            loop {
                if let Some(c) = char::from_u32(rng.gen_range(0..0x10000)) {
                    return c;
                }

                // keep looping if we got an invalid char. this will
                // ignore surrogate pairs
            }
        }
        CharMode::ProgrammingLanguage => {
            // Characters often used in programming languages
            let c = [
                ' ', ' ', ' ', '\t', '\n', '~', '`', '!', '@', '#', '$', '%', '^', '&', '*', '(',
                ')', '_', '-', '=', '+', '[', ']', '{', '}', ':', ';', '\'', '"', '\\', '|', ',',
                '<', '>', '.', '/', '?', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            ]
            .choose(rng)
            .unwrap()
            .to_owned();

            c
        }
        CharMode::TrickyUnicode => {
            // Tricky Unicode, part 1
            let c = [
                '\u{0149}', // a deprecated character
                '\u{fff0}', // some of "Other, format" category:
                '\u{fff1}',
                '\u{fff2}',
                '\u{fff3}',
                '\u{fff4}',
                '\u{fff5}',
                '\u{fff6}',
                '\u{fff7}',
                '\u{fff8}',
                '\u{fff9}',
                '\u{fffA}',
                '\u{fffB}',
                '\u{fffC}',
                '\u{fffD}',
                '\u{fffE}',
                '\u{fffF}',
                '\u{0600}',
                '\u{0601}',
                '\u{0602}',
                '\u{0603}',
                '\u{0604}',
                '\u{0605}',
                '\u{061C}',
                '\u{06DD}',
                '\u{070F}',
                '\u{180E}',
                '\u{110BD}',
                '\u{1D173}',
                '\u{e0001}', // tag
                '\u{e0020}', //  tag space
                '\u{e000}',
                '\u{e001}',
                '\u{ef8ff}', // private use
                '\u{f0000}',
                '\u{ffffd}',
                '\u{ffffe}',
                '\u{fffff}',
                '\u{100000}',
                '\u{10FFFD}',
                '\u{10FFFE}',
                '\u{10FFFF}',
                // "Other, surrogate" characters are so that very special
                // that they are not even allowed in safe Rust,
                //so omitted here
                '\u{3000}', // ideographic space
                '\u{1680}',
                // other space characters are already covered by two next
                // branches
            ]
            .choose(rng)
            .unwrap()
            .to_owned();

            c
        }
        CharMode::TrickyUnicode2 => {
            // Tricky unicode, part 2
            char::from_u32(rng.gen_range(0x2000..0x2070)).unwrap()
        }
        CharMode::Random => {
            // Completely arbitrary characters
            rng.gen()
        }
    }
}

impl Mutable for char {
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        let guard = fazi.before_mutate(true);
        if guard.is_none() {
            return;
        }

        // chars need to be treated with char -- in rust they're guaranteed to be
        // a utf-8 char, so we MUST generate something in the valid UTF-8 range.
        let mut value_u32 = *self as u32;
        value_u32.mutate(fazi);

        // If we mutated to a value that's not a valid utf8-char, we just generate
        // a new char
        if let Some(c) = char::from_u32(value_u32) {
            *self = c;
        } else {
            *self = generate_char(&mut fazi.rng);
        }
    }
}

impl Mutable for String {
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        let guard = fazi.before_mutate(true);
        if guard.is_none() {
            return;
        }

        // Maybe shuffle the string
        if fazi.rng.gen_bool(0.5) {
            let mut chars: Vec<char> = self.chars().collect();
            chars.shuffle(&mut fazi.rng);

            *self = chars.into_iter().collect();
            return;
        }

        // Give a low chance to append a new char
        if self.is_empty() || fazi.rng.gen_bool(0.10) {
            let count = fazi.rng.gen_range(1..=10);
            for _ in 0..count {
                self.push(generate_char(&mut fazi.rng));
            }
            return;
        }

        if !self.is_empty() {
            // Give a low chance to remove an item
            if fazi.rng.gen_bool(0.10) {
                let mut chars: Vec<char> = self.chars().collect();
                chars.remove(fazi.rng.gen_range(0..chars.len()));

                *self = chars.into_iter().collect();
            } else {
                let mut chars: Vec<char> = self.chars().collect();

                // Randomly sample indexes to iterate over
                let count = fazi.rng.gen_range(0..=chars.len());
                let index_sampler =
                    rand::seq::index::sample(&mut fazi.rng, chars.len(), count).into_iter();

                // Change these items in-place
                for idx in index_sampler {
                    chars[idx] = generate_char(&mut fazi.rng);
                }
            }
        }
    }
}

impl<T> Mutable for Vec<T>
where
    T: Mutable + Default + Debug,
{
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        let guard = fazi.before_mutate(true);
        if guard.is_none() {
            return;
        }

        // Maybe shuffle the elements?
        if fazi.rng.gen_bool(0.5) {
            self.shuffle(&mut fazi.rng);
            return;
        }

        // Give a low chance to append a new element
        if self.is_empty() || fazi.rng.gen_bool(0.10) {
            let count = fazi.rng.gen_range(1..=10);
            for _ in 0..count {
                let mut new_item = T::default();
                new_item.mutate(fazi);

                self.push(new_item);
            }
            return;
        }

        if !self.is_empty() {
            // Give a low chance to remove an item
            if fazi.rng.gen_bool(0.10) {
                self.remove(fazi.rng.gen_range(0..self.len()));
            } else {
                // Randomly sample indexes to iterate over
                let count = fazi.rng.gen_range(0..=self.len());
                let index_sampler =
                    rand::seq::index::sample(&mut fazi.rng, self.len(), count).into_iter();
                // Iterate these items in-place
                for idx in index_sampler {
                    self[idx].mutate(fazi);
                }
            }
        }
    }
}

impl<T> Mutable for Option<T>
where
    T: Mutable + Default + Debug, // default here ensures that Options of Vecs can work
{
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        match self {
            Some(value) => {
                if fazi.rng.gen_bool(0.10) {
                    *self = None;
                } else {
                    value.mutate(fazi);
                }
            }
            None => {
                if fazi.rng.gen::<bool>() {
                    let mut new_value = T::default();
                    new_value.mutate(fazi);
                    *self = Some(new_value)
                }
            }
        }
    }
}

impl Mutable for bool {
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        let guard = fazi.before_mutate(true);
        if guard.is_none() {
            return;
        }
        *self = fazi.rng.gen();
    }
}

impl Mutable for i8 {
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        let guard = fazi.before_mutate(true);
        if guard.is_none() {
            return;
        }
        *self = fazi.u8(*self as u8) as i8;
    }
}

impl Mutable for i16 {
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        let guard = fazi.before_mutate(true);
        if guard.is_none() {
            return;
        }
        *self = fazi.u16(*self as u16) as i16;
    }
}

impl Mutable for i32 {
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        let guard = fazi.before_mutate(true);
        if guard.is_none() {
            return;
        }
        *self = fazi.u32(*self as u32) as i32;
    }
}

impl Mutable for i64 {
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        let guard = fazi.before_mutate(true);
        if guard.is_none() {
            return;
        }

        *self = fazi.u64(*self as u64) as i64;
    }
}

impl Mutable for f32 {
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        let guard = fazi.before_mutate(true);
        if guard.is_none() {
            return;
        }

        *self = fazi.u32(*self as u32) as f32;
    }
}

impl Mutable for f64 {
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        let guard = fazi.before_mutate(true);
        if guard.is_none() {
            return;
        }

        *self = fazi.u64(*self as u64) as f64;
    }
}

macro_rules! impl_mutate {
    ( $($name:ident),* ) => {
        $(
            impl Mutable for $name {
                #[inline(always)]
                fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
                    let guard = fazi.before_mutate(true);
                    if guard.is_none() {
                        return;
                    }

                    *self = fazi.$name(*self);
                }
            }
        )*
    }
}

impl_mutate!(u64, u32, u16, u8);

macro_rules! mutate_fn {
    ($($ty:ident),*) => {
        $(
        paste! {
        fn $ty(&mut self, previous_value: $ty) -> $ty {
            let constants = COMPARISON_OPERANDS
                .get()
                .expect("failed to get CONSTANTS")
                .lock()
                .expect("failed to lock CONSTANTS");

            let use_const_dynamic_pair = self.rng.gen_bool(0.90);

            // Try to find a match in the coverage map that correlates the current
            // value to something we compared
            let potential_match = constants
                .[<$ty cov>]
                .iter()
                .filter(|c| {
                    if use_const_dynamic_pair {
                        (c.0.is_dynamic() && c.1.is_const()) || (c.0.is_const() && c.1.is_dynamic())
                    } else {
                        c.0.is_dynamic() || c.1.is_dynamic()
                    }
                })
                .find_map(|c| {
                    // We want to compare against the non-const value. If the non-const value is equal to what this
                    // field was previously set to, we want to change it to be the other item in the pair (the const value
                    // or dynamically calcluated value)
                    if c.0.is_dynamic() {
                        if c.0.inner() == previous_value {
                            return Some(c.1.inner());
                        }
                    } else if c.1.inner() == previous_value {
                            return Some(c.0.inner());
                    }

                    None
                });

            let target_value = match potential_match {
                    Some(value) => {
                        value
                    }
                    None => {
                        return self.rng.gen();
                    }
                };

            let is_big_endian_input = self.rng.gen();

            let new_value = if is_big_endian_input {
                // swap endianness
                $ty::from_le_bytes(target_value.to_be_bytes())
            } else {
                target_value
            };

            return new_value;
        }
        })*
    };
}

#[cfg(feature = "protobuf")]
impl<E> Mutable for protobuf::EnumOrUnknown<E>
where
    E: Mutable + protobuf::Enum,
{
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        match self.enum_value() {
            Ok(mut value) => {
                value.mutate(fazi);
                *self = EnumOrUnknown::new(value);
            }
            Err(_) => {
                let mut value = self.value();
                value.mutate(fazi);

                *self = EnumOrUnknown::from_i32(value);
            }
        }
    }
}

#[cfg(feature = "protobuf")]
impl<T> Mutable for protobuf::MessageField<T>
where
    T: Mutable + Default + Debug,
{
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        self.0.mutate(fazi);
    }
}

impl<T> Mutable for Box<T>
where
    T: Mutable + Default + Debug,
{
    #[inline(always)]
    fn mutate<R: Rng>(&mut self, fazi: &mut Fazi<R>) {
        self.as_mut().mutate(fazi);
    }
}

impl<R: Rng> Fazi<R> {
    mutate_fn!(u8, u16, u32, u64);

    #[cfg(feature = "protobuf")]
    #[inline(always)]
    pub fn choose_enum<T>(&mut self, mut primitive_value: i32, choices: &[T]) -> T
    where
        T: protobuf::Enum,
    {
        primitive_value.mutate(self);

        match T::from_i32(primitive_value) {
            Some(new) => new,
            None => *choices.choose(&mut self.rng).expect("choices are empty?"),
        }
    }
}
