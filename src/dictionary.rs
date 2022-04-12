use std::collections::BTreeMap;

use rand::{prelude::SliceRandom, Rng};

#[derive(Debug, Default)]
pub(crate) struct Dictionary {
    pub u8dict: BTreeMap<usize, u8>,
    pub u16dict: BTreeMap<usize, u16>,
    pub u32dict: BTreeMap<usize, u32>,
    pub u64dict: BTreeMap<usize, u64>,
}

#[derive(Debug)]
pub(crate) enum DictionaryEntry {
    U8(usize, u8),
    U16(usize, u16),
    U32(usize, u32),
    U64(usize, u64),
}

static INTERESTING_NUMBERS_U8: &'static [u8] = &[
    std::u8::MIN,
    std::u8::MAX,
    std::i8::MAX as u8,
    (std::i8::MAX as u8) + 1,
];

static INTERESTING_NUMBERS_U16: &'static [u16] = &[
    std::u16::MIN,
    std::u16::MAX,
    std::i16::MAX as u16,
    (std::i16::MAX as u16) + 1,
];

static INTERESTING_NUMBERS_U32: &'static [u32] = &[
    std::u32::MIN,
    std::u32::MAX,
    std::i32::MAX as u32,
    (std::i32::MAX as u32) + 1,
];

static INTERESTING_NUMBERS_U64: &'static [u64] = &[
    std::u64::MIN,
    std::u64::MAX,
    std::i64::MAX as u64,
    (std::i64::MAX as u64) + 1,
];

static INTERESTING_NUMBERS_F32: &'static [f32] = &[
    std::f32::INFINITY,
    std::f32::MAX,
    std::f32::MIN,
    std::f32::MIN_POSITIVE,
    std::f32::NAN,
    std::f32::NEG_INFINITY,
];

static INTERESTING_NUMBERS_F64: &'static [f64] = &[
    std::f64::INFINITY,
    std::f64::MAX,
    std::f64::MIN,
    std::f64::MIN_POSITIVE,
    std::f64::NAN,
    std::f64::NEG_INFINITY,
];

pub(crate) fn rand_interesting_number(rng: &mut impl Rng, width: usize, output: &mut [u8]) {
    match width {
        1 => {
            output.copy_from_slice(
                INTERESTING_NUMBERS_U8
                    .choose(rng)
                    .unwrap()
                    .to_ne_bytes()
                    .as_slice(),
            );
        }
        2 => output.copy_from_slice(
            INTERESTING_NUMBERS_U16
                .choose(rng)
                .unwrap()
                .to_ne_bytes()
                .as_slice(),
        ),
        4 => {
            let bytes = if rng.gen() {
                INTERESTING_NUMBERS_U32.choose(rng).unwrap().to_ne_bytes()
            } else {
                INTERESTING_NUMBERS_F32.choose(rng).unwrap().to_ne_bytes()
            };
            output.copy_from_slice(bytes.as_slice());
        }
        8 => {
            let bytes = if rng.gen() {
                INTERESTING_NUMBERS_U64.choose(rng).unwrap().to_ne_bytes()
            } else {
                INTERESTING_NUMBERS_F64.choose(rng).unwrap().to_ne_bytes()
            };
            output.copy_from_slice(bytes.as_slice());
        }
        _ => panic!("unexpected interesting number width: {}", width),
    };
}
