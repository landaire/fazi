//! Drives `fazi::embed` with a target that is a tiny interpreted program, the
//! way an emulator would: the host code is not instrumented, the interpreter
//! reports branch coverage through a counter array and comparisons through
//! the comparison API.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU8, Ordering},
};

use fazi::embed::{self, CmpOperand, SessionError, SessionOptions};

#[derive(Clone, Copy)]
enum Op {
    /// `reg = big-endian u32 at input[offset..]`; halts (pass) if the input
    /// is too short
    Load { offset: usize },
    /// Compares `reg` with `imm`
    CmpImm { imm: u32 },
    /// Jumps to `target` if the last comparison was not equal
    Bne { target: usize },
    /// The input is a failure
    Fail,
    /// The input passes
    Halt,
}

const MAGIC: [u32; 3] = [0xDEAD_BEEF, 0x1337_C0DE, 0xCAFE_F00D];

/// Fails only when the input starts with the three magic words.
const PROGRAM: [Op; 11] = [
    Op::Load { offset: 0 },
    Op::CmpImm { imm: MAGIC[0] },
    Op::Bne { target: 10 },
    Op::Load { offset: 4 },
    Op::CmpImm { imm: MAGIC[1] },
    Op::Bne { target: 10 },
    Op::Load { offset: 8 },
    Op::CmpImm { imm: MAGIC[2] },
    Op::Bne { target: 10 },
    Op::Fail,
    Op::Halt,
];

/// Two counters (taken / not taken, or short / long input) per instruction.
static COUNTERS: [AtomicU8; 2 * PROGRAM.len()] = [const { AtomicU8::new(0) }; 2 * PROGRAM.len()];

/// Comparison sites are reported as features too; keep them clear of the
/// counter features.
const CMP_SITE_BASE: u64 = 0x1000;

fn interpret(program: &[Op], input: &[u8], report_cmps: bool) -> bool {
    let bump = |pc: usize, edge: usize| {
        COUNTERS[2 * pc + edge].fetch_add(1, Ordering::Relaxed);
    };

    let (mut pc, mut reg, mut equal) = (0, 0u32, false);
    loop {
        match program[pc] {
            Op::Load { offset } => {
                let Some(bytes) = input.get(offset..offset + 4) else {
                    bump(pc, 0);
                    return false;
                };
                bump(pc, 1);
                reg = u32::from_be_bytes(bytes.try_into().unwrap());
            }
            Op::CmpImm { imm } => {
                if report_cmps {
                    embed::record_cmp4(CMP_SITE_BASE + pc as u64, CmpOperand::Dynamic(reg), CmpOperand::Constant(imm));
                }
                equal = reg == imm;
            }
            Op::Bne { target } => {
                bump(pc, usize::from(!equal));
                if !equal {
                    pc = target;
                    continue;
                }
            }
            Op::Fail => return true,
            Op::Halt => return false,
        }
        pc += 1;
    }
}

fn magic_input() -> Vec<u8> {
    MAGIC.iter().flat_map(|word| word.to_be_bytes()).collect()
}

fn options(seed: u64, max_iterations: u64) -> SessionOptions {
    SessionOptions {
        seed,
        max_input_len: 16,
        len_control: 0,
        max_iterations: Some(max_iterations),
        counters: Some(&COUNTERS),
        ..SessionOptions::default()
    }
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fazi-embed-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn comparison_feedback_finds_magic_words() {
    let stats = embed::run(SessionOptions { stop_on_failure: true, ..options(1, 20_000) }, |input| {
        interpret(&PROGRAM, input, true)
    })
    .unwrap();

    assert_eq!(stats.failures.len(), 1, "{stats:?}");
    assert!(stats.failures[0].starts_with(&magic_input()), "{stats:?}");
    assert!(stats.iterations < 20_000);
    // Both branch edges of every stage plus the comparison sites
    assert!(stats.coverage >= 10, "{stats:?}");
    assert!(stats.corpus_len >= 4, "{stats:?}");
}

#[test]
fn without_comparison_feedback_magic_words_stay_hidden() {
    let stats = embed::run(options(1, 20_000), |input| interpret(&PROGRAM, input, false)).unwrap();

    assert!(stats.failures.is_empty(), "{stats:?}");
    assert_eq!(stats.iterations, 20_000);
}

#[test]
fn sessions_are_deterministic_and_reset_between_runs() {
    let first = embed::run(options(7, 3_000), |input| interpret(&PROGRAM, input, true)).unwrap();

    // A different session in between must not leak coverage, corpus or
    // comparison operands into the next one.
    let other = embed::run(options(99, 500), |input| {
        embed::record_feature(0xFFFF_0000 + input.len() as u64);
        interpret(&PROGRAM, input, true)
    })
    .unwrap();
    assert_ne!(first, other);

    let second = embed::run(options(7, 3_000), |input| interpret(&PROGRAM, input, true)).unwrap();
    assert_eq!(first, second);
}

#[test]
fn failures_are_saved_and_corpus_is_reused() {
    let corpus_dir = scratch_dir("corpus");
    let crashes_dir = scratch_dir("crashes");
    let dirs = |seed| SessionOptions {
        corpus_dir: Some(corpus_dir.clone()),
        crashes_dir: Some(crashes_dir.clone()),
        stop_on_failure: true,
        ..options(seed, 20_000)
    };

    let first = embed::run(dirs(3), |input| interpret(&PROGRAM, input, true)).unwrap();
    assert_eq!(first.failures.len(), 1, "{first:?}");

    let crashes: Vec<_> = std::fs::read_dir(&crashes_dir).unwrap().collect();
    assert_eq!(crashes.len(), 1);
    let crash = crashes[0].as_ref().unwrap();
    assert!(crash.file_name().to_string_lossy().starts_with("crash-"));
    assert_eq!(std::fs::read(crash.path()).unwrap(), first.failures[0]);
    assert!(std::fs::read_dir(&corpus_dir).unwrap().count() >= first.corpus_len);

    // The saved corpus already reaches the last stage, so a new session
    // starting from it needs far fewer inputs.
    let second = embed::run(dirs(4), |input| interpret(&PROGRAM, input, true)).unwrap();
    assert_eq!(second.failures.len(), 1, "{second:?}");
    assert!(second.iterations < first.iterations, "{first:?} {second:?}");

    std::fs::remove_dir_all(&corpus_dir).unwrap();
    std::fs::remove_dir_all(&crashes_dir).unwrap();
}

#[test]
fn seeds_run_first_and_failures_do_not_stop_by_default() {
    let mut seen = Vec::new();
    let stats = embed::run(SessionOptions { seeds: vec![magic_input(), vec![0; 12]], ..options(5, 200) }, |input| {
        seen.push(input.to_vec());
        interpret(&PROGRAM, input, true)
    })
    .unwrap();

    assert_eq!(seen[..2], [vec![0; 12], magic_input()]);
    assert_eq!(stats.iterations, 200);
    assert_eq!(stats.failures[0], magic_input());
}

#[test]
fn invalid_sessions_are_rejected() {
    assert!(matches!(embed::run(SessionOptions::default(), |_| false), Err(SessionError::Unbounded)));
    assert!(matches!(
        embed::run(SessionOptions { max_input_len: 0, ..options(0, 1) }, |_| false),
        Err(SessionError::ZeroMaxInputLen)
    ));

    let mut nested = None;
    embed::run(options(0, 1), |_| {
        nested = Some(embed::run(options(0, 1), |_| false));
        false
    })
    .unwrap();
    assert!(matches!(nested, Some(Err(SessionError::Nested))));
}

#[test]
fn panicking_target_leaves_fazi_usable() {
    let result = std::panic::catch_unwind(|| {
        embed::run(options(0, 10), |input| {
            interpret(&PROGRAM, input, true);
            panic!("target bug")
        })
    });
    assert!(result.is_err());

    let stats = embed::run(options(7, 3_000), |input| interpret(&PROGRAM, input, true)).unwrap();
    let fresh = embed::run(options(7, 3_000), |input| interpret(&PROGRAM, input, true)).unwrap();
    assert_eq!(stats, fresh);
}
