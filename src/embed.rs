//! Fuzzing targets whose execution the host does not instrument, such as code
//! running in an emulator or interpreter.
//!
//! The embedder reports what the target did while it ran an input:
//!
//! - coverage, by bumping a counter array registered through
//!   [`SessionOptions::counters`] and/or by calling [`record_feature`];
//! - comparisons, by calling [`record_cmp1`], [`record_cmp2`], [`record_cmp4`]
//!   or [`record_cmp8`] with the operands the target compared.
//!
//! [`run`] drives a bounded fuzzing session: it calls the target closure once
//! per input, keeps inputs that reach new coverage in the corpus and feeds the
//! recorded comparison operands to the compare-operand mutator and the
//! dictionary, exactly like the SanitizerCoverage callbacks do for
//! instrumented host code.
//!
//! Coverage features are plain `u64` ids in one space: counter `i` of the
//! registered array is feature `i`, [`record_feature`] reports the id it is
//! given, and every comparison also reports its `site` id as a feature. Keep
//! the ranges disjoint if they should be told apart.
//!
//! The coverage and comparison tables are process globals. Sessions in one
//! process run one at a time (concurrent [`run`] calls wait for each other)
//! and each session starts from empty tables, so sessions can run back to back.
//! Recording calls are ignored while no session is running and may come from
//! any thread while one is. Host code compiled with SanitizerCoverage
//! instrumentation (`sancov` feature) also contributes coverage if present.

use std::{
    cell::Cell,
    collections::{BTreeMap, HashSet},
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    time::{Duration, Instant},
};

pub use crate::cmp::CmpOperand;
use crate::{
    driver::{artifact_path, update_coverage, COMPARISON_OPERANDS, COVERAGE, TESTCASE_COVERAGE},
    fazi::{init_shared_state, rng_from_seed},
    options::RuntimeOptions,
    Fazi, Input,
};

/// Held by the running session; sessions share the global tables.
static SESSION_LOCK: Mutex<()> = Mutex::new(());
/// Whether a session is running. Recording calls are dropped otherwise.
static SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Counter array of the running session.
static COUNTERS: Mutex<Option<&'static [AtomicU8]>> = Mutex::new(None);

thread_local! {
    /// Whether this thread is inside [`run`], to reject nested sessions
    /// instead of deadlocking on [`SESSION_LOCK`].
    static IN_SESSION: Cell<bool> = const { Cell::new(false) };
}

/// Configuration of one bounded session. At least one of
/// [`max_iterations`](Self::max_iterations) and [`max_time`](Self::max_time)
/// must be set.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// RNG seed. The same seed and the same target behaviour produce the same
    /// sequence of inputs.
    pub seed: u64,
    /// Inputs are truncated to this many bytes before they run. Must not be 0.
    pub max_input_len: usize,
    /// How quickly inputs may grow towards `max_input_len`: the current limit
    /// grows after about `len_control * log2(limit)` iterations without new
    /// coverage. 0 allows `max_input_len` from the start.
    pub len_control: u32,
    /// Number of mutations stacked on one input before fazi moves on to
    /// another corpus entry.
    pub max_mutation_depth: usize,
    /// Stop after the target has run this many times (seed inputs included).
    pub max_iterations: Option<u64>,
    /// Stop once this much wall time has passed. Checked between inputs.
    pub max_time: Option<Duration>,
    /// Directory whose files seed the session. Inputs that join the corpus
    /// during the session are written to it as `input-<sha1>`. Created if
    /// missing.
    pub corpus_dir: Option<PathBuf>,
    /// Directory failing inputs are written to as `crash-<sha1>`. Created if
    /// missing.
    pub crashes_dir: Option<PathBuf>,
    /// Inputs to run before fuzzing, in addition to the files of `corpus_dir`.
    pub seeds: Vec<Vec<u8>>,
    /// Coverage counters the target bumps (any non-zero value marks counter
    /// `i` as feature `i`). Fazi zeroes them before every input.
    pub counters: Option<&'static [AtomicU8]>,
    /// End the session at the first failing input.
    pub stop_on_failure: bool,
}

impl Default for SessionOptions {
    fn default() -> Self {
        let defaults = RuntimeOptions::default();
        Self {
            seed: 0,
            max_input_len: defaults.max_input_len,
            len_control: defaults.len_control,
            max_mutation_depth: defaults.max_mutation_depth,
            max_iterations: None,
            max_time: None,
            corpus_dir: None,
            crashes_dir: None,
            seeds: Vec::new(),
            counters: None,
            stop_on_failure: false,
        }
    }
}

/// Result of a finished session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Number of times the target ran (seed inputs included).
    pub iterations: u64,
    /// Inputs in the corpus at the end of the session.
    pub corpus_len: usize,
    /// Distinct coverage features observed during the session.
    pub coverage: usize,
    /// Distinct failing inputs, in the order they were found.
    pub failures: Vec<Vec<u8>>,
}

/// Why [`run`] could not run a session.
#[derive(Debug)]
pub enum SessionError {
    /// Neither `max_iterations` nor `max_time` was set.
    Unbounded,
    /// `max_input_len` was 0.
    ZeroMaxInputLen,
    /// [`run`] was called from inside a running session on the same thread.
    Nested,
    /// Reading or writing the corpus or crashes directory failed.
    Io { path: PathBuf, source: io::Error },
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Unbounded => write!(f, "session has neither an iteration nor a time budget"),
            SessionError::ZeroMaxInputLen => write!(f, "max_input_len must not be 0"),
            SessionError::Nested => write!(f, "a session is already running on this thread"),
            SessionError::Io { path, source } => write!(f, "{}: {}", path.display(), source),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SessionError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Records coverage feature `feature` for the running input. Truncated to
/// `usize` on 32-bit hosts.
pub fn record_feature(feature: u64) {
    if !SESSION_ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    if let Some(coverage) = TESTCASE_COVERAGE.get() {
        lock(coverage).insert(feature as usize);
    }
}

/// Records a 1-byte comparison at `site`. `site` is also recorded as a
/// coverage feature.
pub fn record_cmp1(site: u64, arg1: CmpOperand<u8>, arg2: CmpOperand<u8>) {
    record_cmp(site, 1, arg1.map(u64::from), arg2.map(u64::from));
}

/// Records a 2-byte comparison at `site`. `site` is also recorded as a
/// coverage feature.
pub fn record_cmp2(site: u64, arg1: CmpOperand<u16>, arg2: CmpOperand<u16>) {
    record_cmp(site, 2, arg1.map(u64::from), arg2.map(u64::from));
}

/// Records a 4-byte comparison at `site`. `site` is also recorded as a
/// coverage feature.
pub fn record_cmp4(site: u64, arg1: CmpOperand<u32>, arg2: CmpOperand<u32>) {
    record_cmp(site, 4, arg1.map(u64::from), arg2.map(u64::from));
}

/// Records an 8-byte comparison at `site`. `site` is also recorded as a
/// coverage feature.
pub fn record_cmp8(site: u64, arg1: CmpOperand<u64>, arg2: CmpOperand<u64>) {
    record_cmp(site, 8, arg1, arg2);
}

fn record_cmp(site: u64, width: usize, arg1: CmpOperand<u64>, arg2: CmpOperand<u64>) {
    if !SESSION_ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    if let Some(operands) = COMPARISON_OPERANDS.get() {
        lock(operands).insert(width, arg1, arg2);
    }
    record_feature(site);
}

/// Counter array of the running session, read when coverage is collected.
pub(crate) fn registered_counters() -> Option<&'static [AtomicU8]> {
    *lock(&COUNTERS)
}

/// Runs a bounded fuzzing session against `target`, which returns `true` when
/// the input it was given is a failure.
///
/// Seed inputs (`seeds` and the files of `corpus_dir`, shortest first) run
/// first; those that produce any coverage form the initial corpus. Fuzzing
/// then mutates corpus entries until the iteration or time budget is spent,
/// or until the first failure with `stop_on_failure`. Failing inputs are
/// collected (and written to `crashes_dir`); the session continues past them
/// unless `stop_on_failure` is set.
///
/// A panic in `target` propagates to the caller and leaves fazi ready for the
/// next session.
pub fn run<F>(options: SessionOptions, mut target: F) -> Result<SessionStats, SessionError>
where
    F: FnMut(&[u8]) -> bool,
{
    if options.max_iterations.is_none() && options.max_time.is_none() {
        return Err(SessionError::Unbounded);
    }
    if options.max_input_len == 0 {
        return Err(SessionError::ZeroMaxInputLen);
    }
    if IN_SESSION.with(Cell::get) {
        return Err(SessionError::Nested);
    }

    let _lock = SESSION_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let _active = ActiveSession::start(options.counters);

    run_session(options, &mut target)
}

/// Marks a session as running and resets the global tables; dropping it
/// (also during unwinding) ends the session.
struct ActiveSession;

impl ActiveSession {
    fn start(counters: Option<&'static [AtomicU8]>) -> Self {
        init_shared_state();
        reset_tables();
        if let Some(counters) = counters {
            for counter in counters {
                counter.store(0, Ordering::Relaxed);
            }
        }
        *lock(&COUNTERS) = counters;
        IN_SESSION.with(|in_session| in_session.set(true));
        SESSION_ACTIVE.store(true, Ordering::Release);

        ActiveSession
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        SESSION_ACTIVE.store(false, Ordering::Release);
        IN_SESSION.with(|in_session| in_session.set(false));
        *lock(&COUNTERS) = None;
        reset_tables();
    }
}

/// Empties the coverage and comparison tables and clears poisoning left by a
/// panicking thread.
fn reset_tables() {
    if let Some(coverage) = COVERAGE.get() {
        coverage.clear_poison();
        lock(coverage).clear();
    }
    if let Some(coverage) = TESTCASE_COVERAGE.get() {
        coverage.clear_poison();
        lock(coverage).clear();
    }
    if let Some(operands) = COMPARISON_OPERANDS.get() {
        operands.clear_poison();
        lock(operands).clear();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Target invocation and budget bookkeeping of a session.
struct Executor<'a> {
    target: &'a mut dyn FnMut(&[u8]) -> bool,
    max_iterations: Option<u64>,
    deadline: Option<Instant>,
    crashes_dir: Option<&'a Path>,
    stop_on_failure: bool,
    iterations: u64,
    stopped: bool,
    failures: Vec<Vec<u8>>,
    seen_failures: HashSet<Vec<u8>>,
}

impl Executor<'_> {
    fn budget_left(&self) -> bool {
        !self.stopped
            && self.max_iterations.is_none_or(|max| self.iterations < max)
            && self.deadline.is_none_or(|deadline| Instant::now() < deadline)
    }

    fn execute(&mut self, input: &[u8]) -> Result<(), SessionError> {
        let failed = (self.target)(input);
        self.iterations += 1;

        if failed {
            if self.seen_failures.insert(input.to_vec()) {
                if let Some(dir) = self.crashes_dir {
                    write_artifact(dir, "crash", input)?;
                }
                self.failures.push(input.to_vec());
            }
            if self.stop_on_failure {
                self.stopped = true;
            }
        }

        Ok(())
    }
}

fn run_session(options: SessionOptions, target: &mut dyn FnMut(&[u8]) -> bool) -> Result<SessionStats, SessionError> {
    let max_len = options.max_input_len;
    let corpus_dir = options.corpus_dir.as_deref();
    for dir in [corpus_dir, options.crashes_dir.as_deref()].into_iter().flatten() {
        fs::create_dir_all(dir).map_err(|source| io_error(dir, source))?;
    }

    let mut fazi = Fazi::new(rng_from_seed(options.seed));
    fazi.options.seed = Some(options.seed);
    fazi.options.max_input_len = max_len;
    fazi.options.len_control = options.len_control;
    fazi.options.max_mutation_depth = options.max_mutation_depth;
    if options.len_control == 0 {
        // The mutators need room for a few bytes even when inputs are tiny;
        // anything over `max_len` is truncated before it runs.
        fazi.current_max_input_len = max_len.max(4);
    }

    let mut executor = Executor {
        target,
        max_iterations: options.max_iterations,
        deadline: options.max_time.and_then(|time| Instant::now().checked_add(time)),
        crashes_dir: options.crashes_dir.as_deref(),
        stop_on_failure: options.stop_on_failure,
        iterations: 0,
        stopped: false,
        failures: Vec::new(),
        seen_failures: HashSet::new(),
    };

    // Seed inputs, shortest first, each mapped to whether it is already stored
    // in the corpus directory.
    let mut seeds: BTreeMap<(usize, Vec<u8>), bool> = BTreeMap::new();
    for mut seed in options.seeds {
        seed.truncate(max_len);
        seeds.entry((seed.len(), seed)).or_insert(false);
    }
    if let Some(dir) = corpus_dir {
        for entry in fs::read_dir(dir).map_err(|source| io_error(dir, source))? {
            let path = entry.map_err(|source| io_error(dir, source))?.path();
            if !path.is_file() {
                continue;
            }
            let mut data = fs::read(&path).map_err(|source| io_error(&path, source))?;
            let stored = data.len() <= max_len;
            data.truncate(max_len);
            *seeds.entry((data.len(), data)).or_insert(false) |= stored;
        }
    }

    // Fuzzing starts from the shortest seed, as with recoverage.
    if let Some(((_, shortest), _)) = seeds.first_key_value() {
        fazi.input = Arc::new(shortest.clone());
    }
    for ((_, data), stored) in seeds {
        if !executor.budget_left() {
            break;
        }

        executor.execute(&data)?;

        let coverage = update_coverage();
        lock(COMPARISON_OPERANDS.get().expect("initialized by the session")).clear();
        if coverage.input_cov > 0 {
            if !stored {
                if let Some(dir) = corpus_dir {
                    write_artifact(dir, "input", &data)?;
                }
            }
            fazi.corpus.push(Input { coverage: coverage.input_cov, data: Arc::new(data) });
        }
    }

    while executor.budget_left() {
        if fazi.input.len() > max_len {
            Arc::make_mut(&mut fazi.input).truncate(max_len);
        }
        fazi.update_max_size();

        executor.execute(&fazi.input)?;

        let summary = fazi.finish_iteration(false);
        if let (Some(input), Some(dir)) = (summary.new_corpus_input, corpus_dir) {
            write_artifact(dir, "input", &input)?;
        }
    }

    Ok(SessionStats {
        iterations: executor.iterations,
        corpus_len: fazi.corpus.len(),
        coverage: lock(COVERAGE.get().expect("initialized by the session")).len(),
        failures: executor.failures,
    })
}

fn write_artifact(dir: &Path, prefix: &str, input: &[u8]) -> Result<(), SessionError> {
    let path = artifact_path(dir, prefix, None, input);
    fs::write(&path, input).map_err(|source| io_error(&path, source))
}

fn io_error(path: &Path, source: io::Error) -> SessionError {
    SessionError::Io { path: path.to_owned(), source }
}
