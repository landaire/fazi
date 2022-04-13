use std::path::PathBuf;

use clap::{Parser, Subcommand};

const CRASHES_DEFAULT_DIR: &'static str = "./crashes";
const CORPUS_DEFAULT_DIR: &'static str = "./corpus";

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Reproduce some crash
    Repro { file_path: PathBuf },
}

#[derive(Parser, Debug)]
pub struct RuntimeOptions {
    /// Location at which inputs that cause new coverage will be saved
    #[clap(long,  default_value = CORPUS_DEFAULT_DIR)]
    pub corpus_dir: PathBuf,

    /// Location at which crashing inputs will be saved
    #[clap(long, default_value = CRASHES_DEFAULT_DIR)]
    pub crashes_dir: PathBuf,

    /// The maximum number of times to mutate a single input before moving on
    /// to another.
    #[clap(long, default_value = "15")]
    pub max_mutation_depth: usize,

    /// Length control is used in an algorithm for deciding how quickly the
    /// input size grows. A larger value will result in faster growth while
    /// a smaller value will result in slow growth.
    #[clap(long, default_value = "100")]
    pub len_control: u32,

    /// The maximum size (in bytes) that an input can extend to.
    #[clap(long, default_value = "65000")]
    pub max_input_len: usize,

    /// RNG seed.
    #[clap(long)]
    pub seed: Option<u64>,

    /// Maximum number of fuzzing iterations before the fuzzer should exit.
    #[clap(long)]
    pub max_iters: Option<usize>,

    /// File extension to apply to saved input/crash artifacts
    #[clap(long)]
    pub artifact_extension: Option<String>,

    /// Number of cores to scale to
    #[clap(long, default_value = "1")]
    pub cores: usize,

    /// Saturate
    #[clap(long)]
    pub saturate_cores: bool,

    #[clap(subcommand)]
    pub command: Option<Command>,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            corpus_dir: CORPUS_DEFAULT_DIR.into(),
            crashes_dir: CRASHES_DEFAULT_DIR.into(),
            max_mutation_depth: 15,
            len_control: 100,
            max_input_len: 65000,
            max_iters: None,
            seed: None,
            cores: 1,
            saturate_cores: true,
            command: None,
            artifact_extension: None,
        }
    }
}
