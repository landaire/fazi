use std::path::PathBuf;

use clap::{Parser, Subcommand};

const CRASHES_DEFAULT_DIR: &'static str = "./crashes";
const CORPUS_DEFAULT_DIR: &'static str = "./corpus";

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Reproduce some crash
    Repro {
        file_path: PathBuf,
    },
}

#[derive(Parser, Debug)]
pub struct RuntimeOptions {
    #[clap(long,  default_value = CORPUS_DEFAULT_DIR)]
    pub corpus_dir: PathBuf,

    #[clap(long, default_value = CRASHES_DEFAULT_DIR)]
    pub crashes_dir: PathBuf,

    #[clap(long, default_value = "15")]
    pub max_mutation_depth: usize,

    #[clap(long, default_value = "100")]
    pub len_control: u32,

    #[clap(long)]
    pub seed: Option<u64>,

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
            seed: None,
            command: None,
        }
    }
}
