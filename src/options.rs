use std::path::PathBuf;

use clap::Parser;

const CRASHES_DEFAULT_DIR: &'static str = "./crashes";
const CORPUS_DEFAULT_DIR: &'static str = "./corpus";

#[derive(Parser, Debug)]
pub(crate) struct RuntimeOptions {
    #[clap(long, short, default_value = CORPUS_DEFAULT_DIR)]
    pub corpus_dir: PathBuf,

    #[clap(long, short, default_value = CRASHES_DEFAULT_DIR)]
    pub crashes_dir: PathBuf,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            corpus_dir: CORPUS_DEFAULT_DIR.into(),
            crashes_dir: CRASHES_DEFAULT_DIR.into(),
        }
    }
}