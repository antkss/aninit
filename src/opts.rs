//! Command-line option handling

use crate::elf;
use crate::is_bin;
use crate::is_ld;
use crate::is_libc;

use std::path::Path;
use std::path::PathBuf;

use colored::Color;
use colored::Colorize;
use derive_setters::Setters;
use ex::fs;
use ex::io;
use snafu::ResultExt;
use snafu::Snafu;
use structopt::StructOpt;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("ELF detection error: {}", source))]
    ElfDetect { source: elf::detect::Error },

    #[snafu(display("failed reading current directory entry: {}", source))]
    DirEnt { source: io::Error },

    #[snafu(display("failed reading current directory: {}", source))]
    ReadDir { source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

/// automate starting binary exploit challenges
#[derive(StructOpt, Setters, Clone)]
#[setters(generate = "false")]
#[setters(prefix = "with_")]
pub struct Opts {
    /// Binary to pwn
    #[structopt(short)]
    #[setters(generate)]
    pub b: Option<PathBuf>,

    /// Challenge libc
    #[structopt(short)]
    #[setters(generate)]
    pub l: Option<PathBuf>,

    /// A linker to preload the libc
    #[structopt(short)]
    #[setters(generate)]
    pub d: Option<PathBuf>,

    /// Path to custom pwntools solve script template. Check the README for more
    /// information.
    #[structopt(long)]
    pub template_path: Option<PathBuf>,

    /// Name of binary variable for pwntools solve script
    #[structopt(long)]
    #[structopt(default_value = "exe")]
    pub template_bin_name: String,

    /// Name of libc variable for pwntools solve script
    #[structopt(long)]
    #[structopt(default_value = "libc")]
    pub template_libc_name: String,

    /// Name of linker variable for pwntools solve script
    #[structopt(long)]
    #[structopt(default_value = "ld")]
    pub template_ld_name: String,

    /// Disable running patchelf on binary
    #[structopt(long)]
    pub no_patch_bin: bool,

    /// Disable generating template solve script
    #[structopt(long)]
    pub no_template: bool,
}

impl Opts {
    /// Print the locations of known files (binary, libc, linker)
    pub fn print(&self) {
        let f = |opt_path: &Option<PathBuf>, header: &str, color| {
            if let Some(path) = opt_path {
                println!(
                    "{}: {}",
                    header.color(color),
                    path.to_string_lossy().bold().color(color)
                )
            }
        };

        f(&self.b, "pwn.bin", Color::BrightBlue);
        f(&self.l, "pwn.libc", Color::Yellow);
        f(&self.d, "pwn.ld", Color::Green);
    }

    /// For the unspecified files, try to guess their path
    pub fn find_if_unspec(self) -> Result<Self> {
        let mut dir = fs::read_dir(".").context(ReadDirSnafu)?;
        let opts = dir.try_fold(self, Opts::merge_result_entry)?;
        Ok(opts)
    }

    /// Helper for `find_if_unspec()`, merging the `Opts` with a directory entry
    fn merge_result_entry(self, dir_ent: io::Result<fs::DirEntry>) -> Result<Self> {
        self.merge_entry(dir_ent.context(DirEntSnafu)?)
            .context(ElfDetectSnafu)
    }

    /// Helper for `merge_result_entry()`, merging the `Opts` with a directory
    /// entry
    fn merge_entry(self, dir_ent: fs::DirEntry) -> elf::detect::Result<Self> {
        let f = |pred: fn(&Path) -> elf::detect::Result<bool>| {
            let path = dir_ent.path();
            Ok(if pred(&path)? { Some(path) } else { None })
        };

        Ok(self
            .clone()
            .with_b(self.b.or(f(is_bin)?))
            .with_l(self.l.or(f(is_libc)?))
            .with_d(self.d.or(f(is_ld)?)))
    }
}
