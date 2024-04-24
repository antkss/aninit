//! Top-level main code for `pwninit`

use aninit::opts::Opts;

use colored::Colorize;
use structopt::StructOpt;

/// Parse command line options and set up specified directory for pwning
fn try_main() -> aninit::Result {
    // Parse arguments and run
    let opts = Opts::from_args();
    aninit::run(opts)?;
    Ok(())
}

/// Top-level error catcher
fn main() {
    if let Err(err) = try_main() {
        eprintln!("{}", format!("error: {}", err).red().bold());
        std::process::exit(1);
    }
}
