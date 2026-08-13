mod args;
mod commands;
mod io;
mod store;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    commands::run(args::Cli::parse())
}
