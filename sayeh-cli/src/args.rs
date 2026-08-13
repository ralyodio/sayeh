use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use sayeh_core::carrier::CarrierKind;

#[derive(Debug, Parser)]
#[command(
    name = "sayeh",
    version,
    about = "Covert encrypted messages in ordinary chat text"
)]
pub struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    pub vault: Option<PathBuf>,
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Hide(HideArgs),
    Reveal(RevealArgs),
    Scan(InputArgs),
    Strip(StripArgs),
    Analyse(AnalyseArgs),
    Capacity(CapacityArgs),
    Probe(ProbeArgs),
    Identity(IdentityArgs),
    Contact(ContactArgs),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("cover_source").required(true).args(["cover", "cover_file"])))]
#[command(group(ArgGroup::new("payload_source").required(true).args(["secret_file", "file"])))]
pub struct HideArgs {
    #[arg(long, value_name = "TEXT")]
    pub cover: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub cover_file: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub secret_file: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
    #[arg(long, value_name = "NAME")]
    pub contact: Option<String>,
    #[arg(long)]
    pub carrier: Option<CarrierKind>,
    #[arg(long, value_name = "APP")]
    pub app: Option<String>,
    #[arg(long, default_value = "direct")]
    pub path: String,
    #[arg(long)]
    pub argon_memory_kib: Option<u32>,
    #[arg(long)]
    pub argon_passes: Option<u32>,
    #[arg(long)]
    pub argon_lanes: Option<u8>,
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct RevealArgs {
    #[arg(short, long, value_name = "PATH")]
    pub input: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct InputArgs {
    #[arg(short, long, value_name = "PATH")]
    pub input: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct StripArgs {
    #[arg(short, long, value_name = "PATH")]
    pub input: Option<PathBuf>,
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub aggressive: bool,
}

#[derive(Debug, Args)]
pub struct AnalyseArgs {
    #[arg(short, long, value_name = "PATH")]
    pub input: Option<PathBuf>,
    #[arg(long)]
    pub carrier: Option<CarrierKind>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ModeChoice {
    Password,
    Contact,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("cover_source").required(true).args(["cover", "cover_file"])))]
pub struct CapacityArgs {
    #[arg(long, value_name = "TEXT")]
    pub cover: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub cover_file: Option<PathBuf>,
    #[arg(long, default_value = "zero-width")]
    pub carrier: CarrierKind,
    #[arg(long, value_enum, default_value = "password")]
    pub mode: ModeChoice,
    #[arg(long, value_name = "NAME")]
    pub file_name: Option<String>,
}

#[derive(Debug, Args)]
pub struct ProbeArgs {
    #[command(subcommand)]
    pub command: ProbeCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProbeCommand {
    Generate {
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    Analyse {
        #[arg(short, long, value_name = "PATH")]
        input: Option<PathBuf>,
        #[arg(long, value_name = "APP")]
        app: String,
        #[arg(long, default_value = "direct")]
        path: String,
        #[arg(long, value_name = "NAME")]
        contact: Option<String>,
    },
}

#[derive(Debug, Args)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub command: IdentityCommand,
}

#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    Init,
    Show,
}

#[derive(Debug, Args)]
pub struct ContactArgs {
    #[command(subcommand)]
    pub command: ContactCommand,
}

#[derive(Debug, Subcommand)]
pub enum ContactCommand {
    Add {
        name: String,
        #[arg(long, value_name = "HEX_OR_QR")]
        public: String,
    },
    List,
    Remove {
        name: String,
    },
    SetCarrier {
        name: String,
        carrier: CarrierKind,
    },
}
