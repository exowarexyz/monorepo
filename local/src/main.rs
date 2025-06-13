//! Exoware Local CLI

use std::path::PathBuf;

use clap::{Arg, ArgAction, Command};

mod kv;

/// Returns the version of the crate.
pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Flag for verbose output
const VERBOSE_FLAG: &str = "verbose";

/// Flag for the directory to use.
const DIRECTORY_FLAG: &str = "directory";

/// Flag for the port to use.
const PORT_FLAG: &str = "port";

/// Command to run the local server.
const RUN_COMMAND: &str = "run";

/// Entrypoint for the Exoware Local CLI.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Initialize default directory
    let home_directory = std::env::var("HOME").expect("$HOME is not configured");
    let default_directory = PathBuf::from(format!("{}/.exoware_local", home_directory));

    // Define application
    let matches = Command::new("local")
        .version(crate_version())
        .about("TBA")
        .arg(
            Arg::new(VERBOSE_FLAG)
                .short('v')
                .long(VERBOSE_FLAG)
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new(RUN_COMMAND)
                .about("Start the local server.")
                .arg(
                    Arg::new(DIRECTORY_FLAG)
                        .short('d')
                        .long(DIRECTORY_FLAG)
                        .action(ArgAction::Set)
                        .default_value(default_directory)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new(PORT_FLAG)
                        .short('p')
                        .long(PORT_FLAG)
                        .action(ArgAction::Set)
                        .default_value("8080")
                        .value_parser(clap::value_parser!(u16)),
                ),
        )
        .get_matches();

    // Create logger
    let level = if matches.get_flag(VERBOSE_FLAG) {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).init();
    std::process::ExitCode::FAILURE
}
