//! Exoware Local CLI

use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;
use tracing::error;

mod server;

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

/// Entrypoint for the Exoware Local CLI.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Initialize default directory
    let home_directory = std::env::var("HOME").expect("$HOME is not configured");
    let default_directory = PathBuf::from(format!("{}/.exoware_local", home_directory));
    let default_directory: &'static str = default_directory.to_str().unwrap().to_string().leak();

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
            Command::new(server::CMD)
                .about("Interact with a local server.")
                .arg(
                    Arg::new(DIRECTORY_FLAG)
                        .short('d')
                        .long(DIRECTORY_FLAG)
                        .action(ArgAction::Set)
                        .default_value(default_directory)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .subcommand(
                    Command::new(server::RUN_CMD)
                        .about("Run the local server.")
                        .arg(
                            Arg::new(PORT_FLAG)
                                .short('p')
                                .long(PORT_FLAG)
                                .action(ArgAction::Set)
                                .default_value("8080")
                                .value_parser(clap::value_parser!(u16)),
                        ),
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

    // Parse subcommands
    let directory = matches.get_one::<PathBuf>(DIRECTORY_FLAG).unwrap();
    if let Some(server_matches) = matches.subcommand_matches(server::CMD) {
        match server_matches.subcommand() {
            Some((server::RUN_CMD, matches)) => {
                let port = matches.get_one::<u16>(PORT_FLAG).unwrap();
                if let Err(e) = server::run(directory, port).await {
                    error!(error = ?e, "failed to run local server");
                } else {
                    return std::process::ExitCode::SUCCESS;
                }
            }
            _ => {
                error!("invalid subcommand");
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    std::process::ExitCode::FAILURE
}
