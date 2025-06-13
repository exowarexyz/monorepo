//! Exoware Local CLI

use clap::{Arg, ArgAction, Command};
use std::env;
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
        .about("Exoware local development server.")
        .arg_required_else_help(true)
        .arg(
            Arg::new(VERBOSE_FLAG)
                .short('v')
                .long(VERBOSE_FLAG)
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new(server::CMD)
                .about("Commands for the local server.")
                .arg_required_else_help(true)
                .subcommand(
                    Command::new(server::RUN_CMD)
                        .about("Run the local server.")
                        .arg(
                            Arg::new(DIRECTORY_FLAG)
                                .long(DIRECTORY_FLAG)
                                .help("The directory to use for the server.")
                                .default_value(default_directory)
                                .value_parser(clap::value_parser!(PathBuf))
                                .action(ArgAction::Set),
                        )
                        .arg(
                            Arg::new(PORT_FLAG)
                                .long(PORT_FLAG)
                                .help("The port to use for the server.")
                                .default_value("8080")
                                .value_parser(clap::value_parser!(u16))
                                .action(ArgAction::Set),
                        )
                        .arg(
                            Arg::new("consistency-bound")
                                .long("consistency-bound")
                                .help("The consistency bound in milliseconds.")
                                .required(true)
                                .value_parser(clap::value_parser!(u64))
                                .action(ArgAction::Set),
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
    if let Some(server_matches) = matches.subcommand_matches(server::CMD) {
        match server_matches.subcommand() {
            Some((server::RUN_CMD, matches)) => {
                let directory = matches.get_one::<PathBuf>(DIRECTORY_FLAG).unwrap();
                let port = matches.get_one::<u16>(PORT_FLAG).unwrap();
                let consistency_bound = matches
                    .get_one::<u64>("consistency-bound")
                    .copied()
                    .unwrap();
                if let Err(e) = server::run(directory, port, consistency_bound).await {
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
