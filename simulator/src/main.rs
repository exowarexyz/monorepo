//! Exoware Simulator CLI

use clap::{Arg, ArgAction, Command};
use std::env;
use std::path::PathBuf;
use tracing::error;

mod server;

/// Returns the version of the crate from `CARGO_PKG_VERSION`.
pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Flag for verbose output. Controls logging level.
const VERBOSE_FLAG: &str = "verbose";

/// Flag for the directory to use for the persistent store.
const DIRECTORY_FLAG: &str = "directory";

/// Flag for the port to use for the server.
const PORT_FLAG: &str = "port";

/// Flag for the minimum consistency bound in milliseconds.
const CONSISTENCY_BOUND_MIN_FLAG: &str = "consistency-bound-min";

/// Flag for the maximum consistency bound in milliseconds.
const CONSISTENCY_BOUND_MAX_FLAG: &str = "consistency-bound-max";

/// Flag for the token.
const TOKEN_FLAG: &str = "token";

/// Flag to allow public, unauthenticated access for read-only methods.
const ALLOW_PUBLIC_ACCESS_FLAG: &str = "allow-public-access";

/// Entrypoint for the Exoware Simulator CLI.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Initialize the default directory for the persistent store. This will be
    // `$HOME/.exoware_simulator`.
    let home_directory = std::env::var("HOME").expect("$HOME is not configured");
    let default_directory = PathBuf::from(format!("{}/.exoware_simulator", home_directory));
    let default_directory: &'static str = default_directory.to_str().unwrap().to_string().leak();

    // Define the CLI application and its arguments.
    let matches = Command::new("simulator")
        .version(crate_version())
        .about("Simulate the Exoware API.")
        .arg_required_else_help(true)
        .arg(
            Arg::new(VERBOSE_FLAG)
                .short('v')
                .long(VERBOSE_FLAG)
                .help("Enable verbose logging.")
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new(server::CMD)
                .about("Commands for the simulator server.")
                .arg_required_else_help(true)
                .subcommand(
                    Command::new(server::RUN_CMD)
                        .about("Run the simulator server.")
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
                            Arg::new(CONSISTENCY_BOUND_MIN_FLAG)
                                .long(CONSISTENCY_BOUND_MIN_FLAG)
                                .help("The minimum consistency bound in milliseconds.")
                                .default_value("0")
                                .value_parser(clap::value_parser!(u64))
                                .action(ArgAction::Set),
                        )
                        .arg(
                            Arg::new(CONSISTENCY_BOUND_MAX_FLAG)
                                .long(CONSISTENCY_BOUND_MAX_FLAG)
                                .help("The maximum consistency bound in milliseconds.")
                                .default_value("60000")
                                .value_parser(clap::value_parser!(u64))
                                .action(ArgAction::Set),
                        )
                        .arg(
                            Arg::new(TOKEN_FLAG)
                                .long(TOKEN_FLAG)
                                .help("The authorization token to use.")
                                .required(true)
                                .action(ArgAction::Set),
                        )
                        .arg(
                            Arg::new(ALLOW_PUBLIC_ACCESS_FLAG)
                                .long(ALLOW_PUBLIC_ACCESS_FLAG)
                                .help("Allow public access for read-only methods.")
                                .action(ArgAction::SetTrue),
                        ),
                ),
        )
        .get_matches();

    // Create a logger with a level determined by the `verbose` flag.
    let level = if matches.get_flag(VERBOSE_FLAG) {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    // Parse subcommands and run the appropriate logic.
    if let Some(server_matches) = matches.subcommand_matches(server::CMD) {
        match server_matches.subcommand() {
            Some((server::RUN_CMD, matches)) => {
                // Extract arguments for the `run` command.
                let directory = matches.get_one::<PathBuf>(DIRECTORY_FLAG).unwrap();
                let port = matches.get_one::<u16>(PORT_FLAG).unwrap();
                let consistency_bound_min = matches
                    .get_one::<u64>(CONSISTENCY_BOUND_MIN_FLAG)
                    .copied()
                    .unwrap();
                let consistency_bound_max = matches
                    .get_one::<u64>(CONSISTENCY_BOUND_MAX_FLAG)
                    .copied()
                    .unwrap();
                let token = matches.get_one::<String>(TOKEN_FLAG).unwrap();
                let allow_public_access = matches.get_flag(ALLOW_PUBLIC_ACCESS_FLAG);

                // Validate that the minimum consistency bound is not greater than the maximum.
                if consistency_bound_min > consistency_bound_max {
                    error!(
                        "--consistency-bound-min cannot be greater than --consistency-bound-max"
                    );
                    return std::process::ExitCode::FAILURE;
                }

                // Run the server.
                if let Err(e) = server::run(
                    directory,
                    port,
                    consistency_bound_min,
                    consistency_bound_max,
                    token.to_string(),
                    allow_public_access,
                )
                .await
                {
                    error!(error = ?e, "failed to run simulator server");
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
