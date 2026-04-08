//! Store simulator CLI (RocksDB).

use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;
use tracing::error;

use exoware_simulator::server;

pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

const DIRECTORY_FLAG: &str = "directory";
const PORT_FLAG: &str = "port";
const VERBOSE_FLAG: &str = "verbose";

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let home_directory = std::env::var("HOME").expect("$HOME is not configured");
    let default_directory = PathBuf::from(format!("{home_directory}/.exoware_store_simulator"));
    let default_directory: &'static str = default_directory.to_str().unwrap().to_string().leak();

    let matches = Command::new("simulator")
        .version(crate_version())
        .about("Store API simulator (RocksDB).")
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
                .about("Simulator server commands.")
                .arg_required_else_help(true)
                .subcommand(
                    Command::new(server::RUN_CMD)
                        .about("Run the simulator.")
                        .arg(
                            Arg::new(DIRECTORY_FLAG)
                                .long(DIRECTORY_FLAG)
                                .help("RocksDB directory.")
                                .default_value(default_directory)
                                .value_parser(clap::value_parser!(PathBuf))
                                .action(ArgAction::Set),
                        )
                        .arg(
                            Arg::new(PORT_FLAG)
                                .long(PORT_FLAG)
                                .help("Listen port.")
                                .default_value("8080")
                                .value_parser(clap::value_parser!(u16))
                                .action(ArgAction::Set),
                        ),
                ),
        )
        .get_matches();

    let level = if matches.get_flag(VERBOSE_FLAG) {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    if let Some(server_matches) = matches.subcommand_matches(server::CMD) {
        match server_matches.subcommand() {
            Some((server::RUN_CMD, m)) => {
                let directory = m.get_one::<PathBuf>(DIRECTORY_FLAG).unwrap();
                let port = m.get_one::<u16>(PORT_FLAG).unwrap();
                match server::run(directory, *port).await {
                    Ok(()) => return std::process::ExitCode::SUCCESS,
                    Err(e) => {
                        error!(error = ?e, "server failed");
                    }
                }
            }
            _ => error!("invalid subcommand"),
        }
    }

    std::process::ExitCode::FAILURE
}
