use std::path::PathBuf;
use thiserror::Error;

/// Subcommand for the server.
pub const CMD: &str = "server";

/// Run the local server.
pub const RUN_CMD: &str = "run";

/// Errors that can occur when running the local server.
#[derive(Error, Debug)]
pub enum Error {}

pub async fn run(directory: &PathBuf, port: &u16) -> Result<(), Error> {
    unimplemented!()
}
