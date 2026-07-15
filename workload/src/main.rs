use clap::{Parser, Subcommand};
use exoware_workload::{bench, load, validate};

#[derive(Parser, Debug)]
#[command(
    name = "workload",
    about = "Validate an Exoware deployment."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Load(load::Args),
    Bench(bench::Args),
    Validate(validate::Args),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("exoware_workload=info".parse()?)
                .add_directive("workload=info".parse()?),
        )
        .init();

    match Cli::parse().command {
        Command::Load(args) => load::run(args).await,
        Command::Bench(args) => bench::run(args).await,
        Command::Validate(args) => validate::run(args).await,
    }
}
