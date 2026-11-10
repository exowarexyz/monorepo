use axum::{routing::get, serve::ListenerExt, Router};
use clap::{Parser, Subcommand};
use datafusion::arrow::datatypes::DataType;
use exoware_sdk::{transport::set_tcp_nodelay, PreferZstdLayer, StoreClient, StoreKeyPrefix};
use exoware_sql::{sql_stack, IndexSpec, KvSchema, SqlServer, TableColumnConfig};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tower_http::cors::CorsLayer;
use tracing::info;

const TABLE_NAME: &str = "orders_kv";

#[derive(Parser, Debug)]
#[command(name = "sql", version, about = "SQL server over the Exoware store.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Run {
        #[arg(long)]
        store_url: String,
        #[arg(long, default_value = "")]
        store_prefix: String,
        /// Address to listen on. The default accepts only connections from this machine.
        #[arg(long, default_value = "127.0.0.1")]
        host: IpAddr,
        #[arg(long, default_value_t = 8082)]
        port: u16,
    },
    Seed {
        #[arg(long)]
        store_url: String,
        #[arg(long, default_value = "")]
        store_prefix: String,
        #[arg(long, default_value_t = 2)]
        interval_secs: u64,
    },
}

async fn health() -> &'static str {
    "ok"
}

fn build_server(
    store_url: &str,
    store_prefix: String,
) -> Result<Arc<SqlServer>, Box<dyn std::error::Error + Send + Sync>> {
    let store = StoreClient::new(store_url).prefixed(StoreKeyPrefix::new(store_prefix)?);
    let schema = KvSchema::new(store).table(
        TABLE_NAME,
        vec![
            TableColumnConfig::new("region", DataType::Utf8, false),
            TableColumnConfig::new("customer_id", DataType::Int64, false),
            TableColumnConfig::new("order_id", DataType::Int64, false),
            TableColumnConfig::new("amount_cents", DataType::Int64, false),
            TableColumnConfig::new("status", DataType::Utf8, false),
        ],
        vec!["order_id".to_string()],
        vec![IndexSpec::lexicographic(
            "region_customer",
            vec!["region".to_string(), "customer_id".to_string()],
        )?],
    )?;
    let server = SqlServer::new(schema)?;
    Ok(Arc::new(server))
}

async fn run(
    store_url: &str,
    store_prefix: String,
    host: IpAddr,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = build_server(store_url, store_prefix)?;
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(sql_stack(server))
        .layer(PreferZstdLayer)
        .layer(CorsLayer::very_permissive());

    let addr = SocketAddr::from((host, port));
    info!(%addr, store_url, "sql server listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await?
        .tap_io(set_tcp_nodelay);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn seed(
    store_url: &str,
    store_prefix: String,
    interval_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = build_server(store_url, store_prefix)?;
    info!(store_url, interval_secs, "starting sql seed");
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let run_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let mut offset: i64 = run_nonce.saturating_mul(10);

    // Keep the signal listener registered while each batch is written and uploaded.
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                info!("ctrl-c received, shutting down");
                break;
            }
            _ = ticker.tick() => {}
        }

        let sql = format!(
            "INSERT INTO {TABLE_NAME} (region, customer_id, order_id, amount_cents, status) VALUES \
             ('us-east', 1001, {}, 3499, 'paid'), \
             ('us-west', 1002, {}, 1799, 'paid'), \
             ('us-east', 1003, {}, 2299, 'pending'), \
             ('eu-central', 1004, {}, 1299, 'paid'), \
             ('us-west', 1005, {}, 4599, 'refunded')",
            offset + 1,
            offset + 2,
            offset + 3,
            offset + 4,
            offset + 5,
        );
        offset = offset.saturating_add(5);

        let df = server.context().sql(&sql).await?;
        let _ = df.collect().await?;
        println!("seeded 5 rows at order_id base {}", offset - 5);
    }

    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Run {
            store_url,
            store_prefix,
            host,
            port,
        } => run(&store_url, store_prefix, host, port).await,
        Command::Seed {
            store_url,
            store_prefix,
            interval_secs,
        } => seed(&store_url, store_prefix, interval_secs).await,
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sql failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_host(host_args: &[&str]) -> IpAddr {
        let args = ["sql", "run", "--store-url", "http://127.0.0.1:8080"];
        let cli = Cli::try_parse_from(args.iter().chain(host_args)).unwrap();
        let Command::Run { host, .. } = cli.command else {
            panic!("the arguments must parse as the run command");
        };
        host
    }

    #[test]
    fn run_listens_on_loopback_unless_a_host_is_given() {
        assert_eq!(run_host(&[]), IpAddr::from([127, 0, 0, 1]));
        assert_eq!(run_host(&["--host", "0.0.0.0"]), IpAddr::from([0, 0, 0, 0]));
    }
}
