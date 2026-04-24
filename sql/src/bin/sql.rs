use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{routing::get, Router};
use clap::{Parser, Subcommand};
use exoware_sdk::StoreClient;
use exoware_sql::{default_orders_index_specs, sql_connect_stack, KvSchema, SqlServer};
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
        #[arg(long, default_value = "0.0.0.0")]
        host: IpAddr,
        #[arg(long, default_value_t = 8082)]
        port: u16,
    },
    Seed {
        #[arg(long)]
        store_url: String,
        #[arg(long, default_value_t = 2)]
        interval_secs: u64,
    },
}

async fn health() -> &'static str {
    "ok"
}

fn build_server(
    store_url: &str,
) -> Result<Arc<SqlServer>, Box<dyn std::error::Error + Send + Sync>> {
    let client = StoreClient::new(store_url);
    let schema = KvSchema::new(client)
        .orders_table(TABLE_NAME, default_orders_index_specs())
        .map_err(|e| format!("configure schema: {e}"))?;
    let server = SqlServer::new(schema)?;
    Ok(Arc::new(server))
}

async fn run(
    store_url: &str,
    host: IpAddr,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = build_server(store_url)?;
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(sql_connect_stack(server))
        .layer(CorsLayer::very_permissive());

    let addr = SocketAddr::from((host, port));
    info!(%addr, store_url, "sql server listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn seed(
    store_url: &str,
    interval_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = build_server(store_url)?;
    info!(store_url, interval_secs, "starting sql seed");
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let run_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let mut offset: i64 = run_nonce.saturating_mul(10);

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
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

        let df = server.session().sql(&sql).await?;
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
            host,
            port,
        } => run(&store_url, host, port).await,
        Command::Seed {
            store_url,
            interval_secs,
        } => seed(&store_url, interval_secs).await,
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sql failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
