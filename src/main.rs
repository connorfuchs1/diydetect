use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

mod sensors;
use sensors::SensorConfig;

/// which sensor to run
#[derive(Debug, Clone, ValueEnum)]
enum Stage {
    Processes,
    Net,
    File,
    All,
}

#[derive(Parser, Debug)]
#[command(
    name = "diydetect",
    version,
    about = "DIY LLM-assisted endpoint telemetry collector",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a scan on this host
    Scan {
        /// which stage(s) to collect (default: processes)
        #[arg(long, value_enum, default_value_t = Stage::Processes)]
        stage: Stage,

        /// How long to run sampling sensors (seconds)
        #[arg(long, default_value_t = 60)]
        duration_secs: u64,

        /// Where to write JSON (for now: sensors just print to stdout; this is future use)
        #[arg(long)]
        output: Option<PathBuf>,

        /// Override host ID (not yet wired into SensorConfig, future use)
        #[arg(long)]
        host_id: Option<String>,
    },

    /// run as a long-running agent that periodically scans and sends data to a server
    Agent {
        /// orchestrator base URL, i.e http://collector:8080
        #[arg(long)]
        server_url: String,

        /// Scan interval in seconds
        #[arg(long, default_value_t = 300)]
        interval_secs: u64,

        /// Which stage(s) to collect each interval
        #[arg(long, value_enum, default_value_t = Stage::Processes)]
        stage: Stage,

        /// Override host ID (future use)
        #[arg(long)]
        host_id: Option<String>,
    },

    /// Run the orchestrator / collector (HTTP server + LLM + dashboard)
    Orchestrator {
        /// Address to bind, i.e 0.0.0.0:8080
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen: String,

        /// dir to store incoming JSON snapshots from sensors
        #[arg(long, default_value = "captures")]
        storage_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            stage,
            duration_secs,
            output,
            host_id,
        } => {
            // output & host_id are not used yet  keep them for future snapshot/LLM wiring
            let _ = output;
            let _ = host_id;
            run_scan(stage, duration_secs).await;
        }

        Commands::Agent {
            server_url,
            interval_secs,
            stage,
            host_id,
        } => {
            let _ = host_id;
            run_agent(server_url, interval_secs, stage).await;
        }

        Commands::Orchestrator { listen, storage_dir } => {
            run_orchestrator(listen, storage_dir).await;
        }
    }
}

///  scan on this host
async fn run_scan(stage: Stage, duration_secs: u64) {
    let cfg = SensorConfig { duration_secs };

    println!("Starting scan with config: {:?}", cfg);

    if matches!(stage, Stage::Processes | Stage::All) {
        let cfg_clone = cfg.clone();
        tokio::task::spawn_blocking(move || {
            sensors::process::run_process_sensor(&cfg_clone);
        })
        .await
        .expect("process sensor task panicked");
    }

    // network sensor 
    if matches!(stage, Stage::Net | Stage::All) {
        sensors::net::run_net_sensor(&cfg);
    }

    // file sensor 
    if matches!(stage, Stage::File | Stage::All) {
        sensors::file::run_file_sensor(&cfg);
    }

    println!("Scan complete.");
}

/// Agent mode: eventually this will run in a loop on each host,
/// periodically scanning and POSTing JSON to the orchestrator. (we'll probably have an inbetween
/// stage to determine if the scanned data is worthy enough to be shipped to llm(s))
///
async fn run_agent(server_url: String, interval_secs: u64, stage: Stage) {
    eprintln!(
        "[agent stub] would periodically run {:?} every {}s and POST results to {}",
        stage, interval_secs, server_url
    );

    // Skeleton for the future:
    /*
    let cfg = SensorConfig { duration_secs: interval_secs };

    loop {
        // 1) Collect snapshot(s) for the requested stage(s)
        run_scan(stage.clone(), cfg.duration_secs).await;

        // 2) TODO: instead of printing, serialize to JSON and POST to server_url
        //   send SystemSnapshot as application/json

        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
    */
}

/// Orchestrator mode: eventually this will:
///   - Listen for incoming snapshots from agents
///   - Store them to disk/DB
///   - Trigger LLM analysis pipelines
///   - Serve a dashboard API
///
async fn run_orchestrator(listen: String, storage_dir: PathBuf) {
    eprintln!(
        "[orchestrator stub] would listen on {} and store snapshots under {}",
        listen,
        storage_dir.display()
    );

    // Skeleton for the future:
    /*
    // Use axum/warp/etc. here
    // - POST write JSON to storage_dir
    // - GET  /v1/findings        -> return latest LLM analysis
    //
    // let app = build_router(storage_dir);
    // axum::Server::bind(&listen.parse().unwrap())
    //     .serve(app.into_make_service())
    //     .await
    //     .unwrap();
    */
}
