use std::path::PathBuf;
use std::time::Duration;

mod sensors;
mod model;
mod orchestrator;

use sensors::SensorConfig;
use model::SystemSnapshot;
use reqwest::Client;
use clap::{Parser, Subcommand, ValueEnum};



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
            run_agent(server_url, interval_secs, stage, host_id).await;
        }

        Commands::Orchestrator { listen, storage_dir } => {
            run_orchestrator(listen, storage_dir).await;
        }
    }
}

///  scan on this host
async fn run_scan(stage: Stage, duration_secs: u64) {
    let cfg = SensorConfig { duration_secs };

    //println!("Starting scan with config: {:?}", cfg);

    if matches!(stage, Stage::Processes | Stage::All) {
        let cfg_for_process = cfg.clone();
        let host_id = whoami::hostname(); // or later a CLI override

        // Blocking Win32 calls
        let snapshot = tokio::task::spawn_blocking(move || {
            build_process_snapshot(&cfg_for_process, host_id)
        })
        .await
        .expect("process snapshot task panicked");

        // For now: just print the JSON to stdout
        match serde_json::to_string_pretty(&snapshot) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("Failed to serialize snapshot: {e}"),
        }
    }

    //TODO
    if matches!(stage, Stage::Net | Stage::All) {
        sensors::net::run_net_sensor(&cfg);
    }

    if matches!(stage, Stage::File | Stage::All) {
        sensors::file::run_file_sensor(&cfg);
    }

    //println!("Scan complete.");
}


///=============================================AGENTS=============================================================


/// Agent mode: eventually this will run in a loop on each host,
/// periodically scanning and POSTing JSON to the orchestrator. 
/// Runs multiple multithreaded agents (process, file, network, etc)
/// (we'll probably have an inbetween
/// stage to determine if the scanned data is worthy enough to be shipped to llm(s))
/// W
async fn run_agent(
    server_url: String,
    interval_secs: u64,
    stage: Stage,
    host_id: Option<String>,
) {
    let host = host_id.unwrap_or_else(whoami::hostname);
    let cfg = SensorConfig {
        duration_secs: interval_secs, // reuse for now
    };

    let base = server_url.trim_end_matches('/').to_string();
    let client = Client::new();

    println!(
        "Agent starting for host={} -> {} (every {}s, stage={:?})",
        host, base, interval_secs, stage
    );

    match stage 
    {
        Stage::Processes => 
        {
            // Single-stage mode: just run the process loop
            run_process_agent(client, base, host, cfg, interval_secs).await;
        }

        Stage::Net | Stage::File => 
        {
            eprintln!(
                "Agent: stage {:?} not implemented yet, using processes only.",
                stage
            );
        }

        Stage::All => 
        {
            // Multi-stage mode: spawn multiple loops (only processes implemented now)
            let client_proc = client.clone();
            let base_proc = base.clone();
            let host_proc = host.clone();
            let cfg_proc = cfg.clone();

            let proc_task = tokio::spawn(async move {
                run_process_agent(
                    client_proc,
                    base_proc,
                    host_proc,
                    cfg_proc,
                    interval_secs,
                )
                .await
            });

            // TODO: later
            // let net_task = tokio::spawn(async move {
            //     run_net_stage_loop(...).await
            // });
            //
            // let file_task = tokio::spawn(async move {
            //     run_file_stage_loop(...).await
            // });

            // For now just wait on the process loop (it runs forever until killed)
            let _ = proc_task.await;
        }

        // For now, alias Net / File to Processes until those are implemented

    }
}


//Process agent functionality

async fn run_process_agent(
    client: Client,
    base_url: String,
    host: String,
    cfg: SensorConfig,
    interval_secs: u64,
) 
{
    let url = format!("{}/v1/snapshot/processes", base_url);

    loop 
    {
        //Build snapshot (heavy Win32 work -> spawn_blocking)
        let cfg_clone = cfg.clone();
        let host_clone = host.clone();

        let snapshot = match tokio::task::spawn_blocking(move || 
        {
            build_process_snapshot(&cfg_clone, host_clone)
        })
        .await
        {
            Ok(s) => s,
            Err(e) => 
            {
                eprintln!("Agent[processes]: snapshot task panicked: {e}");
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
                continue;
            }
        };

        //POST snapshot
        println!("Agent[processes]: POSTing snapshot to {}", url);
        match client.post(&url).json(&snapshot).send().await {
            Ok(resp) if resp.status().is_success() => {
                println!(
                    "Agent[processes]: snapshot posted successfully ({})",
                    resp.status()
                );
            }
            Ok(resp) => {
                eprintln!(
                    "Agent[processes]: server returned error status {}",
                    resp.status()
                );
            }
            Err(e) => {
                eprintln!("Agent[processes]: error POSTing snapshot: {e}");
            }
        }

        //Wait for next interval
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}


//Process agent helpers
fn build_process_snapshot(cfg: &SensorConfig, host_id: String,) -> SystemSnapshot 
{
    // For now cfg.duration_secs is unused here; later you might use it for sampling duration
    let processes = sensors::process::collect_process_info();

    SystemSnapshot {
        host_id,
        collected_at: chrono::Utc::now(),
        processes,
    }
}



//File Agent Functionality

// ....TODO...





//Net Agent Functionality

//  ....TODO....

//============================================ORCHESTRATOR==========================================================













/// Orchestrator mode: eventually this will:
///   - Listen for incoming snapshots from agents
///   - Store them to disk/DB
///   - Trigger LLM analysis pipelines
///   - Serve a dashboard API
///
async fn run_orchestrator(listen: String, storage_dir: PathBuf) {

    if let Err(e) = orchestrator::start_server(listen, storage_dir).await {
        eprintln!("Orchestrator server exited with error: {e}");
    }


}



