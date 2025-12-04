use axum::{
    routing::{get, post},
    extract::{Path, State},
    http::StatusCode,
    Json, Router,
};

use serde_json::Value;
use std::{net::SocketAddr, path::PathBuf};

use tokio::net::TcpListener;

#[derive(Clone)]
struct OrchestratorState {
    storage_dir: PathBuf,
}


/// Start the orchestrator HTTP server.
///
/// - GET  /v1/health
/// - POST /v1/snapshot/:stage   (body: JSON, stored to disk)
pub async fn start_server(
    listen: String,
    storage_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = OrchestratorState { storage_dir };

    let app = Router::new()
        .route("/v1/health", get(health_handler))
        .route("/v1/snapshot/{stage}", post(snapshot_handler))
        .with_state(state);

    let addr: SocketAddr = listen.parse()?;
    println!("Orchestrator listening on http://{addr}");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_handler() -> &'static str {
    "ok"
}

/// Accept a JSON snapshot for a given stage and write it to disk.
///
async fn snapshot_handler(
    State(state): State<OrchestratorState>,
    Path(stage): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, String) {
    // Ensure storage dir exists
    if let Err(e) = std::fs::create_dir_all(&state.storage_dir) {
        eprintln!(
            "Failed to create storage dir {}: {e}",
            state.storage_dir.display()
        );
        return (StatusCode::INTERNAL_SERVER_ERROR, "storage error".into());
    }

    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let filename = format!("snapshot-{}-{}.json", ts, stage);
    let path = state.storage_dir.join(filename);

    let pretty = match serde_json::to_vec_pretty(&body) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to re-serialize snapshot JSON: {e}");
            return (StatusCode::BAD_REQUEST, "invalid json".into());
        }
    };

    if let Err(e) = std::fs::write(&path, &pretty) {
        eprintln!("Failed to write snapshot to {}: {e}", path.display());
        return (StatusCode::INTERNAL_SERVER_ERROR, "write failed".into());
    }

    println!(
        "Stored snapshot for stage={} at {}",
        stage,
        path.display()
    );

    // TODO (later): enqueue this file for LLM analysis

    (StatusCode::OK, "ok".into())
}