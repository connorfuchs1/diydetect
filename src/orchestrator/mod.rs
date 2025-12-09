use axum::{
    routing::{get, post},
    extract::{Path as AxumPath, State},
    http::StatusCode,
    Json, Router,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::net::TcpListener;
use crate::model::SystemSnapshot;

/// w LLM family/provider
#[derive(Clone, Debug)]
enum LlmProvider {
    OpenAi,
    Anthropic,
    LocalOllama,
    // extend as needed
}

/// A single configured LLM analysis target
#[derive(Clone, Debug)]
struct LlmTarget {
    /// Short ID used in filenames/logs, e.g. "openai-gpt4-mini"
    id: String,
    /// Which API family
    provider: LlmProvider,
    /// Provider-specific model name, e.g. "gpt-4.1-mini"
    model: String,
}

#[derive(Clone)]
struct OrchestratorState {
    storage_dir: PathBuf,
    http_client: Client,
    llm_targets: Arc<Vec<LlmTarget>>,
}

/// Parse --llm flags of the form "provider:model"
fn parse_llm_flags(flags: Vec<String>) -> Result<Vec<LlmTarget>, Box<dyn Error>> 
{
    if flags.is_empty() 
    {
        return Err("at least one --llm flag is required".into());
    }

    let mut out = Vec::new();

    for raw in flags 
    {
        let parts: Vec<_> = raw.splitn(2, ':').collect();
        if parts.len() != 2 
        {
            return Err(format!("invalid --llm flag '{raw}', expected provider:model").into());
        }

        let provider_str = parts[0].to_lowercase();
        let model_str = parts[1].to_string();

        let provider = match provider_str.as_str() {
            "openai" => LlmProvider::OpenAi,
            "anthropic" => LlmProvider::Anthropic,
            "ollama" | "local" => LlmProvider::LocalOllama,
            other => 
            {
                return Err(format!("unknown LLM provider '{other}'").into());
            }
        };

        let id = format!("{provider_str}-{model_str}");

        out.push(LlmTarget 
        {
            id,
            provider,
            model: model_str,
        });
    }

    Ok(out)
}

/// Start the orchestrator HTTP server.
///
/// - GET  /v1/health
/// - POST /v1/snapshot/{stage}
pub async fn start_server(
    listen: String,
    storage_dir: PathBuf,
    llm_flags: Vec<String>,
) -> Result<(), Box<dyn Error>> 
{
    let llm_vec = parse_llm_flags(llm_flags)?;

    // Early env validation
    for target in &llm_vec {
        match target.provider {
            LlmProvider::OpenAi => {
                if std::env::var("OPENAI_API_KEY").is_err() {
                    eprintln!(
                        "Warning: LLM target '{}' uses OpenAI but OPENAI_API_KEY is not set.",
                        target.id
                    );
                }
            }
            LlmProvider::Anthropic => {
                if std::env::var("ANTHROPIC_API_KEY").is_err() {
                    eprintln!(
                        "Warning: LLM target '{}' uses Anthropic but ANTHROPIC_API_KEY is not set.",
                        target.id
                    );
                }
            }
            LlmProvider::LocalOllama => {
                // probably no API key needed, but you might later check OLLAMA_BASE_URL, etc.
            }
        }
    }

    let state = OrchestratorState {
        storage_dir,
        http_client: Client::new(),
        llm_targets: Arc::new(llm_vec),
    };

    let app = Router::new()
        .route("/v1/health", get(health_handler))
        .route("/v1/snapshot/{stage}", post(snapshot_handler))
        .with_state(state.clone());

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
async fn snapshot_handler(
    State(state): State<OrchestratorState>,
    AxumPath(stage): AxumPath<String>,
    Json(snapshot): Json<SystemSnapshot>,
) -> (StatusCode, String) {
    // Pick snapshot directory based on stage
    let snapshots_subdir = match stage.as_str() {
        "processes" => "process_snapshots",
        "net" => "net_snapshots",
        "file" => "file_snapshots",
        other => other, // fallback
    };

    let snapshots_dir = state.storage_dir.join(snapshots_subdir);

    if let Err(e) = std::fs::create_dir_all(&snapshots_dir) {
        eprintln!(
            "Failed to create snapshot dir {}: {e}",
            snapshots_dir.display()
        );
        return (StatusCode::INTERNAL_SERVER_ERROR, "storage error".into());
    }

    let ts = snapshot.collected_at.format("%Y%m%d-%H%M%S").to_string();


    let filename = if stage == "processes" {
        format!("process_snapshot_{}_{}.json", ts, snapshot.host_id)
    }
    else {
        format!("{}_snapshot_{}_{}.json", stage, ts, snapshot.host_id)
    };

    let path = snapshots_dir.join(&filename);

    let pretty = match serde_json::to_vec_pretty(&snapshot) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to re-serialize snapshot JSON: {e}");
            return (StatusCode::BAD_REQUEST, "invalid snapshot".into());
        }
    };

    if let Err(e) = std::fs::write(&path, &pretty) {
        eprintln!("Failed to write snapshot to {}: {e}", path.display());
        return (StatusCode::INTERNAL_SERVER_ERROR, "write failed".into());
    }

    println!(
        "Stored snapshot for host={} stage={} at {}",
        snapshot.host_id,
        stage,
        path.display()
    );

    // === Automatically fan out to all configured LLMs for this snapshot ===
    let state_clone = state.clone();
    let stage_clone = stage.clone();
    let path_clone = path.clone();

    tokio::spawn(async move {
        if let Err(e) = send_to_llms(state_clone, stage_clone, path_clone).await {
            eprintln!("LLM dispatch failed for stage=");
        }
    });

    (StatusCode::OK, "ok".into())
}

/// Read the snapshot from snapshot_path and send it to each configured LLM.


async fn send_to_llms(
    state: OrchestratorState,
    stage: String,
    snapshot_path: PathBuf,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> 
{
    // Read JSON bytes from disk
    let bytes: Vec<u8> = tokio::fs::read(&snapshot_path).await?;

    // Deserialize snapshot for metadata (host_id, etc.)
    let snapshot: SystemSnapshot = serde_json::from_slice::<SystemSnapshot>(&bytes)?;

    // Also keep the raw JSON string for the LLM prompt
    let json_str = String::from_utf8(bytes)?;   // <- done once, outside the loop

    for target in state.llm_targets.iter() {
        println!(
            "[LLM-dispatch] host={} stage={} -> {} ({:?}) with model {}",
            snapshot.host_id,
            stage,
            target.id,
            target.provider,
            target.model
        );

        match target.provider {
            LlmProvider::OpenAi => {
                // Note the borrows:
                //  - &stage  : &String -> &str
                //  - &snapshot_path : &PathBuf -> &Path
                dispatch_openai(
                    &state.http_client,
                    target,
                    &stage,
                    &snapshot.host_id,
                    &json_str,
                    &snapshot_path,
                )
                .await?;
            }
            LlmProvider::Anthropic => {
                // TODO: implement later
            }
            LlmProvider::LocalOllama => {
                // TODO: implement later
            }
        }
    }

    Ok(())
}



// ========================== LLM API HANDLERS AND STRUCTS =====================================

#[derive(Serialize)]
struct ChatMessage {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct ChatRequestBody {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
}

#[derive(Deserialize)]
struct OpenAiChatResponse {
    choices: Vec<OpenAiChoice>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
}

#[derive(Deserialize)]
struct OpenAiMessage {
    content: String,
}


async fn dispatch_openai(
    client: &Client,
    target: &LlmTarget,
    stage: &str,
    host_id: &str,
    snapshot_json: &str,
    snapshot_path: &Path,
) -> Result<(), Box<dyn Error + Send + Sync>> 
{
    // Base URL (optional override)
    let api_base = std::env::var("OPENAI_API_BASE")
        .unwrap_or_else(|_| "https://api.openai.com/v1".to_string());

    // API key (required)
    let api_key = match std::env::var("OPENAI_API_KEY") {
        Ok(k) => k,
        Err(e) => {
            eprintln!(
                "[OpenAI] Skipping analysis for model {}: OPENAI_API_KEY not set ({e})",
                target.model
            );
            return Ok(()); // soft-fail for this target, don't kill pipeline
        }
    };

    let url = format!("{}/chat/completions", api_base.trim_end_matches('/'));

    let system_prompt = format!(
        "You are an incident-response assistant. \
         You are analyzing {stage} telemetry for host {host_id}. \
         Return a concise JSON object with keys like 'summary', 'suspicious_items', \
         and 'recommendations'."
    );

    let user_prompt = format!(
        "Here is the raw JSON snapshot for stage '{stage}' on host '{host_id}':\n\n{}",
        snapshot_json
    );

    let body = ChatRequestBody {
        model: target.model.clone(),
        temperature: 0.0,
        messages: vec![
            ChatMessage {
                role: "system",
                content: system_prompt,
            },
            ChatMessage {
                role: "user",
                content: user_prompt,
            },
        ],
    };

    let resp = client
        .post(&url)
        .bearer_auth(&api_key)
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        eprintln!("[OpenAI] HTTP {}: {}", status, text);
        return Ok(());
    }

    let parsed: OpenAiChatResponse = resp.json().await?;
    let content = parsed
        .choices
        .get(0)
        .map(|c| c.message.content.clone())
        .unwrap_or_else(|| "{}".to_string());

    let stem = snapshot_path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy();

    let out_name = format!("{stem}.{}.analysis.json", target.id);
    let out_path = snapshot_path.with_file_name(out_name);

    tokio::fs::write(&out_path, content).await?;

    println!(
        "[OpenAI] wrote analysis for host={} stage={} to {}",
        host_id,
        stage,
        out_path.display()
    );

    Ok(())
}

