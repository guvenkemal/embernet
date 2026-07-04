use crate::proto::{Envelope, KeypairFile, Message};
use crate::store::{ChannelRef, append_message, read_channel_tail};
use crate::util::valid_channel;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

const JSONRPC_VERSION: &str = "2.0";
const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct TailChannelArgs {
    channel: String,
    limit: usize,
}

#[derive(Debug, Deserialize)]
struct PostMessageArgs {
    channel: String,
    title: Option<String>,
    body: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    refs: Vec<String>,
}

pub fn run_stdio(datadir: PathBuf) -> Result<()> {
    let datadir = secure_datadir(datadir)?;
    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    while let Some(raw) = read_mcp_message(&mut reader)? {
        let request: JsonRpcRequest = match serde_json::from_slice(&raw) {
            Ok(req) => req,
            Err(err) => {
                write_response(
                    &mut writer,
                    &JsonRpcResponse {
                        jsonrpc: JSONRPC_VERSION,
                        id: Value::Null,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32700,
                            message: "Parse error".to_string(),
                            data: Some(json!({ "details": err.to_string() })),
                        }),
                    },
                )?;
                continue;
            }
        };

        // JSON-RPC notifications have no id and must not receive a response.
        let Some(id) = request.id.clone() else {
            handle_notification(&request);
            continue;
        };

        let response = match handle_request(&datadir, request) {
            Ok(result) => JsonRpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id,
                result: Some(result),
                error: None,
            },
            Err(err) => JsonRpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id,
                result: None,
                error: Some(err),
            },
        };

        write_response(&mut writer, &response)?;
    }

    Ok(())
}

fn handle_notification(request: &JsonRpcRequest) {
    tracing::debug!(method = %request.method, "mcp notification received");
}

fn handle_request(
    datadir: &Path,
    request: JsonRpcRequest,
) -> std::result::Result<Value, JsonRpcError> {
    if request.jsonrpc.as_deref().unwrap_or(JSONRPC_VERSION) != JSONRPC_VERSION {
        return Err(invalid_request("jsonrpc must be \"2.0\""));
    }

    match request.method.as_str() {
        "initialize" => Ok(initialize_result()),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => handle_tool_call(datadir, request.params),
        other => Err(method_not_found(format!("unknown method: {other}"))),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "embernet",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "list_channels",
            "description": "List available Embernet channel names under the configured data directory.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "tail_channel",
            "description": "Read recent verified Envelope objects from a channel log.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "channel": {
                        "type": "string",
                        "description": "Channel name, for example tech/linux."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Maximum number of recent messages to return."
                    }
                },
                "required": ["channel", "limit"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "post_message",
            "description": "Create and append a signed text post using the local Embernet identity.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "channel": {
                        "type": "string",
                        "description": "Channel name, for example tech/linux."
                    },
                    "title": {
                        "type": ["string", "null"],
                        "description": "Optional message title. Use null when absent."
                    },
                    "body": {
                        "type": "string",
                        "description": "Text body to store as Body::Text."
                    },
                    "tags": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional tags. Defaults to an empty array."
                    },
                    "refs": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional references. Defaults to an empty array."
                    }
                },
                "required": ["channel", "title", "body"],
                "additionalProperties": false
            }
        }),
    ]
}

fn handle_tool_call(datadir: &Path, params: Value) -> std::result::Result<Value, JsonRpcError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("tools/call requires params.name"))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let payload = match name {
        "list_channels" => list_channels(datadir).map(|channels| json!({ "channels": channels })),
        "tail_channel" => {
            let args: TailChannelArgs = parse_args(arguments)?;
            tail_channel(datadir, args).map(|messages| {
                json!({
                    "channel": messages.0,
                    "messages": messages.1
                })
            })
        }
        "post_message" => {
            let args: PostMessageArgs = parse_args(arguments)?;
            post_message(datadir, args).map(|posted| json!(posted))
        }
        other => Err(anyhow!("unknown tool: {other}")),
    }
    .map_err(tool_error)?;

    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
            }
        ],
        "structuredContent": payload,
        "isError": false
    }))
}

fn parse_args<T: for<'de> Deserialize<'de>>(value: Value) -> std::result::Result<T, JsonRpcError> {
    serde_json::from_value(value).map_err(|err| invalid_params(err.to_string()))
}

fn list_channels(datadir: &Path) -> Result<Vec<String>> {
    let root = datadir.join("channels");
    let mut channels = Vec::new();

    if !root.exists() {
        return Ok(channels);
    }

    collect_channels(&root, &root, &mut channels)?;
    channels.sort();
    Ok(channels)
}

fn collect_channels(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            collect_channels(root, &path, out)?;
        } else if file_type.is_file() && entry.file_name() == "log.ndjson" {
            let Some(parent) = path.parent() else {
                continue;
            };
            let rel = parent.strip_prefix(root)?;
            let channel = rel
                .components()
                .map(|component| component.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            if valid_channel(&channel) {
                out.push(channel);
            }
        }
    }
    Ok(())
}

fn tail_channel(datadir: &Path, args: TailChannelArgs) -> Result<(String, Vec<Envelope>)> {
    let chan = ChannelRef::parse(&args.channel)?;
    ensure_channel_log_exists(datadir, &chan)?;
    let messages = read_channel_tail(datadir, &chan, args.limit)?;
    Ok((chan.full_name, messages))
}

fn post_message(datadir: &Path, args: PostMessageArgs) -> Result<Value> {
    let chan = ChannelRef::parse(&args.channel)?;
    ensure_channel_log_exists(datadir, &chan)?;

    let identity_path = datadir.join("keys/identity.json");
    let keypair = KeypairFile::load(&identity_path).with_context(|| {
        format!(
            "failed to load identity keypair at {}",
            identity_path.display()
        )
    })?;
    let msg = Message::new_text(args.title, args.tags, args.body, args.refs);
    let env = Envelope::sign(keypair, &chan.full_name, msg)?;
    let id = append_message(datadir, &chan, &env)?;

    Ok(json!({
        "id": id,
        "channel": chan.full_name,
        "envelope": env
    }))
}

fn ensure_channel_log_exists(datadir: &Path, chan: &ChannelRef) -> Result<()> {
    let log_path = datadir
        .join("channels")
        .join(&chan.full_name)
        .join("log.ndjson");
    if !log_path.exists() {
        return Err(anyhow!("channel does not exist: {}", chan.full_name));
    }
    ensure_under_datadir(datadir, &log_path)?;
    Ok(())
}

fn secure_datadir(datadir: PathBuf) -> Result<PathBuf> {
    if datadir.exists() {
        datadir
            .canonicalize()
            .with_context(|| format!("canonicalize datadir {}", datadir.display()))
    } else {
        Ok(datadir)
    }
}

fn ensure_under_datadir(datadir: &Path, path: &Path) -> Result<()> {
    let datadir = if datadir.exists() {
        datadir.canonicalize()?
    } else {
        datadir.to_path_buf()
    };
    let path = if path.exists() {
        path.canonicalize()?
    } else {
        path.to_path_buf()
    };

    if !path.starts_with(&datadir) {
        return Err(anyhow!(
            "refusing to access path outside datadir: {}",
            path.display()
        ));
    }
    Ok(())
}

fn read_mcp_message<R: BufRead + Read>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut content_length: Option<usize> = None;

    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return Ok(None);
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }

        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .context("invalid Content-Length header")?,
                );
            }
        } else if trimmed.starts_with('{') {
            // Developer-friendly fallback for newline-delimited JSON during local testing.
            return Ok(Some(trimmed.as_bytes().to_vec()));
        }
    }

    let len = content_length.context("missing Content-Length header")?;
    let mut body = vec![0_u8; len];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_response<W: Write>(writer: &mut W, response: &JsonRpcResponse) -> Result<()> {
    let body = serde_json::to_vec(response)?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

fn invalid_request(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32600,
        message: message.into(),
        data: None,
    }
}

fn method_not_found(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32601,
        message: message.into(),
        data: None,
    }
}

fn invalid_params(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn tool_error(err: anyhow::Error) -> JsonRpcError {
    JsonRpcError {
        code: -32000,
        message: "Tool execution failed".to_string(),
        data: Some(json!({ "details": err.to_string() })),
    }
}
