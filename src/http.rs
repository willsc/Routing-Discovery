//! Read-only status/metrics endpoint: GET only, bounded request size and time.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::error::{backend_err, Error, Result};

const LIMIT: usize = 8192;
const IO_TIMEOUT: Duration = Duration::from_secs(2);

pub trait StatusSource: Send + Sync + 'static {
    /// JSON status; must contain boolean `live` and `ready` fields.
    fn snapshot(&self) -> Value;
    fn metrics(&self) -> String;
}

pub async fn serve(listener: TcpListener, source: Arc<dyn StatusSource>, stop: CancellationToken) {
    loop {
        tokio::select! {
            _ = stop.cancelled() => return,
            accepted = listener.accept() => {
                if let Ok((stream, _)) = accepted {
                    tokio::spawn(handle(stream, source.clone()));
                }
            }
        }
    }
}

async fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 || buffer.len() + n > LIMIT {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
    Some(buffer)
}

fn respond(source: &dyn StatusSource, head: &[u8]) -> (u16, &'static str, String) {
    let line = head.split(|b| *b == b'\r').next().unwrap_or_default();
    let parts: Vec<&str> = std::str::from_utf8(line).unwrap_or_default().split_whitespace().collect();
    if parts.len() != 3 || parts[0] != "GET" {
        return (405, "text/plain", "GET only\n".into());
    }
    match parts[1] {
        "/metrics" => (200, "text/plain; version=0.0.4", source.metrics()),
        path @ ("/healthz" | "/readyz" | "/status") => {
            let snap = source.snapshot();
            let flag = |key: &str| snap.get(key).and_then(Value::as_bool).unwrap_or(false);
            let failing = (path == "/healthz" && !flag("live")) || (path == "/readyz" && !flag("ready"));
            (if failing { 503 } else { 200 }, "application/json", snap.to_string())
        }
        _ => (404, "text/plain", "not found\n".into()),
    }
}

async fn handle(mut stream: TcpStream, source: Arc<dyn StatusSource>) {
    let Ok(Some(head)) = tokio::time::timeout(IO_TIMEOUT, read_head(&mut stream)).await else { return };
    let (code, content, body) = respond(source.as_ref(), &head);
    let reason = if code == 200 { "OK" } else { "Error" };
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::time::timeout(IO_TIMEOUT, async {
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await
    })
    .await;
}

/// Minimal client for `route-discovery status`: plain http://host:port/path only.
pub async fn get(url: &str) -> Result<String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| Error::Config("status URL must start with http://".into()))?;
    let (authority, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}")));
    let exchange = async {
        let mut stream = TcpStream::connect(authority).await?;
        stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };
    let response = tokio::time::timeout(Duration::from_secs(3), exchange)
        .await
        .map_err(|_| Error::Backend(format!("{url}: timed out")))??;
    let text = String::from_utf8_lossy(&response);
    let Some((head, body)) = text.split_once("\r\n\r\n") else { return backend_err(format!("{url}: malformed response")) };
    let status = head.split_whitespace().nth(1).unwrap_or_default();
    if status != "200" {
        return backend_err(format!("HTTP Error {status}: {}", body.trim()));
    }
    Ok(body.to_string())
}
