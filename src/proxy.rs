// One TLS connection, one HTTP/1.1 request (the response says Connection: close).
//
// Everything the game sends is forwarded unchanged except hop-by-hop headers; the API's answer
// is returned with Content-Length and Connection: close. While that happens, the login's
// session is used to read progression and inventory, which are sealed and announced through
// the state file; then forwarding continues until the game exits.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::{Client, Method, StatusCode, Version};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::LazyConfigAcceptor;
use tokio_util::sync::CancellationToken;

use crate::log::{
    self, is_capture_path, json_shape, names, query_names, shorten, Logger, Tally, INVENTORY_PATH,
    LOGIN_PATH, PROGRESSION_PATH,
};
use crate::process;
use crate::seal;
use crate::util;
use crate::Options;

const MAX_HEAD: usize = 65_536;
const MAX_BODY: usize = 1 << 20;
const FORWARD_HOURS_AT_MOST: u64 = 12;

const SKIP_REQUEST: &[&str] = &[
    "Host",
    "Connection",
    "Content-Length",
    "Content-Type",
    "Transfer-Encoding",
    "Accept-Encoding",
    "Expect",
    "Proxy-Connection",
    "Upgrade",
    "TE",
];
const SKIP_RESPONSE: &[&str] = &[
    "Transfer-Encoding",
    "Connection",
    "Keep-Alive",
    "Content-Length",
    "Content-Encoding",
];

pub struct Ctx {
    pub opts: Options,
    pub log: Logger,
    pub http: Client,
    pub tally: Mutex<Tally>,
    pub connections: AtomicU64,
    pub last_request: Mutex<Instant>,
    pub captured: AtomicBool,
    pub seal_ok: AtomicBool,
    pub login_headers: Mutex<Option<Vec<(String, String)>>>,
    pub deadline: watch::Sender<tokio::time::Instant>,
    pub cancel: CancellationToken,
}

impl Ctx {
    pub fn extend_deadline(&self, after: Duration) {
        let _ = self.deadline.send(tokio::time::Instant::now() + after);
    }

    pub fn note_connection(&self) {
        *self
            .last_request
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
    }

    fn tally_add(&self, method: &str, path: &str, status: u16) {
        self.tally
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .add(method, path, status);
    }

    pub fn tally_total(&self) -> u64 {
        self.tally
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .total()
    }

    pub fn seconds_since_last_connection(&self) -> u64 {
        self.last_request
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .elapsed()
            .as_secs()
    }

    fn log_request(&self, id: &str, request: &Request, path: &str) {
        let content_type = header(&request.headers, "Content-Type")
            .map(|value| value.split(';').next().unwrap_or("").trim())
            .unwrap_or("none");
        let host = header(&request.headers, "Host").unwrap_or("no host");
        self.log.line(format!(
            "{id} {} {} {}, body {} bytes ({}); headers: {}; query: {}",
            request.method,
            shorten(path),
            host,
            request.body.len(),
            content_type,
            names(request.headers.iter().map(|(name, _)| name.as_str())),
            query_names(&request.target)
        ));
    }

    fn log_response(&self, id: &str, path: &str, response: ResponseLog<'_>) {
        let ResponseLog {
            status,
            reason,
            version,
            headers,
            body,
            asked,
        } = response;
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or("").trim())
            .unwrap_or("none");
        self.log.line(format!(
            "{id} -> {} {} {:?}, {} bytes ({}) in {}; headers: {}",
            status.as_u16(),
            reason,
            version,
            body.len(),
            content_type,
            milliseconds(asked),
            names(headers.keys().map(|name| name.as_str()))
        ));
        if !status.is_success() {
            self.log
                .line(format!("  refused: {}", log::error_text(body)));
        } else if is_capture_path(path) {
            self.log
                .line(format!("{id} body shape: {}", json_shape(body)));
        }
    }

    async fn capture(self: &Arc<Self>, path: &str, body: &[u8]) {
        if self.captured.load(Ordering::Acquire) {
            return;
        }
        let result = if path.eq_ignore_ascii_case(LOGIN_PATH) {
            self.read_account(body).await
        } else if path.eq_ignore_ascii_case(PROGRESSION_PATH) {
            self.save_progression(body)
        } else if path.eq_ignore_ascii_case(INVENTORY_PATH) {
            self.save_inventory(body)
        } else {
            Ok(())
        };
        if let Err(error) = result {
            self.log
                .line(format!("capture failed: {}", util::describe(&error)));
        }
    }

    /// The login's session reads what the game reads next: progression first, since the
    /// capture ends with the inventory.
    async fn read_account(self: &Arc<Self>, login_response: &[u8]) -> Result<()> {
        let login: Value = match serde_json::from_slice(login_response) {
            Ok(value) => value,
            Err(_) => {
                self.log.line("login response is not JSON");
                return Ok(());
            }
        };
        let session = login
            .get("sessionId")
            .and_then(Value::as_str)
            .or_else(|| login.get("sessionToken").and_then(Value::as_str))
            .filter(|session| !session.is_empty());
        let Some(session) = session else {
            self.log.line("login response has no session");
            return Ok(());
        };
        if self.opts.progression.is_some() {
            if let Some(progression) = self.get(PROGRESSION_PATH, session).await? {
                self.save_progression(&progression)?;
            }
        }
        if let Some(inventory) = self.get(INVENTORY_PATH, session).await? {
            self.save_inventory(&inventory)?;
        }
        Ok(())
    }

    async fn get(&self, path: &str, session: &str) -> Result<Option<Vec<u8>>> {
        let url = format!("https://{}{}", self.opts.host, path);
        let read_headers = read_headers(
            self.login_headers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref(),
            SystemTime::now(),
        );
        let mut builder = self
            .http
            .get(&url)
            .header("Authorization", format!("session {session}"));
        for (name, value) in &read_headers {
            let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) else {
                continue;
            };
            builder = builder.header(name, value);
        }
        let asked = Instant::now();
        let response = builder.send().await?;
        let status = response.status();
        let version = response.version();
        let response_headers = response.headers().clone();
        let body = response.bytes().await?.to_vec();
        self.log.line(format!(
            "GET {path} {} {} bytes (login session)",
            status.as_u16(),
            body.len()
        ));
        let mut sent: Vec<&str> = vec!["Authorization"];
        sent.extend(read_headers.iter().map(|(name, _)| name.as_str()));
        self.log
            .line(format!("capture GET {path}: sent headers {}", names(sent)));
        self.log_response(
            "capture",
            path,
            ResponseLog {
                status,
                reason: status.canonical_reason().unwrap_or(""),
                version,
                headers: &response_headers,
                body: &body,
                asked,
            },
        );
        Ok(status.is_success().then_some(body))
    }

    fn save_progression(&self, body: &[u8]) -> Result<()> {
        let Some(path) = self.opts.progression.as_ref() else {
            return Ok(());
        };
        if !json_object_with(body, None) {
            self.log.line("progression response is not an object");
            return Ok(());
        }
        util::write_atomic(path, body)?;
        self.log.line("progression saved");
        Ok(())
    }

    fn save_inventory(self: &Arc<Self>, body: &[u8]) -> Result<()> {
        if !json_object_with(body, Some("items")) {
            self.log.line("inventory response has no items list");
            return Ok(());
        }
        if self
            .captured
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        if let Err(error) = util::write_atomic(&self.opts.output, body) {
            // A later inventory may still be saved.
            self.captured.store(false, Ordering::Release);
            return Err(error.into());
        }
        self.log.line("inventory saved");
        self.complete_capture();
        Ok(())
    }

    /// Once the inventory is in: seal what was captured and tell the launcher, then keep
    /// forwarding until the game exits.
    fn complete_capture(self: &Arc<Self>) {
        let progression = self
            .opts
            .progression
            .as_ref()
            .map(|path| path.exists())
            .unwrap_or(false);
        let seal_ok = match (self.opts.seal_key.as_ref(), self.opts.steam_account) {
            (Some(key_path), Some(account)) => {
                let folder = self
                    .opts
                    .output
                    .parent()
                    .map(|parent| parent.to_path_buf())
                    .unwrap_or_else(|| self.opts.output.clone());
                match seal::write(&folder, key_path, account, SystemTime::now()) {
                    Ok(()) => true,
                    Err(error) => {
                        self.log.line(format!("seal failed: {error}"));
                        false
                    }
                }
            }
            _ => true,
        };
        self.seal_ok.store(seal_ok, Ordering::Release);
        if self.opts.seal_key.is_some() && seal_ok {
            self.log.line(format!(
                "capture sealed{}",
                if progression {
                    ""
                } else {
                    " without progression"
                }
            ));
        }
        if let Err(error) = log::write_state(
            &self.opts.evidence,
            std::process::id(),
            seal_ok,
            progression,
        ) {
            self.log.line(format!("state failed: {error}"));
        }
        let me = self.clone();
        tokio::spawn(async move { me.forward_until_game_exits().await });
    }

    /// The redirect and the CA stay until the game exits, so its requests after the login still
    /// reach the API; never past the certificates' day.
    async fn forward_until_game_exits(self: Arc<Self>) {
        self.extend_deadline(Duration::from_secs(FORWARD_HOURS_AT_MOST * 3600));
        self.log.line("forwarding until the game exits");
        loop {
            if !process::is_game_running() {
                self.log.line("game exited");
                break;
            }
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    self.log.line(format!("still forwarding after {FORWARD_HOURS_AT_MOST} hours: stopping"));
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
        }
        self.cancel.cancel();
    }
}

pub async fn handle(
    socket: TcpStream,
    peer: std::net::SocketAddr,
    ctx: Arc<Ctx>,
    server_config: Arc<rustls::ServerConfig>,
) {
    let id = format!("#{}", ctx.connections.fetch_add(1, Ordering::SeqCst) + 1);
    let watch = Instant::now();
    ctx.log.line(format!("{id} connection from {peer}"));

    let start = match LazyConfigAcceptor::new(rustls::server::Acceptor::default(), socket).await {
        Ok(start) => start,
        Err(error) => {
            ctx.log.line(format!(
                "{id} TLS handshake failed after {}: {}",
                milliseconds(watch),
                util::describe_io(&error)
            ));
            return;
        }
    };
    let sni = start
        .client_hello()
        .server_name()
        .map(|name| name.to_string());
    let mut tls = match start.into_stream(server_config).await {
        Ok(tls) => tls,
        Err(error) => {
            ctx.log.line(format!(
                "{id} TLS handshake failed after {}: {}",
                milliseconds(watch),
                util::describe_io(&error)
            ));
            return;
        }
    };
    ctx.log.line(format!(
        "{id} TLS {} in {}",
        tls_description(&tls, sni.as_deref()),
        milliseconds(watch)
    ));

    let request = match read_request(&mut tls).await {
        Ok(Some(request)) => request,
        Ok(None) => {
            ctx.log.line(format!(
                "{id} closed before a whole request ({})",
                milliseconds(watch)
            ));
            return;
        }
        Err(error) => {
            ctx.log.line(format!(
                "{id} failed while reading the request after {}: {}",
                milliseconds(watch),
                util::describe_io(&error)
            ));
            return;
        }
    };
    let path = request.target.split('?').next().unwrap_or("").to_string();
    if path.eq_ignore_ascii_case(LOGIN_PATH) {
        *ctx.login_headers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(request.headers.clone());
    }
    ctx.log_request(&id, &request, &path);

    let asked = Instant::now();
    let response = match send_upstream(&ctx, &request).await {
        Ok(response) => response,
        Err(error) => {
            ctx.log.line(format!(
                "{id} failed while asking the API after {}: {}",
                milliseconds(watch),
                util::describe(&error)
            ));
            return;
        }
    };
    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("").to_string();
    let version = response.version();
    let response_headers = response.headers().clone();
    let response_body = match response.bytes().await {
        Ok(body) => body.to_vec(),
        Err(error) => {
            let error = anyhow::Error::new(error);
            ctx.log.line(format!(
                "{id} failed while asking the API after {}: {}",
                milliseconds(watch),
                util::describe(&error)
            ));
            return;
        }
    };
    ctx.tally_add(&request.method, &shorten(&path), status.as_u16());
    ctx.log.line(format!(
        "{} {} {} {} bytes",
        request.method,
        shorten(&path),
        status.as_u16(),
        response_body.len()
    ));
    ctx.log_response(
        &id,
        &path,
        ResponseLog {
            status,
            reason: &reason,
            version,
            headers: &response_headers,
            body: &response_body,
            asked,
        },
    );

    if status.is_success() {
        ctx.capture(&path, &response_body).await;
    }

    if let Err(error) = respond(&mut tls, status, &reason, &response_headers, &response_body).await
    {
        ctx.log.line(format!(
            "{id} failed while answering the game after {}: {}",
            milliseconds(watch),
            util::describe_io(&error)
        ));
        return;
    }
    check_reuse(&mut tls, &id, &ctx).await;
    ctx.log
        .line(format!("{id} done in {}", milliseconds(watch)));
}

fn tls_description(tls: &TlsStream<TcpStream>, sni: Option<&str>) -> String {
    let (_, connection) = tls.get_ref();
    let version = match connection.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3".to_string(),
        Some(other) => format!("{other:?}"),
        None => "no tls".to_string(),
    };
    let cipher = connection
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .unwrap_or_else(|| "no cipher".to_string());
    let alpn = connection
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
        .unwrap_or_else(|| "no alpn".to_string());
    let sni = sni
        .map(|name| format!("sni {name}"))
        .unwrap_or_else(|| "no sni".to_string());
    format!("{version} {cipher} {alpn}, {sni}")
}

#[derive(Debug, Clone)]
struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Everything log_response needs, kept together so the signature stays readable.
struct ResponseLog<'a> {
    status: StatusCode,
    reason: &'a str,
    version: Version,
    headers: &'a HeaderMap,
    body: &'a [u8],
    asked: Instant,
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .rev()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// One HTTP/1.1 request. Chunked bodies are refused (the game does not send them), bodies are
/// capped at 1 MiB and the head at 64 KiB, as in the original.
async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
    ssl: &mut S,
) -> std::io::Result<Option<Request>> {
    let mut buffer: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let header_end;
    loop {
        if buffer.len() >= MAX_HEAD {
            return Ok(None);
        }
        let read = ssl.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(at) = find_subsequence(&buffer, b"\r\n\r\n") {
            header_end = at;
            break;
        }
    }

    let head = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method.is_empty() || target.is_empty() || version.is_empty() {
        return Ok(None);
    }
    let mut headers = Vec::new();
    for line in lines {
        if let Some(colon) = line.find(':') {
            if colon > 0 {
                headers.push((
                    line[..colon].trim().to_string(),
                    line[colon + 1..].trim().to_string(),
                ));
            }
        }
    }
    if header(&headers, "Transfer-Encoding").is_some() {
        return Ok(None);
    }
    if header(&headers, "Expect")
        .map(|value| value.to_ascii_lowercase().contains("100-continue"))
        .unwrap_or(false)
    {
        ssl.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
    }
    let length = header(&headers, "Content-Length")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length <= MAX_BODY)
        .unwrap_or(0);
    let body_start = header_end + 4;
    let available = buffer.len().saturating_sub(body_start);
    let mut body = Vec::with_capacity(length);
    body.extend_from_slice(&buffer[body_start..body_start + available.min(length)]);
    while body.len() < length {
        let wanted = (length - body.len()).min(chunk.len());
        let read = ssl.read(&mut chunk[..wanted]).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(Some(Request {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        body,
    }))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn send_upstream(ctx: &Ctx, request: &Request) -> Result<reqwest::Response> {
    let method = Method::from_bytes(request.method.as_bytes()).context("invalid method")?;
    let url = format!("https://{}{}", ctx.opts.host, request.target);
    let mut builder = ctx.http.request(method.clone(), &url);
    for (name, value) in &request.headers {
        if SKIP_REQUEST
            .iter()
            .any(|skipped| name.eq_ignore_ascii_case(skipped))
        {
            continue;
        }
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) else {
            continue;
        };
        builder = builder.header(name, value);
    }
    if !request.body.is_empty() || method == Method::POST || method == Method::PUT {
        if let Some(content_type) = header(&request.headers, "Content-Type") {
            if let Ok(value) = HeaderValue::from_bytes(content_type.as_bytes()) {
                builder = builder.header(CONTENT_TYPE, value);
            }
        }
        builder = builder.body(request.body.clone());
    }
    Ok(builder.send().await?)
}

async fn respond<S: AsyncWrite + Unpin>(
    ssl: &mut S,
    status: StatusCode,
    reason: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> std::io::Result<()> {
    let mut head = Vec::with_capacity(512);
    head.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason).as_bytes());
    for (name, value) in headers {
        if SKIP_RESPONSE
            .iter()
            .any(|skipped| name.as_str().eq_ignore_ascii_case(skipped))
        {
            continue;
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    ssl.write_all(&head).await?;
    ssl.write_all(body).await?;
    ssl.flush().await?;
    Ok(())
}

/// A client that expected keep-alive sends on this connection and loses that request; the log
/// says so, so a capture that needs a second try can be understood.
async fn check_reuse<S: AsyncRead + Unpin>(ssl: &mut S, id: &str, ctx: &Ctx) {
    let mut probe = [0u8; 1];
    match timeout(Duration::from_millis(300), ssl.read(&mut probe)).await {
        Err(_) => ctx
            .log
            .line(format!("{id} client kept the connection open after the response")),
        Ok(Ok(0)) => ctx.log.line(format!("{id} client closed after the response")),
        Ok(Ok(_)) => ctx.log.line(format!(
            "{id} client sent more on this connection after Connection: close (keep-alive is not supported)"
        )),
        Ok(Err(error)) => ctx.log.line(format!(
            "{id} connection reset after the response: {}",
            util::describe_io(&error)
        )),
    }
}

fn json_object_with(body: &[u8], required_array: Option<&str>) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    let Value::Object(object) = value else {
        return false;
    };
    required_array
        .map(|name| object.get(name).map(Value::is_array).unwrap_or(false))
        .unwrap_or(true)
}

/// The headers the login carried, repeated on the capture's own reads (CaptureHeaders).
/// The API refuses a read without Accept-Language.
fn read_headers(login: Option<&Vec<(String, String)>>, now: SystemTime) -> Vec<(String, String)> {
    let value = |name: &str| {
        login
            .and_then(|headers| header(headers, name))
            .filter(|value| !value.trim().is_empty())
    };
    let mut headers = vec![
        ("Accept".to_string(), "application/json".to_string()),
        (
            "Accept-Language".to_string(),
            value("Accept-Language").unwrap_or("en-US").to_string(),
        ),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("ct".to_string(), util::microseconds_since_epoch(now)),
    ];
    if let Some(agent) = value("User-Agent") {
        headers.push(("User-Agent".to_string(), agent.to_string()));
    }
    headers
}

fn milliseconds(watch: Instant) -> String {
    format!("{} ms", watch.elapsed().as_millis())
}
