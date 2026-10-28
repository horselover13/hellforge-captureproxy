// A Linux reimplementation of HellForge.CaptureProxy, runnable on its own.
//
// It maps the live API's name to loopback in /etc/hosts, trusts a per-run CA in the system trust
// store (with a CRL on loopback, because a Windows client under Wine may check revocation),
// terminates the game's TLS and forwards every request unchanged to the real API by IP. With
// the session the login returns it reads GET /api/Progression and GET /api/Progression/inventory,
// repeating the login's client headers, and writes them to --progression and --output. With
// --seal-key and --steam-account it seals the two files as soon as the inventory is in and says
// so in capture-state.json. It keeps forwarding until the game exits, then removes the hosts
// line and the CA. Exit 0 only when an inventory was captured and the seal (when asked for)
// succeeded; 1 otherwise; 2 for a bad command line.

mod certs;
mod hosts;
mod log;
mod process;
mod proxy;
mod seal;
mod trust;
mod upstream;
mod util;

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

const DEFAULT_HOST: &str = "api.live.prod.thehelldiversgame.com";

#[derive(Clone)]
pub struct Options {
    pub host: String,
    pub listen_port: u16,
    pub fixed_upstream: Option<Ipv4Addr>,
    pub upstream_port: u16,
    pub output: PathBuf,
    pub progression: Option<PathBuf>,
    pub evidence: PathBuf,
    pub timeout_min: u64,
    pub manage_hosts: bool,
    pub manage_ca: bool,
    pub cleanup: bool,
    pub seal_key: Option<PathBuf>,
    pub steam_account: Option<u64>,
    pub hosts_path: PathBuf,
    pub ca_out: Option<PathBuf>,
}

impl Options {
    fn defaults() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self {
            host: DEFAULT_HOST.to_string(),
            listen_port: 443,
            fixed_upstream: None,
            upstream_port: 443,
            output: cwd.join(seal::INVENTORY_FILE),
            progression: None,
            evidence: cwd.join("capture"),
            timeout_min: 10,
            manage_hosts: true,
            manage_ca: true,
            cleanup: false,
            seal_key: None,
            steam_account: None,
            hosts_path: hosts::default_path(),
            ca_out: None,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };

    if opts.cleanup {
        let log = log::Logger::new(opts.evidence.clone());
        let hosts_ok = hosts::step_remove(&log, &opts.hosts_path, &opts.host);
        let ca_ok = trust::remove(&log);
        return ExitCode::from(if hosts_ok && ca_ok { 0 } else { 1 });
    }

    if let Err(error) = util::ensure_private_dir(&opts.evidence) {
        eprintln!("Cannot use {}: {error}", opts.evidence.display());
        return ExitCode::from(1);
    }
    let logger = log::Logger::new(opts.evidence.clone());

    if (opts.manage_hosts || opts.manage_ca) && !util::is_root() {
        let message = "editing /etc/hosts and the system trust store needs root: run with sudo, or use --no-hosts --no-ca --listen-port 8443 --real-ip <ip> for a local test";
        eprintln!("{message}");
        logger.line(message);
        return ExitCode::from(1);
    }

    let cleanup = Arc::new(Cleanup {
        opts: opts.clone(),
        log: logger.clone(),
        hosts_added: AtomicBool::new(false),
        ca_installed: AtomicBool::new(false),
        state_written: AtomicBool::new(false),
        done: AtomicBool::new(false),
    });

    ExitCode::from(serve(opts, logger, cleanup).await)
}

async fn serve(opts: Options, logger: log::Logger, cleanup: Arc<Cleanup>) -> u8 {
    log_start(&logger, &opts);

    // Resolve before the hosts line points the name at loopback; clear a line an earlier killed
    // run left first.
    if opts.manage_hosts && !hosts::step_remove(&logger, &opts.hosts_path, &opts.host) {
        return 1;
    }
    let upstream_ips = match resolve_upstream(&opts, &logger).await {
        Ok(addresses) => addresses,
        Err(()) => return 1,
    };
    logger.line(format!(
        "upstream {}",
        upstream_ips
            .iter()
            .map(|ip| format!("{ip}:{}", opts.upstream_port))
            .collect::<Vec<_>>()
            .join(", ")
    ));

    // The CA, leaf and CRL take long enough that they should not block the runtime's workers.
    let (material, mut crl_listener) =
        match prepare_certificates(&opts, &logger, cleanup.clone()).await {
            Ok(prepared) => prepared,
            Err(error) => {
                logger.line(format!("certificates failed: {}", util::describe(&error)));
                return 1;
            }
        };

    let mut server_config = match rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(material.chain, material.private_key)
    {
        Ok(config) => config,
        Err(error) => {
            logger.line(format!("TLS configuration failed: {error}"));
            return 1;
        }
    };
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_config = Arc::new(server_config);

    if let (Some(listener), Some(crl)) = (crl_listener.take(), material.crl) {
        tokio::spawn(serve_crl(listener, crl));
    }

    // Bind before the hosts line changes: if the port is taken, the game never sees a redirect.
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, opts.listen_port)).await {
        Ok(listener) => listener,
        Err(error) => {
            logger.line(format!(
                "cannot listen on 127.0.0.1:{}: {error}",
                opts.listen_port
            ));
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                logger.line("port 443 needs root or CAP_NET_BIND_SERVICE; --listen-port 8443 works unprivileged");
            }
            return 1;
        }
    };

    let http = match upstream::build(&opts.host, &upstream_ips, opts.upstream_port) {
        Ok(client) => client,
        Err(error) => {
            logger.line(format!("HTTP client failed: {}", util::describe(&error)));
            return 1;
        }
    };

    let cancel = CancellationToken::new();
    let (deadline, deadline_rx) = watch::channel(
        tokio::time::Instant::now() + Duration::from_secs(opts.timeout_min.saturating_mul(60)),
    );
    tokio::spawn(deadline_watcher(deadline_rx, cancel.clone()));

    let ctx = Arc::new(proxy::Ctx {
        opts: opts.clone(),
        log: logger.clone(),
        http,
        tally: Mutex::new(log::Tally::default()),
        connections: AtomicU64::new(0),
        last_request: Mutex::new(Instant::now()),
        captured: AtomicBool::new(false),
        seal_ok: AtomicBool::new(false),
        login_headers: Mutex::new(None),
        deadline,
        cancel: cancel.clone(),
    });

    spawn_signal_handler(logger.clone(), cleanup.clone());

    if opts.manage_hosts {
        cleanup.hosts_added.store(true, Ordering::Release);
        if !hosts::step_add(&logger, &opts.hosts_path, &opts.host) {
            return 1;
        }
    }

    log_resolution(&logger, &opts.host).await;
    logger.line(format!("listening on port {}", opts.listen_port));

    // Written once the capture listens (the launcher then opens the game). The redirect is in
    // place by now, so a game started on this signal cannot slip past it.
    cleanup.state_written.store(true, Ordering::Release);
    if let Err(error) = log::write_state(&opts.evidence, std::process::id(), false, false) {
        logger.line(format!("state failed: {error}"));
    }

    tokio::spawn(watch_processes(ctx.clone()));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((socket, peer)) => {
                    ctx.note_connection();
                    let connection = ctx.clone();
                    let config = server_config.clone();
                    tokio::spawn(async move {
                        proxy::handle(socket, peer, connection, config).await;
                    });
                }
                Err(error) => {
                    logger.line(format!("accept failed: {error}"));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    cleanup.run();
    let captured = ctx.captured.load(Ordering::Acquire);
    logger.line(if captured {
        "capture complete"
    } else {
        "nothing captured"
    });
    log_summary(&logger, &ctx);
    if captured && ctx.seal_ok.load(Ordering::Acquire) {
        0
    } else {
        1
    }
}

fn log_start(logger: &log::Logger, opts: &Options) {
    let built = std::env::current_exe()
        .ok()
        .and_then(|path| fs::metadata(path).ok())
        .and_then(|metadata| metadata.modified().ok())
        .map(util::utc_seconds)
        .unwrap_or_else(|| "unknown".to_string());
    logger.line(format!(
        "capture built {built}, {} / {}, rust {} {}, elevated {}",
        util::os_pretty_name(),
        util::kernel_release(),
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        if util::is_root() { "yes" } else { "no" }
    ));
    logger.line(format!(
        "options: host {}, port {}, timeout {} min, hosts line {}, CA {}, progression {}, seal {}",
        opts.host,
        opts.listen_port,
        opts.timeout_min,
        if opts.manage_hosts { "yes" } else { "no" },
        if opts.manage_ca { "yes" } else { "no" },
        if opts.progression.is_some() {
            "yes"
        } else {
            "no"
        },
        if opts.seal_key.is_some() { "yes" } else { "no" }
    ));
}

async fn resolve_upstream(opts: &Options, logger: &log::Logger) -> Result<Vec<Ipv4Addr>, ()> {
    if let Some(address) = opts.fixed_upstream {
        return Ok(vec![address]);
    }
    match tokio::net::lookup_host((opts.host.as_str(), opts.upstream_port)).await {
        Ok(addresses) => {
            let addresses: Vec<Ipv4Addr> = addresses
                .filter_map(|address| match address.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(_) => None,
                })
                .collect();
            if addresses.is_empty() {
                logger.line(format!("no IPv4 address for {}", opts.host));
                Err(())
            } else {
                Ok(addresses)
            }
        }
        Err(error) => {
            logger.line(format!("could not resolve {}: {error}", opts.host));
            Err(())
        }
    }
}

async fn prepare_certificates(
    opts: &Options,
    logger: &log::Logger,
    cleanup: Arc<Cleanup>,
) -> Result<(certs::Material, Option<TcpListener>)> {
    // --ca-out asks for a CA to import by hand even when this run does not install one.
    let uses_ca = opts.manage_ca || opts.ca_out.is_some();
    if !uses_ca {
        let host = opts.host.clone();
        let material = tokio::task::spawn_blocking(move || certs::generate(&host, None))
            .await
            .context("certificate task failed")??;
        return Ok((material, None));
    }

    let crl_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .context("cannot bind the CRL server")?;
    let port = crl_listener.local_addr()?.port();
    let url = format!("http://127.0.0.1:{port}/ca-{}.crl", certs::crl_token());
    let host = opts.host.clone();
    let build_url = url.clone();
    let material = tokio::task::spawn_blocking(move || certs::generate(&host, Some(&build_url)))
        .await
        .context("certificate task failed")??;
    let pem = material
        .ca_pem
        .clone()
        .context("the managed certificate has no CA")?;

    if let Some(path) = opts.ca_out.as_ref() {
        certs::write_pem(path, &pem)?;
        util::give_to_sudo_user(path);
        logger.line(format!("CA exported to {}", path.display()));
    }

    logger.line(certs::describe_material(&material));
    if opts.manage_ca {
        cleanup.ca_installed.store(true, Ordering::Release);
        trust::install(&pem, logger)?;
    }
    Ok((material, Some(crl_listener)))
}

/// One CRL URL for the whole run. A client that checks revocation gets an empty, signed list;
/// one that does not, never asks.
async fn serve_crl(listener: TcpListener, crl: Vec<u8>) {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        crl.len()
    );
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(_) => return,
        };
        let task_head = head.clone();
        let task_crl = crl.clone();
        tokio::spawn(async move {
            let mut request = [0u8; 2048];
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::io::AsyncReadExt::read(&mut stream, &mut request),
            )
            .await;
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, task_head.as_bytes()).await;
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, &task_crl).await;
        });
    }
}

async fn deadline_watcher(
    mut deadline: watch::Receiver<tokio::time::Instant>,
    cancel: CancellationToken,
) {
    loop {
        let when = *deadline.borrow_and_update();
        tokio::select! {
            _ = tokio::time::sleep_until(when) => {
                if *deadline.borrow() == when {
                    cancel.cancel();
                    break;
                }
            }
            changed = deadline.changed() => {
                if changed.is_err() {
                    break;
                }
            }
        }
    }
}

fn spawn_signal_handler(logger: log::Logger, cleanup: Arc<Cleanup>) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let Ok(mut interrupt) = signal(SignalKind::interrupt()) else {
            return;
        };
        let Ok(mut terminate) = signal(SignalKind::terminate()) else {
            return;
        };
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        logger.line("interrupted");
        cleanup.run();
        std::process::exit(1);
    });
}

async fn watch_processes(ctx: Arc<proxy::Ctx>) {
    let mut seen: std::collections::BTreeMap<i32, String> = std::collections::BTreeMap::new();
    let mut beat = Instant::now();
    loop {
        let now = process::snapshot();
        for (pid, name) in now.iter().filter(|(pid, _)| !seen.contains_key(pid)) {
            ctx.log.line(format!("process {name} started (pid {pid})"));
        }
        for (pid, name) in seen.iter().filter(|(pid, _)| !now.contains_key(pid)) {
            ctx.log.line(format!("process {name} exited (pid {pid})"));
        }
        seen = now;
        if beat.elapsed() >= Duration::from_secs(30) {
            beat = Instant::now();
            let game = seen
                .values()
                .any(|name| name.eq_ignore_ascii_case(process::GAME_PROCESS));
            ctx.log.line(format!(
                "status: {} connections, {} requests, last connection {} s ago, game {}, captured {}",
                ctx.connections.load(Ordering::Relaxed),
                ctx.tally_total(),
                ctx.seconds_since_last_connection(),
                if game { "running" } else { "not running" },
                if ctx.captured.load(Ordering::Acquire) {
                    "yes"
                } else {
                    "no"
                }
            ));
        }
        tokio::select! {
            _ = ctx.cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
    }
}

async fn log_resolution(logger: &log::Logger, host: &str) {
    match tokio::net::lookup_host((host, 0)).await {
        Ok(addresses) => logger.line(format!(
            "system DNS: {host} -> {}",
            addresses
                .map(|address| address.ip().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
        Err(error) => logger.line(format!("system DNS: {host} does not resolve: {error}")),
    }
}

fn log_summary(logger: &log::Logger, ctx: &proxy::Ctx) {
    let tally = ctx
        .tally
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    logger.line(format!(
        "summary: {} connections, {} requests answered by the API",
        ctx.connections.load(Ordering::Relaxed),
        tally.total()
    ));
    for line in tally.lines() {
        logger.line(format!("  {line}"));
    }
}

/// Cleanup runs once, whether from the normal path, a signal, or a panic.
struct Cleanup {
    opts: Options,
    log: log::Logger,
    hosts_added: AtomicBool,
    ca_installed: AtomicBool,
    state_written: AtomicBool,
    done: AtomicBool,
}

impl Cleanup {
    fn run(&self) {
        if self.done.swap(true, Ordering::SeqCst) {
            return;
        }
        if self.opts.manage_hosts && self.hosts_added.load(Ordering::Acquire) {
            hosts::step_remove(&self.log, &self.opts.hosts_path, &self.opts.host);
        }
        if self.opts.manage_ca && self.ca_installed.load(Ordering::Acquire) {
            trust::remove(&self.log);
        }
        if self.state_written.load(Ordering::Acquire) {
            let path = self.opts.evidence.join(log::STATE_FILE);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => self.log.line(format!("state cleanup failed: {error}")),
            }
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.run();
    }
}

fn parse_args() -> Result<Options, String> {
    let mut opts = Options::defaults();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value."));
        match arg.as_str() {
            "--host" => opts.host = value(&arg)?,
            "--listen-port" => {
                opts.listen_port = value(&arg)?
                    .parse()
                    .map_err(|_| format!("invalid --listen-port: {arg}"))?
            }
            "--real-ip" => {
                opts.fixed_upstream = Some(
                    value(&arg)?
                        .parse()
                        .map_err(|_| format!("invalid --real-ip: {arg}"))?,
                )
            }
            "--real-port" => {
                opts.upstream_port = value(&arg)?
                    .parse()
                    .map_err(|_| format!("invalid --real-port: {arg}"))?
            }
            "--output" => opts.output = PathBuf::from(value(&arg)?),
            "--progression" => opts.progression = Some(PathBuf::from(value(&arg)?)),
            "--evidence" => opts.evidence = PathBuf::from(value(&arg)?),
            "--timeout-min" => {
                opts.timeout_min = value(&arg)?
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --timeout-min: {arg}"))?
                    .max(1)
            }
            "--seal-key" => opts.seal_key = Some(PathBuf::from(value(&arg)?)),
            "--steam-account" => {
                opts.steam_account = Some(
                    value(&arg)?
                        .parse::<u64>()
                        .map_err(|_| format!("invalid --steam-account: {arg}"))?,
                )
            }
            "--hosts-file" => opts.hosts_path = PathBuf::from(value(&arg)?),
            "--ca-out" => opts.ca_out = Some(PathBuf::from(value(&arg)?)),
            "--no-hosts" => opts.manage_hosts = false,
            "--no-ca" => opts.manage_ca = false,
            "--cleanup" => opts.cleanup = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("hellforge-capture-proxy {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => return Err(format!("Unknown argument: {other}")),
        }
    }

    if opts.seal_key.is_some() != opts.steam_account.is_some() {
        return Err("--seal-key and --steam-account go together.".to_string());
    }
    if opts.seal_key.is_some() {
        let output_is_inventory = opts
            .output
            .file_name()
            .map(|name| name == seal::INVENTORY_FILE)
            .unwrap_or(false);
        if !output_is_inventory {
            return Err(format!(
                "A sealed capture writes {} and {} in one folder.",
                seal::INVENTORY_FILE,
                seal::PROGRESSION_FILE
            ));
        }
        if let Some(progression) = opts.progression.as_ref() {
            let folder = absolute(&opts.output)
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            if absolute(progression) != folder.join(seal::PROGRESSION_FILE) {
                return Err(format!(
                    "A sealed capture writes {} and {} in one folder.",
                    seal::INVENTORY_FILE,
                    seal::PROGRESSION_FILE
                ));
            }
        }
    }
    Ok(opts)
}

fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn print_help() {
    println!("hellforge-capture-proxy [--output <file>] [--progression <file>] [--evidence <dir>] [--timeout-min <n>]");
    println!("  [--seal-key <file> --steam-account <SteamID64>] [--host <name>] [--listen-port <n>] [--real-ip <ip>]");
    println!("  [--no-hosts] [--no-ca] [--ca-out <file.pem>] [--hosts-file <path>] | --cleanup");
    println!();
    println!(
        "The default output is ./real-inventory.json and the default evidence folder ./capture."
    );
    println!("Managing /etc/hosts or the system trust store needs root (sudo).");
    println!("Exit codes: 0 captured (and sealed when asked), 1 nothing captured or setup failed, 2 bad arguments.");
}
