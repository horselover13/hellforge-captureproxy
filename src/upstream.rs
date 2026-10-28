// The HTTP client to the real API.
//
// The hosts line points the API's name at loopback, so this client is told to connect to the
// resolved upstream addresses instead, while TLS still verifies (and presents SNI for) the real
// name. Redirects and cookies stay off, compressed responses are decoded the way
// SocketsHttpHandler's AutomaticDecompression did, and proxy environment variables are ignored:
// this traffic must go straight to the API by IP.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;

pub fn build(host: &str, addresses: &[Ipv4Addr], port: u16) -> Result<Client> {
    let sockets: Vec<SocketAddr> = addresses
        .iter()
        .map(|address| SocketAddr::new((*address).into(), port))
        .collect();
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .http1_only()
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .resolve_to_addrs(host, &sockets)
        .build()
        .context("could not build the upstream HTTP client")
}
