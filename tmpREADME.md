# hellforge-capture-proxy

A standalone Linux port of [`HellForge.CaptureProxy`](https://github.com/SkyeShade/HellForge/blob/main/src/HellForge.CaptureProxy/Program.cs)
from SkyeShade/HellForge. It captures the player's own HELLDIVERS 2 inventory and progression
from the live API while the game logs in, and can seal the result for the HellForge launcher.

It is a self-contained program: HellForge does not launch it, and it does not need HellForge's
.NET runtime. It is licensed GPL-3.0-or-later, the same as the original.

## What it does

1. Resolves the real API host **before** touching DNS, then adds a marked loopback line to
   `/etc/hosts` (or the file given by `--hosts-file`).
2. Creates a per-run RSA-2048 CA and leaf certificate, installs the CA in the distribution's
   system trust store, and serves an empty signed CRL on loopback for clients that check
   revocation.
3. Listens on `127.0.0.1:443` (or `--listen-port`), terminates TLS 1.2/1.3 as the API host, and
   forwards each request unchanged to the real API by IP.
4. When the login response carries `sessionId` or `sessionToken`, it repeats the login's client
   headers and reads `GET /api/Progression` and `GET /api/Progression/inventory`.
5. Writes the inventory to `--output` and the progression to `--progression` (when given),
   optionally seals both, and records `capture-state.json` for the launcher.
6. Keeps forwarding until the game exits (or the certificate day ends), then removes the hosts
   line, the CA, and the state file. Exit code 0 means an inventory was captured and, if asked
   for, sealed.

## Requirements

- Linux (x86-64 or any Rust-supported architecture).
- Rust 1.87 or newer to build. `Cargo.lock` and `.cargo/config.toml` are part of the build; the
  MSRV-aware resolver in `.cargo/config.toml` selects dependency versions that still build on
  older toolchains. Do not delete either file.
- Root (`sudo`) for a real capture: binding port 443, editing `/etc/hosts`, and refreshing the
  system trust store all require it. A local plumbing test needs no privileges.

No OpenSSL development package is needed; TLS is implemented with `rustls` and `ring`.

## Build

```sh
cargo build --release
sudo install -m 0755 target/release/hellforge-capture-proxy /usr/local/bin/
```

## Usage

A normal capture, launched before the game:

```sh
sudo hellforge-capture-proxy \
  --progression /path/to/snapshot/progression.json \
  --output /path/to/snapshot/real-inventory.json
```

Defaults are relative to the **current working directory** (unlike the Windows build, which used
the executable's folder):

- output: `./real-inventory.json`
- evidence/log folder: `./capture`
- host: `api.live.prod.thehelldiversgame.com`
- listen port: 443
- timeout: 10 minutes

If the process runs under `sudo`, captured files and the evidence folder are handed to the
invoking user (`SUDO_UID`/`SUDO_GID`) where possible. The seal key remains root-only.

### Options

| Option | Meaning |
| --- | --- |
| `--output <file>` | Inventory file. Must be named `real-inventory.json` when sealing. |
| `--progression <file>` | Also write progression. Must be the sibling `progression.json` when sealing. |
| `--evidence <dir>` | Folder for `proxy.log` and `capture-state.json` (default `./capture`). |
| `--timeout-min <n>` | Give up after `n` minutes with nothing captured (minimum 1, default 10). |
| `--seal-key <file>` | Seal the snapshot for the given Steam account; requires `--steam-account`. |
| `--steam-account <SteamID64>` | Account the seal is for. |
| `--host <name>` | API host to impersonate (default above). |
| `--listen-port <n>` | Local TLS port (default 443). |
| `--real-ip <ip>` | Send upstream traffic to this IPv4 address instead of resolving the host. |
| `--real-port <n>` | Upstream port (default 443). Linux-only; useful for tests. |
| `--no-hosts` | Do not edit `/etc/hosts`. |
| `--no-ca` | Do not install the CA in the system trust store. |
| `--ca-out <file.pem>` | Write this run's CA certificate for manual trust. Implies a CA-signed leaf and CRL even with `--no-ca`; it does not install the CA. |
| `--hosts-file <path>` | Use another hosts file (Linux-only, for testing). |
| `--cleanup` | Remove a hosts line and trust anchors left by a run that was killed, then exit. |
| `--help`, `--version` | Usage / version. |

### Local test without system changes

This exercises TLS termination, forwarding, logging and CRL generation without root:

```sh
hellforge-capture-proxy --no-hosts --no-ca --ca-out /tmp/ca.pem \
  --listen-port 8443 --host example.com --timeout-min 1

# in another terminal
curl --cacert /tmp/ca.pem --resolve example.com:8443:127.0.0.1 \
  https://example.com:8443/
```

The run ends when the timeout expires. A plain request like this does not capture an inventory, so
the exit code is 1; `capture/proxy.log` should show the TLS version, the request and the 200.

## Sealing

`--seal-key` and `--steam-account` must be used together, and the output must be
`real-inventory.json` with an optional sibling `progression.json`. The seal payload, hashes,
JSON fields and HMAC-SHA256 are byte-for-byte compatible with the Windows `SnapshotSeal`.

The **key container is not compatible**. Windows protects a 32-byte key with machine-scoped
DPAPI, which Linux does not have. This port stores the key in a root-only (`0600`) file prefixed
with the 8-byte marker `HFLINUX1`. A `seal.key` created by the Windows tool is detected and
refused rather than overwritten; delete it deliberately or use another `--seal-key` path. As in
the original, the seal is a good-faith integrity check, not a security boundary: copying both the
snapshot and the key lets anyone verify and re-seal it.

## Trust, Wine and Proton

The CA is installed into the first usable system store:

| Distribution family | Anchor directory | Refresh command |
| --- | --- | --- |
| Debian/Ubuntu/Mint | `/usr/local/share/ca-certificates` | `update-ca-certificates` |
| Fedora/RHEL | `/etc/pki/ca-trust/source/anchors` | `update-ca-trust extract` |
| Arch | `/etc/ca-certificates/trust-source/anchors` | `trust extract-compat` |
| openSUSE | `/etc/pki/trust/anchors`, `/usr/share/pki/trust/anchors` | `update-ca-certificates` |

The anchor is named `hellforge-capture-ca.crt`; `--cleanup` removes every anchor with that prefix
from every known location.

HELLDIVERS 2 does not run natively on Linux. A game running under Wine or Proton may use its own
root store rather than the host's, so the system-wide install is not always enough. If the game
reports a certificate or connection error during login:

1. Run with `--ca-out /somewhere/ca.pem` so the CA for that run is saved (the CA changes every
   run, so export it again for each capture).
2. Import it into the game's prefix while the game is **not** running. For Proton, with the
   game's app ID:

   ```sh
   protontricks <appid> wine certutil -addstore -f Root /somewhere/ca.pem
   ```

   For plain Wine: `WINEPREFIX=... wine certutil -addstore -f Root /somewhere/ca.pem`.

3. Start the proxy, then the game. Remove the imported certificate from the prefix afterwards if
   you do not want a stale CA trusted.

Wine's use of the host store varies by build; check `capture/proxy.log` for a TLS handshake
failure to confirm this is the problem.

### Containers and network namespaces

If Steam or the game runs in a sandbox with its own network namespace (some Flatpak or container
setups), `127.0.0.1` inside that namespace is not the host's loopback, so the game cannot reach
the proxy and the hosts line has no effect. Run the proxy inside the same namespace, or give the
game host networking. The default Steam Linux Runtime normally shares the host network.

### NixOS and immutable systems

`/etc/ssl/certs` is generated from the system configuration, so writing an anchor directly is not
persistent and may not be picked up. Use `--ca-out` and add the CA through your NixOS
configuration (`security.pki.certificates` / `certificates`), or trust it in the Wine/Proton
prefix directly.

## Cleanup, state and exit codes

Normal shutdown (capture complete, timeout, or Ctrl-C/SIGTERM) removes what this run added: only
the marked hosts lines, only anchors named `hellforge-capture-ca*`, and the state file. A crash
that skips the normal path can leave the hosts line or CA behind; run:

```sh
sudo hellforge-capture-proxy --cleanup
```

`--cleanup` removes leftover hosts mappings for the configured host and every
`hellforge-capture-ca*` anchor, in every known trust-store location. It exits 0 when all steps
succeeded.

`capture-state.json` exists only while a capture is live:

```json
{"pid":12345,"sealed":false,"progression":false}
```

Exit codes:

- `0` — an inventory was captured, and the seal (when requested) succeeded.
- `1` — nothing captured before the timeout, setup failed, or the seal failed.
- `2` — bad command line.

## What is logged

`capture/proxy.log` receives the same line as the console: a per-run build and options header,
TLS version/cipher/SNI, timings, per-request method and shortened path, status, sizes, content
types, **header and query parameter names only**, JSON key/count shapes, process starts/exits, a
30-second status heartbeat and a summary. It never contains bodies, header values, query values
or the session token. Error descriptions also drop URL query strings.

The log is the first place to look when the game cannot connect: a TLS handshake failure, an
upstream connect failure (the real IP is unreachable or blocked) and a refused API response are
distinguished there.

## Differences from the Windows original

The behaviour, capture logic, seal format, log shape, timeout and exit codes follow the original.
Only the platform integration differs:

- `/etc/hosts` instead of `%SystemDirectory%\drivers\etc\hosts`.
- Distribution trust stores instead of `LocalMachine\Root`.
- `/proc` process scanning (including `helldivers2.exe` under Wine) instead of
  `Process.GetProcessesByName`.
- `resolvectl` / `systemd-resolve` / `nscd` cache flushing instead of `ipconfig /flushdns`.
- A Linux key container for sealing instead of DPAPI, as described above.
- Default paths are relative to the current directory instead of the executable's directory.
- `--ca-out`, `--hosts-file` and `--real-port` are Linux-only additions for testing and manual
  trust.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE). The original project, its capture behaviour and the
snapshot seal are by SkyeShade and the HellForge contributors:
<https://github.com/SkyeShade/HellForge>.
