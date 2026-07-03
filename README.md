# ZeusDNS-CLI

A stripped-down, **Windows-only** secure DNS forwarder. It runs a local DNS
server on `127.0.0.1:53` that forwards queries to an ordered list of **DoH**
and **DoT** upstreams, sets `127.0.0.1` as your system DNS while running, and
installs a WFP filter so a VPN's "block outside DNS" rule doesn't kill it.

Single binary. One command, `zeusdns`, available from any terminal.

Inspired by [ctrld](https://github.com/Control-D-Inc/ctrld) (policy engine) and
[AdGuard DNS CLI](https://github.com/AdguardTeam/AdGuardDNSCLI) (minimal
lifecycle), keeping only what makes sense on a single Windows box.

## Features

- **DoH + DoT only** — `https://host/path` and `tls://host[:853]`.
- **Ordered upstream list** with automatic failover (primary first, then
  fallbacks). Manage it interactively with `zeusdns configure`.
- **First-run TUI wizard** (`huh`) that live-validates each resolver with a test
  query — a non-responding resolver is reported and re-prompted.
- **Interactive configure menu** (`bubbletea` + `lipgloss`): add, delete,
  reorder, and test-all upstreams.
- **Auto system DNS** — sets `127.0.0.1` on start, restores your previous
  servers on stop/uninstall (persisted to `C:\ProgramData\ZeusDNS\prev_dns.json`
  so restore survives restarts/crashes).
- **WFP loopback protect** — permits loopback DNS (`127.0.0.1:53` / `[::1]:53`,
  UDP+TCP, in/out) past VPN block-outside-DNS rules, via
  [inet.af/wf](https://github.com/inetaf/wf). Rules live in a dynamic session
  and are removed automatically when the service stops.
- **Windows service** lifecycle: `install / start / stop / restart / status /
  uninstall`.
- **Self-update** from GitHub releases (`zeusdns update`).
- **Config layering**: file < env (`ZEUSDNS_*`) < CLI flags.
- **LRU + TTL cache**, structured logging, defined exit codes (`0` / `1` / `2`).

## Quick start

Run `zeusdns` from an **elevated** terminal (service install + system DNS
changes need admin):

```
> zeusdns
--- Zeus_DNS-CLI ---
Would you like to install?            (Yes / No)
Provide your DNS Resolver: DoH/DoT    https://dns.controld.com/p2
Fallback DNS Resolver (Enter empty)   tls://dns.adguard.com

Configuring...
  ✓ writing config
  ✓ installing service
  ✓ starting service
Done!!!, Enter To Exit:
```

From then on, `zeusdns` (no args) shows status. Edit upstreams any time with
`zeusdns configure`.

## Commands

```
zeusdns                       first-run setup (or status if configured)
zeusdns configure             manage upstream resolvers (TUI)
zeusdns install               install & start the Windows service
zeusdns uninstall             stop, restore system DNS, remove the service
zeusdns start | stop | restart   control the service
zeusdns status                show service + config status
zeusdns run                   run the server in the foreground (Ctrl+C)
zeusdns update                self-update from GitHub releases
zeusdns --version | -h

Flags:
  -c, --config <path>   config file (default C:\ProgramData\ZeusDNS\config.yaml)
  -v                    verbose output (also enables per-query logging)
```

## Resolver formats

| Protocol | Example |
|---|---|
| DoH | `https://dns.controld.com/p2` |
| DoH | `https://doh.pub/dns-query` |
| DoT | `tls://dns.adguard.com` (port 853 default) |
| DoT | `tls://dns.google:853` |

Other forms are rejected with a clear error.

## Configuration

`C:\ProgramData\ZeusDNS\config.yaml`:

```yaml
upstreams:
  - "https://dns.controld.com/p2"   # primary
  - "tls://dns.adguard.com"         # fallback

listener:
  ip: "127.0.0.1"
  port: 53

cache:
  size: 1024            # LRU slots, 0 disables

log:
  level: "info"         # info | verbose | debug
  path: "C:\\ProgramData\\ZeusDNS\\zeusdns.log"

windows:
  set_system_dns: true        # set 127.0.0.1 on start, restore on stop
  wfp_loopback_protect: true  # permit loopback DNS past VPN block-outside-DNS
```

Environment overrides (higher precedence than the file):

```
ZEUSDNS_UPSTREAMS="https://a.example/dns-query,tls://b.example"
ZEUSDNS_LISTENER_IP=127.0.0.1
ZEUSDNS_LISTENER_PORT=53
ZEUSDNS_CACHE_SIZE=1024
ZEUSDNS_LOG_LEVEL=debug
ZEUSDNS_LOG_PATH=...
ZEUSDNS_WINDOWS_SET_SYSTEM_DNS=true
ZEUSDNS_WINDOWS_WFP_LOOPBACK_PROTECT=true
```

CLI flags (`-c`, `-v`) override both.

## How system DNS + WFP work

On start (service or foreground `run`):

1. **Save** the current per-interface IPv4 DNS servers to `prev_dns.json`
   (via PowerShell `Get-DnsClientServerAddress`).
2. **Set** each of those interfaces to `127.0.0.1`
   (`Set-DnsClientServerAddress`).
3. **Enable WFP** loopback permit filters (dynamic session).

On stop / uninstall the reverse happens: WFP session closed (filters removed),
interfaces restored from `prev_dns.json` (or reset to DHCP if they had none).

Both steps require elevation. The service runs as `LocalSystem`, so the
service path needs no extra rights; the CLI commands that touch the system
(`install`, `uninstall`, `start`, `stop`, `run`) should be run from an elevated
terminal.

## Build

Requires Go 1.26+ (Windows, amd64 or arm64):

```
go build -ldflags "-X github.com/JustNak/ZeusDNS-CLI/cmd.Version=1.0.0" -o zeusdns.exe .
```

Test:

```
go test ./...
```

## Project layout

```
main.go              arg dispatch, service detection, usage
cmd/                 command handlers (wizard, configure, runner, lifecycle)
config/              YAML + env + flag layering, validation
dns/                 local server, DoH/DoT clients, upstream failover, cache
tui/                 huh wizard, bubbletea configure menu, lipgloss styles
windows/             system DNS set/restore (PowerShell), WFP loopback protect
service/             Windows service lifecycle (x/sys/windows/svc + mgr)
updater/             GitHub-releases self-update
internal/            exit codes, slog logger
docs/tui-preview.html   design preview of the TUI screens
```

## Notes & limitations

- **Windows-only.** The service, system-DNS, and WFP code use Windows APIs and
  won't compile/run elsewhere.
- **Admin required** for anything that changes the system (service install,
  system DNS, WFP). `status` and `configure` work without elevation.
- **WFP loopback protect is best-effort.** It adds high-weight permit filters
  for loopback DNS so the common VPN "block outside DNS" block rule doesn't
  drop traffic to `127.0.0.1:53`. Whether it fully overrides a given VPN's
  rule depends on that rule's soft/hard block semantics; it matches the
  approach used by ctrld.
- **Self-update** targets `github.com/JustNak/ZeusDNS-CLI` releases with
  assets named `zeusdns_<version>_windows_<arch>.zip` containing `zeusdns.exe`.
  Change `updater.Repo` if you publish elsewhere.
