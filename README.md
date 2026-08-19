# DataDome Solver

Go library, CLI, and local HTTP server that solves the DataDome `api-js` telemetry flow and returns a
valid `datadome` cookie. Chrome-151 fingerprint + uTLS (JA3/JA4 match) + HTTP/2. Aligned to live
tags.js **5.9.2**. Codec seeds are unchanged from 5.9.0 / 5.7.0.

Changelog: **[v5.7.0 → v5.9.0 → v5.9.2](CHANGELOG.md)**.

```bash
git clone https://github.com/buggerlogger/datadome-solver.git
cd datadome-solver/go
```

## Quick start

```bash
cd go

go build -o datadome-server ./cmd/server/
go build -o datadome        ./cmd/datadome/

./datadome-server -addr 127.0.0.1:8080

curl -s http://127.0.0.1:8080/solve \
  -H 'content-type: application/json' \
  -d '{"ddk":"YOUR_DDK","site":"https://your-target.example","verify":true}'

curl -s http://127.0.0.1:8080/solve \
  -H 'content-type: application/json' \
  -H 'Proxy: geo.iproyal.com:12321:username:password' \
  -d '{"ddk":"YOUR_DDK","site":"https://your-target.example","verify":true}'
```

```json
{
  "ok": true,
  "status": 200,
  "cookie": "datadome=...; Max-Age=31536000; Domain=...; Path=/; Secure; SameSite=Lax",
  "cookie_value": "datadome=...",
  "cid": "...",
  "verify": { "scraping_status": 200, "clean": true }
}
```

CLI:

```bash
./datadome -site https://your-target.example -key YOUR_DDK -two-phase -delay 5 -verify \
  -proxy "geo.iproyal.com:12321:username:password"
```

## Changelog

See **[CHANGELOG.md](CHANGELOG.md)** for the full v5.7.0 → v5.9.0 → v5.9.2 history.

- **v5.7.0** — Go SDK/CLI, fingerprint builder, `jspl` encrypt
- **v5.9.0** — tags.js 5.9.0 eventCounters + behavioral/biometric layer, uTLS server/CLI
- **v5.9.2** — tags.js 5.9.2 keys, Chrome 151, `jspl` decrypt, remainder + `_` alphabet fix

## Proxy

Pass a proxy as the `Proxy:` request header (server) or `-proxy` (CLI), in `ip:port:user:pass` form.
`host:port`, `user:pass@host:port`, `http(s)://…` and `socks5://…` are also accepted. HTTP CONNECT
and SOCKS5 auth are both supported. The Chrome uTLS fingerprint is preserved through the proxy.
Precedence: `Proxy:` header → `proxy` field → server `-proxy` default.

## Layout

| Path | What |
|------|------|
| `go/cmd/server/`   | Local HTTP API — `POST /solve` returns a cookie |
| `go/cmd/datadome/` | CLI (solve / verify / scrape / fetch / encrypt) |
| `go/pkg/datadome/` | Client library + Chrome uTLS transport |
| `go/internal/`     | Fingerprint builder, generators, profiles, jspl codec |

## Authorization

Only run active solves against targets you are authorized to test. A cookie may be issued (200) yet
still be bot-scored from a flagged IP/session.

## License

MIT
