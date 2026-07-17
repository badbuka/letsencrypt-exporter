# Repository Guidelines

## Project Overview

`letsencrypt-exporter` — Prometheus exporter exposing X.509 certificate validity
(`not_before`, `not_after`, `expires_in`) for every cert found under a certbot
root plus operator-configured extra/recursive paths. Also usable as a Go library.

- Module: `github.com/badbuka/letsencrypt-exporter`, Go 1.26.4 (pinned in go.mod, CI, Docker)
- Direct deps: `kelseyhightower/envconfig` (env config), `prometheus/client_golang` (metrics/HTTP)
- Binary subcommands: default = serve HTTP on :8622; `debug` = one-shot discovery dump (debug.go)

## Architecture & Data Flow

Scrape-driven, no background goroutines, no caches, no `context`. Per Prometheus scrape:

```
main.go → reg.MustRegister(collector.New(Options{...}))
  Collector.Collect()                        # pkg/collector, implements prometheus.Collector
    → discovery.ScanAll(Config{...})         # pkg/discovery: fs scan, knows nothing about Prometheus
        certbot live/ + extra paths + recursive roots → dedupe by CertPath, sort by (FallbackID, CertPath)
    → cert.Load(path)                        # pkg/cert: PEM (CERTIFICATE block) or DER fallback
    → cert.PrimaryDomain(parsed, fallback)   # first DNS SAN → subject CN → fallback
    → 4 MustNewConstMetric gauges per cert + scrape-timestamp + read-error counters
```

- Metrics namespace `letsencrypt_*`; labels `domain`, `lineage` (= FallbackID); const label `hostname` on all metrics.
- Collector never fails a scrape: scan/parse errors are logged and surfaced as `letsencrypt_cert_read_errors_total`.
- Only synchronization: `sync.Mutex` guarding the `readErrs` map (Prometheus may call `Collect` concurrently).
- `debug` subcommand reuses the same pipeline (`ScanAllVerbose` → `Load` → `[OK]`/`[SKIP]`/`[PARSE-ERR]`).

## Key Directories

| Path | Purpose |
|---|---|
| `main.go`, `debug.go` | package main: config load, HTTP server, debug CLI |
| `pkg/collector/` | `prometheus.Collector` impl; `Options` struct is the config + test-hook surface |
| `pkg/discovery/` | filesystem scanning: certbot root (`certbot.go`), explicit paths (`paths.go`), recursive (`recursive.go`) |
| `pkg/cert/` | cert parsing + `PrimaryDomain`; `testutil.go` (NOT `_test.go`) exports shared test-cert writers |
| `grafana/`, `dash.json` | git-ignored local Grafana dashboards; not referenced by build/CI — don't rely on them |

## Development Commands

```sh
make build   # go build -trimpath -ldflags="-s -w" -o bin/letsencrypt-exporter .
make test    # go test -race -count=1 ./...
make lint    # golangci-lint run        (v2 config, see .golangci.yml)
make fmt     # golangci-lint fmt        (gofmt + goimports)
make vet     # go vet ./...
make all     # lint test build
```

Run: `go run .` (serves :8622, `/metrics` + `/healthz`) or `go run . debug` (discovery dump).
Docker: two-stage `golang:1.26.4-alpine` → `gcr.io/distroless/static-debian12`, `CGO_ENABLED=0`.

## Code Conventions & Common Patterns

- **Errors**: wrap with `fmt.Errorf("...: %w", err)`. `log.Fatalf` only in `main`. Discovery separates
  source-level errors (abort scan) from per-entry errors (`Entry.Error`, scan continues).
- **Logging**: stdlib `log` only. Cross-package logging via injected `Logger func(format string, args ...any)`
  on `collector.Options` and `discovery.Config` (nil logger = no-op). Log lines use `key=value` pairs.
- **Config**: envconfig struct tags + flag overrides; precedence flags > env > defaults.
  Env `LETSENCRYPT_PATH`, `CERT_PATHS`, `CERT_RECURSIVE_PATHS`, `PORT`, `HOSTNAME`, `DEBUG`;
  flags are the kebab-case equivalents.
- **DI/state**: no framework. Dependencies are struct fields (`Options.Now` — "Intended for tests").
- **Naming**: verbose/non-verbose API pair (`ScanAll`/`ScanAllVerbose`);
  `cert` imported as `certpkg` on collision. Full godoc on every exported symbol (revive `exported` enforced).
- **Lint**: `.golangci.yml` `default: none` + 18 explicit linters (errcheck, gosec, gocritic, revive,
  gocyclo@15, ...). goimports local-prefix `github.com/badbuka/letsencrypt-exporter`.
  `_test.go` exempt from gosec/errcheck/gocyclo/unparam. `//nolint` requires a justifying comment by convention.

## Important Files

- `main.go` — entry: `loadConfig` (envconfig+flags), HTTP server with explicit timeouts (5/10/10/30s)
- `pkg/collector/collector.go` — metric Descs and `Collect`; namespace/labels defined in `New` (:117-150)
- `pkg/discovery/discovery.go` — `Config`, `Cert`, `Entry`, `ScanAll*` orchestration
- `pkg/cert/cert.go` — `Load`, `LooksLikeCertificate*`, `PrimaryDomain`
- `.golangci.yml`, `Makefile`, `Dockerfile`, `go.mod` — build/lint/toolchain
- `.github/workflows/ci.yml` — vet+test+lint+snyk; `release.yml` — tag `v*` → multi-arch Docker image only

## Runtime/Tooling Preferences

- **Go 1.26.4 exactly** — keep go.mod, CI `setup-go`, and Docker base image in sync when bumping.
- golangci-lint **v2** (CI pins v2.11.4); `make fmt` uses `golangci-lint fmt`, not bare gofmt.
- Static binary (`CGO_ENABLED=0`, `-trimpath -ldflags="-s -w"`) on distroless — no shell/libc at runtime.
- Container runs as root by default: certbot sets `live/`/`archive/` to `0700 root:root` and `cert.pem`
  is a relative symlink into `archive/` — exporter needs read+execute on both.
- Default port **8622**.

## Testing & QA

- **Stdlib `testing` only — no testify/gomega.** Flat `func TestX(t *testing.T)`; one table-driven test
  (`TestPrimaryDomain`). Same-package tests (`package x`, not `x_test`).
- Fixtures: real filesystem in `t.TempDir()`, real self-signed certs via `cert.WriteTestCert*` —
  reuse these from `pkg/cert/testutil.go` instead of writing new cert generators.
- Env isolation via `t.Setenv`; collector tests use `prometheus/testutil` (`GatherAndCompare`,
  `NewPedanticRegistry`) with fixed clock via `Options.Now` and hard-coded timestamps (e.g. `1.893456e+09`).
- Command: `go test -race -count=1 ./...`. **No coverage tooling exists** — don't add thresholds unasked.
- Known untested surface: `debug.go`, `main()` — okay to leave unless touching them.
- CI gates: `go vet`, race tests, golangci-lint, Snyk. Dependabot PRs auto-merge.
