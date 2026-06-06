# letsencrypt-exporter
[![Go Report Card](https://goreportcard.com/badge/github.com/badbuka/letsencrypt-exporter)](https://goreportcard.com/report/github.com/badbuka/letsencrypt-exporter)

A Prometheus exporter and reusable Go library that auto-discovers TLS
certificates from certbot layouts and other configured PEM paths, then
exposes their validity windows.

Each metric is labeled with `hostname` (the OS hostname of the machine
running the exporter) and `domain` (the primary name from the certificate:
first DNS SAN, else common name, else a filesystem fallback).

## Features

- Auto-discovers certbot `live/<lineage>/cert.pem` on every scrape, plus
  optional explicit PEM paths and recursive directory walks;
- Reads only the public certificate, never the private key, so the exporter
  can run as an unprivileged user.
- Ships as both a self-contained binary and an importable Go package.
- Configuration via environment variables (`envconfig`) and CLI flags. 

## Metrics

| Metric                                                | Labels                                | Meaning                                        |
| ----------------------------------------------------- | ------------------------------------- | ---------------------------------------------- |
| `letsencrypt_cert_not_after_seconds`                  | `hostname`, `domain`                  | `NotAfter` as Unix seconds                     |
| `letsencrypt_cert_not_before_seconds`                 | `hostname`, `domain`                  | `NotBefore` as Unix seconds                    |
| `letsencrypt_cert_expires_in_seconds`                 | `hostname`, `domain`                  | `NotAfter - now`; negative once expired        |
| `letsencrypt_cert_info`                               | `hostname`, `domain`, `cn`, `issuer`, `serial`, `sans` | Constant `1`, descriptive labels |
| `letsencrypt_cert_read_errors_total`                  | `hostname`, `domain`                  | Counter of read/parse failures per domain      |
| `letsencrypt_exporter_last_scrape_timestamp_seconds`  | `hostname`                            | Wallclock of most recent scrape                |

## Run as a Docker image

Via Docker — pre-built images are published on Docker Hub at
[`badbuka/letsencrypt-exporter`](https://hub.docker.com/r/badbuka/letsencrypt-exporter):

```bash
docker run -d --rm -p 8622:8622 \
  -v /etc/letsencrypt:/etc/letsencrypt:ro \
  badbuka/letsencrypt-exporter:latest
```

Pin a specific release with the semver tag, e.g. `badbuka/letsencrypt-exporter:v1.0.0`.

To build locally instead:

```bash
docker build -t letsencrypt-exporter .
docker run -d --rm -p 8622:8622 \
  -v /etc/letsencrypt:/etc/letsencrypt:ro \
  letsencrypt-exporter
```

> **Permissions.** Stock certbot creates `/etc/letsencrypt/{live,archive}` with
> mode `0700 root:root`, and `live/<domain>/cert.pem` is a relative symlink
> into `archive/`, so the exporter needs read+execute on **both** directories.
> The published image runs as root for that reason. If you tighten the host
> permissions (dedicated group + `chmod g+rX`, or POSIX ACLs) you can drop
> privileges via `docker run --user 65532:65532` or the equivalent
> `User=`/`Group=` in your systemd unit.

### Configuration

Flags override environment variables, environment variables override defaults.

| Flag                      | Env                    | Default            | Description                                  |
| ------------------------- | ---------------------- | ------------------ | -------------------------------------------- |
| `-letsencrypt-path`       | `LETSENCRYPT_PATH`     | `/etc/letsencrypt` | Certbot / Let's Encrypt root directory       |
| `-cert-paths`             | `CERT_PATHS`           | `""`               | Comma-separated PEM files or directories     |
| `-cert-recursive-paths`   | `CERT_RECURSIVE_PATHS` | `""`               | Comma-separated roots for recursive PEM walk |
| `-port`                   | `PORT`                 | `8622`             | TCP port for the HTTP server                 |
| `-hostname`               | `HOSTNAME`             | `os.Hostname()`    | Override for the `hostname` metric label     |
| `-debug`                  | `DEBUG`                | `false`            | Enable standard Go and process runtime metrics |

`CERT_PATHS` accepts individual `.pem`/`.crt` files or directories. For a
directory, `cert.pem` is preferred (certbot-style); otherwise every
`.pem`/`.crt` file in that directory is scanned (non-recursive).

`CERT_RECURSIVE_PATHS` walks each root recursively for `.pem`, `.crt`, and
`.cer` files. Private keys (`privkey.pem`, `*-key.pem`) and non-certificate
PEM blocks are skipped. Avoid pointing recursive roots at certbot `archive/`
when `LETSENCRYPT_PATH` is already configured — results are deduplicated by
file path, but overlapping scans waste I/O.

Example with nginx-managed certificates alongside certbot:

```bash
docker run -d --rm -p 8622:8622 \
  -v /etc/letsencrypt:/etc/letsencrypt:ro \
  -v /etc/nginx/certs:/etc/nginx/certs:ro \
  -e CERT_PATHS=/etc/nginx/certs \
  badbuka/letsencrypt-exporter:latest
```

> **Breaking change.** The `domain` label is now derived from the
> certificate (first SAN, else CN) rather than the certbot lineage directory
> name. Dashboards and alerts keyed on lineage names may need updates when
> lineage and primary SAN differ (e.g. lineage `example.com` whose first SAN
> is `www.example.com`).

### Endpoints

- `GET /metrics` &mdash; Prometheus exposition
- `GET /healthz` &mdash; liveness probe

### Debugging

If `letsencrypt_cert_read_errors_total` is climbing or no certificates show
up at all, run a one-shot dump that lists every `live/<domain>` entry with
the reason it was kept or skipped, plus parsed certificate details:

```bash
letsencrypt-exporter debug \
  -letsencrypt-path /etc/letsencrypt \
  -cert-paths /etc/nginx/certs
```

Sample output:

```
letsencrypt-exporter debug
  certbot root:     /etc/letsencrypt
  extra paths:      0
  recursive roots:  0
  hostname: edge-01
  live dir: /etc/letsencrypt/live (mode=-rwx------)

[OK]    example.com
        fallback_id: example.com
        path:        /etc/letsencrypt/archive/example.com/cert3.pem
        cn:          example.com
        issuer:      R3
        not_before:  2026-04-10T00:00:00Z
        not_after:   2026-07-09T00:00:00Z
        expires_in:  1736h12m04s
        sans:        [example.com www.example.com]

[SKIP]  stale.example.com
        reason: resolve cert.pem: lstat /etc/letsencrypt/live/stale.example.com/cert.pem: no such file or directory

summary: ok=1 skipped=1 parse_errors=0 total=2
```

The running exporter logs the same scan / parse errors to stderr each scrape,
so you can also `journalctl -u letsencrypt-exporter` (or `docker logs`) to
spot the cause without restarting in debug mode.

### Scrape config

```yaml
scrape_configs:
  - job_name: letsencrypt
    static_configs:
      - targets: ["edge-01.internal:8622"]
```

### Sample alert

```yaml
groups:
  - name: letsencrypt
    rules:
      - alert: LetsencryptCertExpiringSoon
        expr: letsencrypt_cert_expires_in_seconds < 14 * 24 * 3600
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Certificate {{ $labels.domain }} on {{ $labels.hostname }} expires soon"
```

## Use as a library

If you already have a service exposing `/metrics`, register the collector on
your own registry instead of running a second process:

```go
package main

import (
    "net/http"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"

    "github.com/badbuka/letsencrypt-exporter/pkg/collector"
)

func main() {
    collector.MustRegister(prometheus.DefaultRegisterer, collector.Options{
        CertbotPath: "/etc/letsencrypt",
        ExtraPaths:  []string{"/etc/nginx/certs"},
        ConstLabels: prometheus.Labels{"env": "prod"},
    })
    http.Handle("/metrics", promhttp.Handler())
    http.ListenAndServe(":9090", nil)
}
```

The lower-level `pkg/discovery` package is also exported for non-Prometheus
consumers:

```go
import "github.com/badbuka/letsencrypt-exporter/pkg/discovery"

certs, err := discovery.ScanAll(discovery.Config{
    CertbotRoot: "/etc/letsencrypt",
    Paths:       []string{"/etc/nginx/certs"},
})

// discovery.Scan(root) remains as a certbot-only shorthand.
```

## Development

Requires Go 1.26.2 and [golangci-lint](https://golangci-lint.run/) v2.x.

```bash
make lint    # golangci-lint run
make test    # go test -race -count=1 ./...
make build   # produces bin/letsencrypt-exporter
make all     # lint + test + build
```

## License

MIT
