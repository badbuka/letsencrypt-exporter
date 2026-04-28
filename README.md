# letsencrypt-exporter
[![Go Report Card](https://goreportcard.com/badge/github.com/badbuka/letsencrypt-exporter)](https://goreportcard.com/report/github.com/badbuka/letsencrypt-exporter)
A Prometheus exporter and reusable Go library that auto-discovers Let's
Encrypt certificates under `/etc/letsencrypt/live/*` and exposes their
validity windows.

Each metric is labeled with `hostname` (the OS hostname of the machine
running the exporter) and `domain` (the certbot lineage directory name).

## Features

- Auto-discovers every `live/<domain>/cert.pem` on every scrape; 
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

## Run as a binary

```bash
go install github.com/badbuka/letsencrypt-exporter/cmd/letsencrypt-exporter@latest
letsencrypt-exporter -letsencrypt-path /etc/letsencrypt -port 8622
```

Or via Docker:

```bash
docker build -t letsencrypt-exporter .
docker run --rm -p 8622:8622 \
  -v /etc/letsencrypt:/etc/letsencrypt:ro \
  letsencrypt-exporter
```

### Configuration

Flags override environment variables, environment variables override defaults.

| Flag                  | Env                | Default            | Description                                  |
| --------------------- | ------------------ | ------------------ | -------------------------------------------- |
| `-letsencrypt-path`   | `LETSENCRYPT_PATH` | `/etc/letsencrypt` | Let's Encrypt root directory                 |
| `-port`               | `PORT`             | `8622`             | TCP port for the HTTP server                 |
| `-hostname`           | `HOSTNAME`         | `os.Hostname()`    | Override for the `hostname` metric label     |

### Endpoints

- `GET /metrics` &mdash; Prometheus exposition
- `GET /healthz` &mdash; liveness probe

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
        Path: "/etc/letsencrypt",
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

certs, err := discovery.Scan("/etc/letsencrypt")
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
