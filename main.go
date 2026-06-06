// Command letsencrypt-exporter serves Prometheus metrics describing the
// validity windows of every certificate found under configured paths.
//
// Configuration is read from environment variables (via envconfig) and may
// be overridden by command-line flags. There is no JSON config file.
//
// Subcommands:
//
//	letsencrypt-exporter            # default: serve /metrics
//	letsencrypt-exporter debug      # one-shot dump of what discovery sees
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/badbuka/letsencrypt-exporter/pkg/collector"
)

type config struct {
	LetsencryptPath    string `envconfig:"LETSENCRYPT_PATH"       default:"/etc/letsencrypt"`
	CertPaths          string `envconfig:"CERT_PATHS"             default:""`
	CertRecursivePaths string `envconfig:"CERT_RECURSIVE_PATHS"   default:""`
	Port               int    `envconfig:"PORT"                   default:"8622"`
	Hostname           string `envconfig:"HOSTNAME"`
	Debug              bool   `envconfig:"DEBUG"                  default:"false"`
}

func loadConfig(args []string) (config, error) {
	var cfg config
	if err := envconfig.Process("", &cfg); err != nil {
		return cfg, fmt.Errorf("envconfig: %w", err)
	}

	fs := flag.NewFlagSet("letsencrypt-exporter", flag.ContinueOnError)
	fs.StringVar(&cfg.LetsencryptPath, "letsencrypt-path", cfg.LetsencryptPath,
		"Path to the Let's Encrypt / certbot root directory (env: LETSENCRYPT_PATH)")
	fs.StringVar(&cfg.CertPaths, "cert-paths", cfg.CertPaths,
		"Comma-separated PEM files or directories to scan (env: CERT_PATHS)")
	fs.StringVar(&cfg.CertRecursivePaths, "cert-recursive-paths", cfg.CertRecursivePaths,
		"Comma-separated roots for recursive PEM walk (env: CERT_RECURSIVE_PATHS)")
	fs.IntVar(&cfg.Port, "port", cfg.Port,
		"TCP port for the HTTP server (env: PORT)")
	fs.StringVar(&cfg.Hostname, "hostname", cfg.Hostname,
		"Override for the hostname label; defaults to os.Hostname() (env: HOSTNAME)")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug,
		"Enable debug mode (adds standard Go/process runtime metrics) (env: DEBUG)")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func parseList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "debug" {
		os.Exit(runDebug(args[1:], os.Stdout, os.Stderr))
	}

	cfg, err := loadConfig(args)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	extraPaths := parseList(cfg.CertPaths)
	recursivePaths := parseList(cfg.CertRecursivePaths)

	reg := prometheus.NewRegistry()
	if cfg.Debug {
		reg.MustRegister(collectors.NewGoCollector())
		reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}
	collector.MustRegister(reg, collector.Options{
		CertbotPath:    cfg.LetsencryptPath,
		ExtraPaths:     extraPaths,
		RecursivePaths: recursivePaths,
		Hostname:       cfg.Hostname,
		Logger: func(format string, a ...any) {
			log.Printf("collector: "+format, a...)
		},
	})

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("letsencrypt-exporter\nGET /metrics\nGET /healthz\n"))
	})

	addr := ":" + strconv.Itoa(cfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Printf("letsencrypt-exporter listening on %s, certbot=%s extra=%d recursive=%d",
		addr, cfg.LetsencryptPath, len(extraPaths), len(recursivePaths))
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("http server: %v", err)
	}
}
