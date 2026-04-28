// Command letsencrypt-exporter serves Prometheus metrics describing the
// validity windows of every certificate found under a Let's Encrypt
// directory tree.
//
// Configuration is read from environment variables (via envconfig) and may
// be overridden by command-line flags. There is no JSON config file.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/badbuka/letsencrypt-exporter/pkg/collector"
)

type config struct {
	LetsencryptPath string `envconfig:"LETSENCRYPT_PATH" default:"/etc/letsencrypt"`
	Port            int    `envconfig:"PORT"             default:"8622"`
	Hostname        string `envconfig:"HOSTNAME"`
}

func loadConfig(args []string) (config, error) {
	var cfg config
	if err := envconfig.Process("", &cfg); err != nil {
		return cfg, fmt.Errorf("envconfig: %w", err)
	}

	fs := flag.NewFlagSet("letsencrypt-exporter", flag.ContinueOnError)
	fs.StringVar(&cfg.LetsencryptPath, "letsencrypt-path", cfg.LetsencryptPath,
		"Path to the Let's Encrypt root directory (env: LETSENCRYPT_PATH)")
	fs.IntVar(&cfg.Port, "port", cfg.Port,
		"TCP port for the HTTP server (env: PORT)")
	fs.StringVar(&cfg.Hostname, "hostname", cfg.Hostname,
		"Override for the hostname label; defaults to os.Hostname() (env: HOSTNAME)")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func main() {
	cfg, err := loadConfig(os.Args[1:])
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	collector.MustRegister(reg, collector.Options{
		Path:     cfg.LetsencryptPath,
		Hostname: cfg.Hostname,
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

	log.Printf("letsencrypt-exporter listening on %s, scanning %s", addr, cfg.LetsencryptPath)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("http server: %v", err)
	}
}
