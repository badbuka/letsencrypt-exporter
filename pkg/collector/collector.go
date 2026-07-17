// Package collector implements a prometheus.Collector that reports the
// validity windows of every certificate found by the discovery package.
//
// The collector is purely scrape-driven: every call to Collect re-runs
// discovery and re-parses each cert.pem. There are no background goroutines
// and no internal caches, which makes it trivial to embed in a host service
// that already exposes a Prometheus registry.
package collector

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	certpkg "github.com/badbuka/letsencrypt-exporter/pkg/cert"
	"github.com/badbuka/letsencrypt-exporter/pkg/discovery"
)

// Options configures a collector instance. The zero value is valid and
// produces a collector that scans /etc/letsencrypt and labels metrics with
// the local OS hostname.
type Options struct {
	// CertbotPath is the certbot root directory. Defaults to
	// discovery.DefaultRoot ("/etc/letsencrypt") when empty.
	CertbotPath string

	// ExtraPaths lists explicit PEM files or directories to scan.
	ExtraPaths []string

	// RecursivePaths lists directories walked recursively for PEM files.
	RecursivePaths []string

	// Hostname is the value used for the "hostname" label. When empty the
	// collector calls os.Hostname() once at construction time.
	Hostname string

	// ConstLabels are merged into every metric on top of the built-in
	// {hostname,domain,lineage} triple. Useful for things like {"env":"prod"}.
	ConstLabels prometheus.Labels

	// Now overrides the time source. Intended for tests.
	Now func() time.Time

	// Debug enables per-scrape discovery logs for CERT_PATHS and
	// CERT_RECURSIVE_PATHS scans.
	Debug bool

	// Logger, if non-nil, is invoked for every scrape-time error
	// (scanner failure or per-certificate parse failure). It is in
	// addition to the letsencrypt_cert_read_errors_total counter and is
	// meant to surface why metrics are missing in operator logs. When Debug
	// is true, extra and recursive path scan details are also logged.
	Logger func(format string, args ...any)
}

// Collector implements prometheus.Collector.
type Collector struct {
	cfg      discovery.Config
	hostname string
	debug    bool
	now      func() time.Time
	logf     func(format string, args ...any)

	notAfter    *prometheus.Desc
	notBefore   *prometheus.Desc
	expiresIn   *prometheus.Desc
	info        *prometheus.Desc
	scrapeTS    *prometheus.Desc
	readErrDesc *prometheus.Desc

	mu       sync.Mutex
	readErrs map[string]float64
}

// New builds a Collector from opts.
func New(opts Options) *Collector {
	certbotPath := opts.CertbotPath
	if certbotPath == "" {
		certbotPath = discovery.DefaultRoot
	}

	host := opts.Hostname
	if host == "" {
		if h, err := os.Hostname(); err == nil {
			host = h
		} else {
			host = "unknown"
		}
	}

	cfg := discovery.Config{
		CertbotRoot:    certbotPath,
		Paths:          opts.ExtraPaths,
		RecursiveRoots: opts.RecursivePaths,
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	logf := opts.Logger
	if logf == nil {
		logf = func(string, ...any) {}
	}

	const ns = "letsencrypt"
	hostLabels := prometheus.Labels{"hostname": host}
	for k, v := range opts.ConstLabels {
		hostLabels[k] = v
	}

	return &Collector{
		cfg:      cfg,
		hostname: host,
		debug:    opts.Debug,
		now:      now,
		logf:     logf,
		notAfter: prometheus.NewDesc(
			ns+"_cert_not_after_seconds",
			"Certificate NotAfter expressed as seconds since the Unix epoch.",
			[]string{"domain", "lineage"}, hostLabels,
		),
		notBefore: prometheus.NewDesc(
			ns+"_cert_not_before_seconds",
			"Certificate NotBefore expressed as seconds since the Unix epoch.",
			[]string{"domain", "lineage"}, hostLabels,
		),
		expiresIn: prometheus.NewDesc(
			ns+"_cert_expires_in_seconds",
			"Seconds until the certificate's NotAfter; negative once expired.",
			[]string{"domain", "lineage"}, hostLabels,
		),
		info: prometheus.NewDesc(
			ns+"_cert_info",
			"Constant 1 with descriptive certificate labels.",
			[]string{"domain", "lineage", "cn", "issuer", "serial", "sans"}, hostLabels,
		),
		scrapeTS: prometheus.NewDesc(
			"letsencrypt_exporter_last_scrape_timestamp_seconds",
			"Unix timestamp of the most recent scrape.",
			nil, hostLabels,
		),
		readErrDesc: prometheus.NewDesc(
			ns+"_cert_read_errors_total",
			"Total number of errors encountered while reading or parsing a certificate file, by domain.",
			[]string{"domain"}, hostLabels,
		),
		readErrs: make(map[string]float64),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.notAfter
	ch <- c.notBefore
	ch <- c.expiresIn
	ch <- c.info
	ch <- c.scrapeTS
	ch <- c.readErrDesc
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	now := c.now()

	certs, err := c.discoverCerts()
	if err != nil {
		c.logf("scan: %v", err)
		c.bumpReadErr("")
	}

	for _, cert := range certs {
		parsed, perr := certpkg.Load(cert.CertPath)
		if perr != nil {
			c.logf("parse fallback_id=%q path=%q: %v", cert.FallbackID, cert.CertPath, perr)
			c.bumpReadErr(cert.FallbackID)
			continue
		}

		domain := certpkg.PrimaryDomain(parsed, cert.FallbackID)
		lineage := cert.FallbackID

		ch <- prometheus.MustNewConstMetric(
			c.notAfter, prometheus.GaugeValue,
			float64(parsed.NotAfter.Unix()), domain, lineage,
		)
		ch <- prometheus.MustNewConstMetric(
			c.notBefore, prometheus.GaugeValue,
			float64(parsed.NotBefore.Unix()), domain, lineage,
		)
		ch <- prometheus.MustNewConstMetric(
			c.expiresIn, prometheus.GaugeValue,
			parsed.NotAfter.Sub(now).Seconds(), domain, lineage,
		)
		ch <- prometheus.MustNewConstMetric(
			c.info, prometheus.GaugeValue, 1,
			domain,
			lineage,
			parsed.Subject.CommonName,
			parsed.Issuer.CommonName,
			parsed.SerialNumber.Text(16),
			strings.Join(parsed.DNSNames, ","),
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.scrapeTS, prometheus.GaugeValue, float64(now.Unix()),
	)

	c.mu.Lock()
	for domain, count := range c.readErrs {
		ch <- prometheus.MustNewConstMetric(
			c.readErrDesc, prometheus.CounterValue, count, domain,
		)
	}
	c.mu.Unlock()
}

func (c *Collector) discoverCerts() ([]discovery.Cert, error) {
	cfg := c.cfg
	if c.debug {
		cfg.Logger = c.logf
	}
	return discovery.ScanAll(cfg)
}

func (c *Collector) bumpReadErr(domain string) {
	c.mu.Lock()
	c.readErrs[domain]++
	c.mu.Unlock()
}
