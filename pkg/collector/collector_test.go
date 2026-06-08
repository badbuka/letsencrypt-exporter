package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/badbuka/letsencrypt-exporter/pkg/cert"
)

func TestCollectorMetrics(t *testing.T) {
	root := t.TempDir()
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cert.WriteTestCert(t,
		filepath.Join(root, "live", "example.com", "cert.pem"),
		notAfter,
		[]string{"example.com", "www.example.com"},
	)

	now := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)

	c := New(Options{
		CertbotPath: root,
		Hostname:    "edge-01",
		Now:         func() time.Time { return now },
	})

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	expected := `
# HELP letsencrypt_cert_not_after_seconds Certificate NotAfter expressed as seconds since the Unix epoch.
# TYPE letsencrypt_cert_not_after_seconds gauge
letsencrypt_cert_not_after_seconds{domain="example.com",hostname="edge-01",lineage="example.com"} 1.893456e+09
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "letsencrypt_cert_not_after_seconds"); err != nil {
		t.Fatalf("not_after mismatch: %v", err)
	}

	expectedExpires := `
# HELP letsencrypt_cert_expires_in_seconds Seconds until the certificate's NotAfter; negative once expired.
# TYPE letsencrypt_cert_expires_in_seconds gauge
letsencrypt_cert_expires_in_seconds{domain="example.com",hostname="edge-01",lineage="example.com"} 3.1536e+07
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expectedExpires), "letsencrypt_cert_expires_in_seconds"); err != nil {
		t.Fatalf("expires_in mismatch: %v", err)
	}

	if got := testutil.CollectAndCount(c, "letsencrypt_cert_info"); got != 1 {
		t.Errorf("expected 1 info series, got %d", got)
	}
}

func TestCollectorDomainFromFirstSAN(t *testing.T) {
	root := t.TempDir()
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cert.WriteTestCert(t,
		filepath.Join(root, "live", "example.com", "cert.pem"),
		notAfter,
		[]string{"www.example.com", "example.com"},
	)

	c := New(Options{
		CertbotPath: root,
		Hostname:    "edge-01",
	})
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	expected := `
# HELP letsencrypt_cert_not_after_seconds Certificate NotAfter expressed as seconds since the Unix epoch.
# TYPE letsencrypt_cert_not_after_seconds gauge
letsencrypt_cert_not_after_seconds{domain="www.example.com",hostname="edge-01",lineage="example.com"} 1.893456e+09
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "letsencrypt_cert_not_after_seconds"); err != nil {
		t.Fatalf("domain should come from first SAN: %v", err)
	}
}

func TestCollectorFlatPEMPath(t *testing.T) {
	root := t.TempDir()
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	pemPath := filepath.Join(root, "custom.pem")
	cert.WriteTestCert(t, pemPath, notAfter, []string{"custom.example.com"})

	c := New(Options{
		CertbotPath: filepath.Join(t.TempDir(), "missing"),
		ExtraPaths:  []string{pemPath},
		Hostname:    "edge-01",
	})
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	expected := `
# HELP letsencrypt_cert_not_after_seconds Certificate NotAfter expressed as seconds since the Unix epoch.
# TYPE letsencrypt_cert_not_after_seconds gauge
letsencrypt_cert_not_after_seconds{domain="custom.example.com",hostname="edge-01",lineage="custom.pem"} 1.893456e+09
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "letsencrypt_cert_not_after_seconds"); err != nil {
		t.Fatalf("flat PEM path mismatch: %v", err)
	}
}

func TestCollectorHandlesMissingRoot(t *testing.T) {
	c := New(Options{
		CertbotPath: filepath.Join(t.TempDir(), "missing"),
		Hostname:    "h",
	})
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	if got := testutil.CollectAndCount(c, "letsencrypt_cert_not_after_seconds"); got != 0 {
		t.Errorf("expected zero series, got %d", got)
	}
	if got := testutil.CollectAndCount(c, "letsencrypt_exporter_last_scrape_timestamp_seconds"); got != 1 {
		t.Errorf("scrape timestamp must always be emitted, got %d", got)
	}
}

func TestCollectorDuplicatePrimaryDomain(t *testing.T) {
	root := t.TempDir()
	oldExpiry := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	newExpiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cert.WriteTestCert(t,
		filepath.Join(root, "live", "wildcard-old", "cert.pem"),
		oldExpiry,
		[]string{"*.uzumid.uz"},
	)
	cert.WriteTestCert(t,
		filepath.Join(root, "live", "wildcard-new", "cert.pem"),
		newExpiry,
		[]string{"*.uzumid.uz"},
	)

	c := New(Options{
		CertbotPath: root,
		Hostname:    "edge-01",
	})
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	if got := testutil.CollectAndCount(c, "letsencrypt_cert_not_after_seconds"); got != 2 {
		t.Fatalf("expected 2 series for duplicate primary domain, got %d", got)
	}
}

func TestCollectorLogsParseErrors(t *testing.T) {
	root := t.TempDir()
	domainDir := filepath.Join(root, "live", "broken.example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "cert.pem"), []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}

	var logs []string
	c := New(Options{
		CertbotPath: root,
		Hostname:    "h",
		Logger: func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
	})
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	if got := testutil.CollectAndCount(c, "letsencrypt_cert_read_errors_total"); got != 1 {
		t.Errorf("expected one read-error series, got %d", got)
	}
	if len(logs) == 0 || !strings.Contains(logs[0], "broken.example.com") {
		t.Errorf("expected logger to fire with fallback id context, got %v", logs)
	}
}
