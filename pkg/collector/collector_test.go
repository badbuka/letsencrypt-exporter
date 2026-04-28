package collector

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/badbuka/letsencrypt-exporter/pkg/discovery"
)

func writeCert(t *testing.T, path string, notAfter time.Time, dnsNames []string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorMetrics(t *testing.T) {
	root := t.TempDir()
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	writeCert(t,
		filepath.Join(root, "live", "example.com", "cert.pem"),
		notAfter,
		[]string{"example.com", "www.example.com"},
	)

	now := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)

	c := New(Options{
		Path:     root,
		Hostname: "edge-01",
		Now:      func() time.Time { return now },
		Scanner:  discovery.Scan,
	})

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	expected := `
# HELP letsencrypt_cert_not_after_seconds Certificate NotAfter expressed as seconds since the Unix epoch.
# TYPE letsencrypt_cert_not_after_seconds gauge
letsencrypt_cert_not_after_seconds{domain="example.com",hostname="edge-01"} 1.893456e+09
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "letsencrypt_cert_not_after_seconds"); err != nil {
		t.Fatalf("not_after mismatch: %v", err)
	}

	expectedExpires := `
# HELP letsencrypt_cert_expires_in_seconds Seconds until the certificate's NotAfter; negative once expired.
# TYPE letsencrypt_cert_expires_in_seconds gauge
letsencrypt_cert_expires_in_seconds{domain="example.com",hostname="edge-01"} 3.1536e+07
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expectedExpires), "letsencrypt_cert_expires_in_seconds"); err != nil {
		t.Fatalf("expires_in mismatch: %v", err)
	}

	if got := testutil.CollectAndCount(c, "letsencrypt_cert_info"); got != 1 {
		t.Errorf("expected 1 info series, got %d", got)
	}
}

func TestCollectorHandlesMissingRoot(t *testing.T) {
	c := New(Options{
		Path:     filepath.Join(t.TempDir(), "missing"),
		Hostname: "h",
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
