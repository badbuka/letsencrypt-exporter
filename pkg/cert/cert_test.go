package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrimaryDomain(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		fallback string
		want     string
	}{
		{
			name: "san first",
			cert: &x509.Certificate{
				Subject:  pkix.Name{CommonName: "example.com"},
				DNSNames: []string{"www.example.com", "example.com"},
			},
			fallback: "lineage",
			want:     "www.example.com",
		},
		{
			name: "cn only",
			cert: &x509.Certificate{
				Subject: pkix.Name{CommonName: "example.com"},
			},
			fallback: "lineage",
			want:     "example.com",
		},
		{
			name:     "fallback",
			cert:     &x509.Certificate{},
			fallback: "custom-id",
			want:     "custom-id",
		},
		{
			name: "wildcard san",
			cert: &x509.Certificate{
				DNSNames: []string{"*.example.com"},
			},
			fallback: "lineage",
			want:     "*.example.com",
		},
		{
			name:     "nil cert",
			cert:     nil,
			fallback: "fallback",
			want:     "fallback",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PrimaryDomain(tc.cert, tc.fallback); got != tc.want {
				t.Fatalf("PrimaryDomain() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pem")
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	WriteTestCert(t, path, notAfter, []string{"example.com", "www.example.com"})

	parsed, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if parsed.Subject.CommonName != "example.com" {
		t.Fatalf("unexpected CN: %q", parsed.Subject.CommonName)
	}
	if len(parsed.DNSNames) != 2 {
		t.Fatalf("unexpected SANs: %v", parsed.DNSNames)
	}
}

func TestLoadDER(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.cer")
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	WriteTestCertDER(t, path, notAfter, []string{"der.example.com"})

	parsed, err := Load(path)
	if err != nil {
		t.Fatalf("Load DER: %v", err)
	}
	if parsed.Subject.CommonName != "der.example.com" {
		t.Fatalf("unexpected CN: %q", parsed.Subject.CommonName)
	}
}

func TestLoadRejectsNonCertificatePEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for non-certificate PEM")
	}
}
