// Package cert loads X.509 certificates (PEM or DER) and extracts primary
// domain names from parsed certificate fields.
package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Load reads a certificate file and returns the first X.509 certificate.
// PEM-encoded files may contain a chain; only the first CERTIFICATE block is
// used. DER-encoded files (common for .cer) are also supported.
func Load(path string) (*x509.Certificate, error) {
	// path is supplied by discovery from the operator-configured roots;
	// reading it is the whole purpose of this exporter.
	raw, err := os.ReadFile(path) //nolint:gosec // G304: see comment above
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	parsed, err := parseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return parsed, nil
}

// LooksLikeCertificate reports whether raw contains a parseable X.509
// certificate in PEM or DER form.
func LooksLikeCertificate(raw []byte) bool {
	_, err := parseCertificate(raw)
	return err == nil
}

// LooksLikeCertificateFile reads path and reports whether it contains a
// certificate.
func LooksLikeCertificateFile(path string) bool {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: discovery reads operator-configured cert paths
	if err != nil {
		return false
	}
	return LooksLikeCertificate(raw)
}

func parseCertificate(raw []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("expected CERTIFICATE PEM block, got %q", block.Type)
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(raw)
}

// PrimaryDomain returns the best hostname label for a certificate: the first
// DNS SAN when present, otherwise the subject common name, otherwise fallback.
func PrimaryDomain(c *x509.Certificate, fallback string) string {
	if c == nil {
		return fallback
	}
	if len(c.DNSNames) > 0 {
		return c.DNSNames[0]
	}
	if cn := c.Subject.CommonName; cn != "" {
		return cn
	}
	return fallback
}
