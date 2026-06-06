// Package cert loads PEM-encoded X.509 certificates and extracts primary
// domain names from parsed certificate fields.
package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Load reads a PEM file and returns the first CERTIFICATE block.
func Load(path string) (*x509.Certificate, error) {
	// path is supplied by discovery from the operator-configured roots;
	// reading it is the whole purpose of this exporter.
	raw, err := os.ReadFile(path) //nolint:gosec // G304: see comment above
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE PEM block in %s, got %q", path, block.Type)
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return parsed, nil
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
