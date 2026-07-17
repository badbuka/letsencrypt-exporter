// Package discovery scans certificate locations and returns the set of
// certificates that should be monitored.
//
// It deliberately knows nothing about Prometheus so it can be reused by
// arbitrary tooling (alerting CLIs, ad-hoc reports, tests).
package discovery

import (
	"fmt"
	"sort"
)

// Cert describes a single certificate discovered on disk.
type Cert struct {
	// CertPath is the absolute, symlink-resolved path to the PEM file.
	CertPath string
	// FallbackID is the certbot lineage directory name, PEM basename, or
	// another filesystem identifier used when the certificate carries no
	// DNS names or common name.
	FallbackID string
}

// DefaultRoot is the conventional Let's Encrypt directory on Linux.
const DefaultRoot = "/etc/letsencrypt"

// Config selects which discovery sources to run.
type Config struct {
	// CertbotRoot is the certbot root directory (<root>/live/*). Empty skips
	// the certbot scan.
	CertbotRoot string
	// Paths lists explicit PEM files or directories to scan (non-recursive).
	Paths []string
	// RecursiveRoots lists directories walked recursively for PEM files.
	RecursiveRoots []string
	// Logger, if non-nil, receives per-path scan lines for Paths and
	// RecursiveRoots. Certbot discovery is not logged.
	Logger func(format string, args ...any)
}

// Entry is a single observation produced by ScanAllVerbose. If Error is nil
// the entry was usable; otherwise Cert.FallbackID still names the source but
// Cert.CertPath may be empty.
type Entry struct {
	Cert  Cert
	Error error
}

// ScanAll merges certificates from all enabled discovery sources.
func ScanAll(cfg Config) ([]Cert, error) {
	entries, err := ScanAllVerbose(cfg)
	if err != nil {
		return nil, err
	}
	out := make([]Cert, 0, len(entries))
	for _, e := range entries {
		if e.Error != nil {
			continue
		}
		out = append(out, e.Cert)
	}
	return out, nil
}

// ScanAllVerbose runs every enabled scanner and reports per-entry results.
func ScanAllVerbose(cfg Config) ([]Entry, error) {
	var out []Entry

	if cfg.CertbotRoot != "" {
		entries, err := scanCertbotVerbose(cfg.CertbotRoot)
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}

	for _, p := range cfg.Paths {
		if cfg.Logger != nil {
			cfg.Logger("extra path scan start path=%q", p)
		}
		entries, err := scanPathsVerbose([]string{p})
		if err != nil {
			if cfg.Logger != nil {
				cfg.Logger("extra path scan failed path=%q: %v", p, err)
			}
			return nil, fmt.Errorf("scan path %q: %w", p, err)
		}
		logScanEntries(cfg.Logger, "extra path", p, entries)
		out = append(out, entries...)
	}

	for _, root := range cfg.RecursiveRoots {
		if cfg.Logger != nil {
			cfg.Logger("recursive path scan start root=%q", root)
		}
		entries, err := scanRecursiveVerbose([]string{root})
		if err != nil {
			if cfg.Logger != nil {
				cfg.Logger("recursive path scan failed root=%q: %v", root, err)
			}
			return nil, fmt.Errorf("scan recursive %q: %w", root, err)
		}
		logScanEntries(cfg.Logger, "recursive path", root, entries)
		out = append(out, entries...)
	}

	return mergeEntries(out), nil
}

func logScanEntries(logf func(format string, args ...any), source, root string, entries []Entry) {
	if logf == nil {
		return
	}
	var found, skipped int
	for _, e := range entries {
		if e.Error != nil {
			skipped++
			logf("%s scan skip root=%q fallback_id=%q: %v", source, root, e.Cert.FallbackID, e.Error)
			continue
		}
		found++
		logf("%s scan found root=%q lineage=%q path=%q", source, root, e.Cert.FallbackID, e.Cert.CertPath)
	}
	logf("%s scan done root=%q found=%d skipped=%d", source, root, found, skipped)
}

func mergeEntries(entries []Entry) []Entry {
	seen := make(map[string]struct{}, len(entries))
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if e.Error != nil || e.Cert.CertPath == "" {
			out = append(out, e)
			continue
		}
		if _, ok := seen[e.Cert.CertPath]; ok {
			continue
		}
		seen[e.Cert.CertPath] = struct{}{}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Cert.FallbackID != out[j].Cert.FallbackID {
			return out[i].Cert.FallbackID < out[j].Cert.FallbackID
		}
		return out[i].Cert.CertPath < out[j].Cert.CertPath
	})
	return out
}
