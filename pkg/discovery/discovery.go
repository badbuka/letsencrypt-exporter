// Package discovery scans a Let's Encrypt directory tree and returns the set
// of certificates that should be monitored.
//
// It deliberately knows nothing about Prometheus so it can be reused by
// arbitrary tooling (alerting CLIs, ad-hoc reports, tests).
package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Cert describes a single certificate lineage discovered under a Let's Encrypt
// root directory.
type Cert struct {
	// Domain is the name of the live/<domain> directory. Certbot uses this as
	// the lineage identifier; it is the most stable label for metrics.
	Domain string
	// CertPath is the absolute, symlink-resolved path to cert.pem.
	CertPath string
}

// DefaultRoot is the conventional Let's Encrypt directory on Linux.
const DefaultRoot = "/etc/letsencrypt"

// Entry is a single observation produced by ScanVerbose. Exactly one of Cert
// or Error is informative: if Error is nil the entry was usable, otherwise
// Cert.Domain still names the live/ subdirectory but Cert.CertPath may be
// empty. Verbose output is intended for human-driven debugging, never for
// metric emission.
type Entry struct {
	Cert  Cert
	Error error
}

// Scan walks <root>/live/* and returns one Cert per directory that contains a
// readable cert.pem. Symlinks are resolved so callers can stat the underlying
// file directly. The result is sorted by Domain for deterministic output.
//
// If <root>/live does not exist, Scan returns an empty slice and no error so
// that callers can distinguish "no certificates yet" from "configuration is
// broken".
func Scan(root string) ([]Cert, error) {
	entries, err := ScanVerbose(root)
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

// ScanVerbose is the same walk as Scan but reports a per-entry result
// (success or skip reason) for every name found under <root>/live. It is
// intended for the debug subcommand and ad-hoc diagnostics.
func ScanVerbose(root string) ([]Entry, error) {
	if root == "" {
		root = DefaultRoot
	}

	liveDir := filepath.Join(root, "live")
	dirEntries, err := os.ReadDir(liveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", liveDir, err)
	}

	out := make([]Entry, 0, len(dirEntries))
	for _, e := range dirEntries {
		name := e.Name()
		if name == "" || name == "README" {
			continue
		}

		entry := Entry{Cert: Cert{Domain: name}}

		if !e.IsDir() {
			info, statErr := os.Stat(filepath.Join(liveDir, name))
			switch {
			case statErr != nil:
				entry.Error = fmt.Errorf("stat: %w", statErr)
				out = append(out, entry)
				continue
			case !info.IsDir():
				entry.Error = fmt.Errorf("not a directory")
				out = append(out, entry)
				continue
			}
		}

		certPath := filepath.Join(liveDir, name, "cert.pem")
		resolved, rerr := filepath.EvalSymlinks(certPath)
		if rerr != nil {
			entry.Error = fmt.Errorf("resolve cert.pem: %w", rerr)
			out = append(out, entry)
			continue
		}
		entry.Cert.CertPath = resolved
		out = append(out, entry)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Cert.Domain < out[j].Cert.Domain })
	return out, nil
}
