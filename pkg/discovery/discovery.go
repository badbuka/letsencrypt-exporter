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

// Scan walks <root>/live/* and returns one Cert per directory that contains a
// readable cert.pem. Symlinks are resolved so callers can stat the underlying
// file directly. The result is sorted by Domain for deterministic output.
//
// If <root>/live does not exist, Scan returns an empty slice and no error so
// that callers can distinguish "no certificates yet" from "configuration is
// broken".
func Scan(root string) ([]Cert, error) {
	if root == "" {
		root = DefaultRoot
	}

	liveDir := filepath.Join(root, "live")
	entries, err := os.ReadDir(liveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", liveDir, err)
	}

	out := make([]Cert, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if name == "README" || name == "" {
			continue
		}
		// certbot creates real directories; some setups symlink the lineage
		// itself, so accept either as long as cert.pem resolves.
		if !e.IsDir() {
			info, statErr := os.Stat(filepath.Join(liveDir, name))
			if statErr != nil || !info.IsDir() {
				continue
			}
		}

		certPath := filepath.Join(liveDir, name, "cert.pem")
		resolved, rerr := filepath.EvalSymlinks(certPath)
		if rerr != nil {
			continue
		}
		out = append(out, Cert{Domain: name, CertPath: resolved})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}
