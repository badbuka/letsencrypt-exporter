package discovery

import (
	"fmt"
	"os"
	"path/filepath"
)

func scanCertbotVerbose(root string) ([]Entry, error) {
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

		entry := Entry{Cert: Cert{FallbackID: name}}

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
		resolved, rerr := resolveCertPath(certPath)
		if rerr != nil {
			entry.Error = fmt.Errorf("resolve cert.pem: %w", rerr)
			out = append(out, entry)
			continue
		}
		entry.Cert.CertPath = resolved
		out = append(out, entry)
	}

	return out, nil
}
