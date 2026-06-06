package discovery

import (
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func scanRecursiveVerbose(roots []string) ([]Entry, error) {
	var out []Entry
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		entries, err := scanOneRecursiveVerbose(root)
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}
	return out, nil
}

func scanOneRecursiveVerbose(root string) ([]Entry, error) {
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return []Entry{{
				Cert:  Cert{FallbackID: filepath.Base(root)},
				Error: fmt.Errorf("stat: %w", err),
			}}, nil
		}
		return nil, fmt.Errorf("stat %s: %w", root, err)
	}

	var out []Entry
	walkFn := func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !isCertFilename(path) || isPrivateKeyFilename(name) {
			return nil
		}
		if !isCertificatePEM(path) {
			return nil
		}
		resolved, rerr := resolveCertPath(path)
		entry := Entry{Cert: Cert{FallbackID: name}}
		if rerr != nil {
			entry.Error = rerr
		} else {
			entry.Cert.CertPath = resolved
		}
		out = append(out, entry)
		return nil
	}

	if info.IsDir() {
		if err := filepath.WalkDir(root, walkFn); err != nil {
			return nil, fmt.Errorf("walk %s: %w", root, err)
		}
		return out, nil
	}

	if !isCertFilename(root) || isPrivateKeyFilename(filepath.Base(root)) {
		return []Entry{{
			Cert:  Cert{FallbackID: filepath.Base(root)},
			Error: fmt.Errorf("not a certificate file"),
		}}, nil
	}
	if !isCertificatePEM(root) {
		return []Entry{{
			Cert:  Cert{FallbackID: filepath.Base(root)},
			Error: fmt.Errorf("no CERTIFICATE PEM block"),
		}}, nil
	}
	resolved, rerr := resolveCertPath(root)
	entry := Entry{Cert: Cert{FallbackID: filepath.Base(root)}}
	if rerr != nil {
		entry.Error = rerr
	} else {
		entry.Cert.CertPath = resolved
	}
	return []Entry{entry}, nil
}

func isPrivateKeyFilename(name string) bool {
	lower := strings.ToLower(name)
	if lower == "privkey.pem" || strings.HasSuffix(lower, "-key.pem") {
		return true
	}
	return false
}

func isCertificatePEM(path string) bool {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: discovery reads operator-configured cert paths
	if err != nil {
		return false
	}
	block, _ := pem.Decode(raw)
	return block != nil && block.Type == "CERTIFICATE"
}

func resolveCertPath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	return abs, nil
}
