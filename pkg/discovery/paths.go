package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var certFileSuffixes = []string{".pem", ".crt", ".cer"}

// entryError returns a single verbose entry carrying err. The outer error is
// always nil because ScanAllVerbose reports per-path failures in Entry.Error.
func entryError(fallbackID string, err error) ([]Entry, error) {
	return []Entry{{Cert: Cert{FallbackID: fallbackID}, Error: err}}, nil
}

func scanPathsVerbose(paths []string) ([]Entry, error) {
	var out []Entry
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		entries, err := scanOnePathVerbose(p)
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}
	return out, nil
}

func scanOnePathVerbose(path string) ([]Entry, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return entryError(filepath.Base(path), fmt.Errorf("stat: %w", err))
		}
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	if !info.IsDir() {
		if !isCertFilename(path) {
			return entryError(filepath.Base(path), fmt.Errorf("not a certificate file"))
		}
		resolved, resolveErr := resolveCertPath(path)
		if resolveErr != nil {
			return entryError(filepath.Base(path), resolveErr)
		}
		return []Entry{{Cert: Cert{
			FallbackID: filepath.Base(path),
			CertPath:   resolved,
		}}}, nil
	}

	return scanDirNonRecursive(path)
}

func scanDirNonRecursive(dir string) ([]Entry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	certbotPath := filepath.Join(dir, "cert.pem")
	if _, err := os.Stat(certbotPath); err == nil {
		resolved, rerr := resolveCertPath(certbotPath)
		entry := Entry{Cert: Cert{FallbackID: filepath.Base(dir)}}
		if rerr != nil {
			entry.Error = rerr
		} else {
			entry.Cert.CertPath = resolved
		}
		return []Entry{entry}, nil
	}

	var out []Entry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		full := filepath.Join(dir, name)
		if !isCertFilename(full) || isPrivateKeyFilename(name) {
			continue
		}
		resolved, rerr := resolveCertPath(full)
		entry := Entry{Cert: Cert{FallbackID: name}}
		if rerr != nil {
			entry.Error = rerr
		} else {
			entry.Cert.CertPath = resolved
		}
		out = append(out, entry)
	}
	return out, nil
}

func isCertFilename(path string) bool {
	lower := strings.ToLower(path)
	for _, suffix := range certFileSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
