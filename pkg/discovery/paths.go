package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/badbuka/letsencrypt-exporter/pkg/cert"
)

var certFileSuffixes = []string{".pem", ".crt", ".cer"}

var preferredCertBasenames = []string{"cert.pem", "cert.crt", "cert.cer"}

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
		if !cert.LooksLikeCertificateFile(path) {
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

	var brokenPreferred *Entry
	for _, name := range preferredCertBasenames {
		preferredPath := filepath.Join(dir, name)
		if _, err := os.Stat(preferredPath); err != nil {
			continue
		}
		resolved, rerr := resolveCertPath(preferredPath)
		entry := Entry{Cert: Cert{FallbackID: filepath.Base(dir)}}
		if rerr != nil {
			entry.Error = rerr
		} else {
			entry.Cert.CertPath = resolved
		}
		if entry.Error == nil {
			return []Entry{entry}, nil
		}
		brokenPreferred = &entry
		break
	}

	var out []Entry
	if brokenPreferred != nil {
		out = append(out, *brokenPreferred)
	}
	for _, e := range entries {
		name := e.Name()
		full := filepath.Join(dir, name)
		if e.IsDir() {
			subEntries, subErr := scanOnePathVerbose(full)
			if subErr != nil {
				return nil, subErr
			}
			out = append(out, subEntries...)
			continue
		}
		if isPreferredCertBasename(name) {
			continue
		}
		if !isCertFilename(full) || isPrivateKeyFilename(name) {
			continue
		}
		if !cert.LooksLikeCertificateFile(full) {
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

func isPreferredCertBasename(name string) bool {
	lower := strings.ToLower(name)
	for _, preferred := range preferredCertBasenames {
		if lower == preferred {
			return true
		}
	}
	return false
}
