package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/badbuka/letsencrypt-exporter/pkg/discovery"
)

// runDebug performs a one-shot dump of what discovery sees under the
// configured Let's Encrypt root and why each entry was kept or skipped. It
// returns a process exit code so main can call os.Exit directly.
func runDebug(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("debug", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("letsencrypt-path", envOrDefault("LETSENCRYPT_PATH", discovery.DefaultRoot),
		"Path to the Let's Encrypt root directory (env: LETSENCRYPT_PATH)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	out := &errWriter{w: stdout}
	errOut := &errWriter{w: stderr}

	out.printf("letsencrypt-exporter debug\n")
	out.printf("  root:     %s\n", *path)

	host, _ := os.Hostname()
	out.printf("  hostname: %s\n", host)

	live := filepath.Join(*path, "live")
	if info, err := os.Stat(live); err != nil {
		out.printf("  live dir: %s -> ERROR %v\n", live, err)
		return finalize(out, errOut, 1)
	} else {
		out.printf("  live dir: %s (mode=%v)\n", live, info.Mode().Perm())
	}
	out.println()

	entries, err := discovery.ScanVerbose(*path)
	if err != nil {
		errOut.printf("scan failed: %v\n", err)
		return finalize(out, errOut, 1)
	}
	if len(entries) == 0 {
		out.println("no entries found under live/")
		return finalize(out, errOut, 0)
	}

	var ok, skipped, parseFail int
	for _, e := range entries {
		if e.Error != nil {
			skipped++
			out.printf("[SKIP]  %s\n        reason: %v\n\n", e.Cert.Domain, e.Error)
			continue
		}
		cert, perr := loadCertForDebug(e.Cert.CertPath)
		if perr != nil {
			parseFail++
			out.printf("[PARSE-ERR] %s\n            path:   %s\n            error:  %v\n\n",
				e.Cert.Domain, e.Cert.CertPath, perr)
			continue
		}
		ok++
		out.printf("[OK]    %s\n", e.Cert.Domain)
		out.printf("        path:       %s\n", e.Cert.CertPath)
		out.printf("        cn:         %s\n", cert.Subject.CommonName)
		out.printf("        issuer:     %s\n", cert.Issuer.CommonName)
		out.printf("        not_before: %s\n", cert.NotBefore.UTC().Format(time.RFC3339))
		out.printf("        not_after:  %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
		out.printf("        expires_in: %s\n", time.Until(cert.NotAfter).Round(time.Second))
		if len(cert.DNSNames) > 0 {
			out.printf("        sans:       %v\n", cert.DNSNames)
		}
		out.println()
	}

	out.printf("summary: ok=%d skipped=%d parse_errors=%d total=%d\n",
		ok, skipped, parseFail, len(entries))

	exit := 0
	if skipped+parseFail > 0 {
		exit = 1
	}
	return finalize(out, errOut, exit)
}

func finalize(out, errOut *errWriter, code int) int {
	if err := out.err; err != nil {
		errOut.printf("write stdout: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func envOrDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func loadCertForDebug(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: same justification as collector.loadCertificate
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in file (size=%d bytes, first 32: %q)", len(raw), firstN(raw, 32))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509: %w", err)
	}
	return cert, nil
}

func firstN(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// errWriter is a tiny io.Writer wrapper that captures the first write error
// it encounters. Callers can chain printf/println calls without checking
// each one and inspect .err once at the end.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, a...)
}

func (e *errWriter) println(a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintln(e.w, a...)
}
