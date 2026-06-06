package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	certpkg "github.com/badbuka/letsencrypt-exporter/pkg/cert"
	"github.com/badbuka/letsencrypt-exporter/pkg/discovery"
)

// runDebug performs a one-shot dump of what discovery sees under the
// configured certificate roots and why each entry was kept or skipped.
func runDebug(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("debug", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("letsencrypt-path", envOrDefault("LETSENCRYPT_PATH", discovery.DefaultRoot),
		"Path to the Let's Encrypt / certbot root directory (env: LETSENCRYPT_PATH)")
	certPaths := fs.String("cert-paths", envOrDefault("CERT_PATHS", ""),
		"Comma-separated PEM files or directories to scan (env: CERT_PATHS)")
	recursivePaths := fs.String("cert-recursive-paths", envOrDefault("CERT_RECURSIVE_PATHS", ""),
		"Comma-separated roots for recursive PEM walk (env: CERT_RECURSIVE_PATHS)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg := discovery.Config{
		CertbotRoot:    *path,
		Paths:          parseList(*certPaths),
		RecursiveRoots: parseList(*recursivePaths),
	}

	out := &errWriter{w: stdout}
	errOut := &errWriter{w: stderr}

	out.printf("letsencrypt-exporter debug\n")
	out.printf("  certbot root:     %s\n", cfg.CertbotRoot)
	out.printf("  extra paths:      %d\n", len(cfg.Paths))
	for _, p := range cfg.Paths {
		out.printf("    - %s\n", p)
	}
	out.printf("  recursive roots:  %d\n", len(cfg.RecursiveRoots))
	for _, p := range cfg.RecursiveRoots {
		out.printf("    - %s\n", p)
	}

	host, _ := os.Hostname()
	out.printf("  hostname: %s\n", host)

	live := filepath.Join(cfg.CertbotRoot, "live")
	if info, err := os.Stat(live); err != nil {
		out.printf("  live dir: %s -> %v\n", live, err)
	} else {
		out.printf("  live dir: %s (mode=%v)\n", live, info.Mode().Perm())
	}
	out.println()

	entries, err := discovery.ScanAllVerbose(cfg)
	if err != nil {
		errOut.printf("scan failed: %v\n", err)
		return finalize(out, errOut, 1)
	}
	if len(entries) == 0 {
		out.println("no certificate entries found")
		return finalize(out, errOut, 0)
	}

	var ok, skipped, parseFail int
	for _, e := range entries {
		if e.Error != nil {
			skipped++
			out.printf("[SKIP]  %s\n        reason: %v\n\n", e.Cert.FallbackID, e.Error)
			continue
		}
		parsed, perr := certpkg.Load(e.Cert.CertPath)
		if perr != nil {
			parseFail++
			out.printf("[PARSE-ERR] %s\n            path:   %s\n            error:  %v\n\n",
				e.Cert.FallbackID, e.Cert.CertPath, perr)
			continue
		}
		domain := certpkg.PrimaryDomain(parsed, e.Cert.FallbackID)
		ok++
		out.printf("[OK]    %s\n", domain)
		out.printf("        fallback_id: %s\n", e.Cert.FallbackID)
		out.printf("        path:        %s\n", e.Cert.CertPath)
		out.printf("        cn:          %s\n", parsed.Subject.CommonName)
		out.printf("        issuer:      %s\n", parsed.Issuer.CommonName)
		out.printf("        not_before:  %s\n", parsed.NotBefore.UTC().Format(time.RFC3339))
		out.printf("        not_after:   %s\n", parsed.NotAfter.UTC().Format(time.RFC3339))
		out.printf("        expires_in:  %s\n", time.Until(parsed.NotAfter).Round(time.Second))
		if len(parsed.DNSNames) > 0 {
			out.printf("        sans:        %v\n", parsed.DNSNames)
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
