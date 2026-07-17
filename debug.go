package main

import (
	"cmp"
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
	path := fs.String("letsencrypt-path", cmp.Or(os.Getenv("LETSENCRYPT_PATH"), discovery.DefaultRoot),
		"Path to the Let's Encrypt / certbot root directory (env: LETSENCRYPT_PATH)")
	certPaths := fs.String("cert-paths", os.Getenv("CERT_PATHS"),
		"Comma-separated PEM files or directories to scan (env: CERT_PATHS)")
	recursivePaths := fs.String("cert-recursive-paths", os.Getenv("CERT_RECURSIVE_PATHS"),
		"Comma-separated roots for recursive PEM walk (env: CERT_RECURSIVE_PATHS)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg := discovery.Config{
		CertbotRoot:    *path,
		Paths:          parseList(*certPaths),
		RecursiveRoots: parseList(*recursivePaths),
	}

	// ponytail: write errors ignored — one-shot dump to stdout; exit code
	// reflects scan results, not pipe state
	_, _ = fmt.Fprintf(stdout, "letsencrypt-exporter debug\n")
	_, _ = fmt.Fprintf(stdout, "  certbot root:     %s\n", cfg.CertbotRoot)
	_, _ = fmt.Fprintf(stdout, "  extra paths:      %d\n", len(cfg.Paths))
	for _, p := range cfg.Paths {
		_, _ = fmt.Fprintf(stdout, "    - %s\n", p)
	}
	_, _ = fmt.Fprintf(stdout, "  recursive roots:  %d\n", len(cfg.RecursiveRoots))
	for _, p := range cfg.RecursiveRoots {
		_, _ = fmt.Fprintf(stdout, "    - %s\n", p)
	}

	host, _ := os.Hostname()
	_, _ = fmt.Fprintf(stdout, "  hostname: %s\n", host)

	live := filepath.Join(cfg.CertbotRoot, "live")
	//nolint:gosec // G703: operator-supplied root is the point of the debug command
	if info, err := os.Stat(live); err != nil {
		_, _ = fmt.Fprintf(stdout, "  live dir: %s -> %v\n", live, err)
	} else {
		_, _ = fmt.Fprintf(stdout, "  live dir: %s (mode=%v)\n", live, info.Mode().Perm())
	}
	_, _ = fmt.Fprintln(stdout)

	entries, err := discovery.ScanAllVerbose(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(stdout, "no certificate entries found")
		return 0
	}

	var ok, skipped, parseFail int
	for _, e := range entries {
		if e.Error != nil {
			skipped++
			_, _ = fmt.Fprintf(stdout, "[SKIP]  %s\n        reason: %v\n\n", e.Cert.FallbackID, e.Error)
			continue
		}
		parsed, perr := certpkg.Load(e.Cert.CertPath)
		if perr != nil {
			parseFail++
			_, _ = fmt.Fprintf(stdout, "[PARSE-ERR] %s\n            path:   %s\n            error:  %v\n\n",
				e.Cert.FallbackID, e.Cert.CertPath, perr)
			continue
		}
		domain := certpkg.PrimaryDomain(parsed, e.Cert.FallbackID)
		ok++
		_, _ = fmt.Fprintf(stdout, "[OK]    %s\n", domain)
		_, _ = fmt.Fprintf(stdout, "        fallback_id: %s\n", e.Cert.FallbackID)
		_, _ = fmt.Fprintf(stdout, "        path:        %s\n", e.Cert.CertPath)
		_, _ = fmt.Fprintf(stdout, "        cn:          %s\n", parsed.Subject.CommonName)
		_, _ = fmt.Fprintf(stdout, "        issuer:      %s\n", parsed.Issuer.CommonName)
		_, _ = fmt.Fprintf(stdout, "        not_before:  %s\n", parsed.NotBefore.UTC().Format(time.RFC3339))
		_, _ = fmt.Fprintf(stdout, "        not_after:   %s\n", parsed.NotAfter.UTC().Format(time.RFC3339))
		_, _ = fmt.Fprintf(stdout, "        expires_in:  %s\n", time.Until(parsed.NotAfter).Round(time.Second))
		if len(parsed.DNSNames) > 0 {
			_, _ = fmt.Fprintf(stdout, "        sans:        %v\n", parsed.DNSNames)
		}
		_, _ = fmt.Fprintln(stdout)
	}

	_, _ = fmt.Fprintf(stdout, "summary: ok=%d skipped=%d parse_errors=%d total=%d\n",
		ok, skipped, parseFail, len(entries))

	if skipped+parseFail > 0 {
		return 1
	}
	return 0
}
