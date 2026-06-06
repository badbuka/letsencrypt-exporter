package discovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/badbuka/letsencrypt-exporter/pkg/cert"
)

func TestScanCertbot(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, "live")
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, d := range []string{"a.example.com", "b.example.com", "README"} {
		dir := filepath.Join(live, d)
		if d == "README" {
			if err := os.WriteFile(dir, []byte("ignore me"), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("dummy"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.MkdirAll(filepath.Join(live, "no-cert.example.com"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 certs, got %d: %#v", len(got), got)
	}
	if got[0].FallbackID != "a.example.com" || got[1].FallbackID != "b.example.com" {
		t.Fatalf("unexpected order: %#v", got)
	}
	for _, c := range got {
		if !filepath.IsAbs(c.CertPath) {
			t.Errorf("CertPath should be absolute, got %q", c.CertPath)
		}
	}
}

func TestScanMissingRoot(t *testing.T) {
	got, err := Scan(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("expected nil error for missing root, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %#v", got)
	}
}

func TestScanVerboseReportsSkips(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, "live")
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}

	good := filepath.Join(live, "good.example.com")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(good, "cert.pem"), []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(live, "missing-cert.example.com"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(live, "stray-file"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := ScanVerbose(root)
	if err != nil {
		t.Fatalf("ScanVerbose: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d: %#v", len(entries), entries)
	}

	byFallback := map[string]Entry{}
	for _, e := range entries {
		byFallback[e.Cert.FallbackID] = e
	}

	if e := byFallback["good.example.com"]; e.Error != nil {
		t.Errorf("good entry should have no error, got %v", e.Error)
	}
	if e := byFallback["missing-cert.example.com"]; e.Error == nil {
		t.Errorf("missing-cert entry should have a resolve error")
	}
	if e := byFallback["stray-file"]; e.Error == nil {
		t.Errorf("stray file should have a not-a-directory error")
	}
}

func TestScanPathsFileAndDirectory(t *testing.T) {
	root := t.TempDir()
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	single := filepath.Join(root, "edge.pem")
	cert.WriteTestCert(t, single, notAfter, []string{"edge.example.com"})

	dir := filepath.Join(root, "nginx")
	cert.WriteTestCert(t, filepath.Join(dir, "fullchain.pem"), notAfter, []string{"nginx.example.com"})

	got, err := ScanAll(Config{Paths: []string{single, dir}})
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 certs, got %d: %#v", len(got), got)
	}
}

func TestScanPathsMissingPathVerbose(t *testing.T) {
	entries, err := ScanAllVerbose(Config{Paths: []string{"/does/not/exist.pem"}})
	if err != nil {
		t.Fatalf("ScanAllVerbose: %v", err)
	}
	if len(entries) != 1 || entries[0].Error == nil {
		t.Fatalf("expected one skip entry, got %#v", entries)
	}
}

func TestScanRecursive(t *testing.T) {
	root := t.TempDir()
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	nested := filepath.Join(root, "certs", "nested")
	cert.WriteTestCert(t, filepath.Join(nested, "site.crt"), notAfter, []string{"site.example.com"})
	cert.WriteTestCert(t, filepath.Join(root, "privkey.pem"), notAfter, []string{"ignored.example.com"})

	got, err := ScanAll(Config{RecursiveRoots: []string{root}})
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 cert, got %d: %#v", len(got), got)
	}
	if got[0].FallbackID != "site.crt" {
		t.Fatalf("unexpected fallback: %q", got[0].FallbackID)
	}
}

func TestScanAllDedupesByCertPath(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, "live", "example.com")
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}

	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	pemPath := filepath.Join(live, "cert.pem")
	cert.WriteTestCert(t, pemPath, notAfter, []string{"example.com"})

	got, err := ScanAll(Config{
		CertbotRoot: root,
		Paths:       []string{pemPath},
	})
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected deduped single cert, got %d: %#v", len(got), got)
	}
}

func TestScanAllRecursiveOnlyNonCertbot(t *testing.T) {
	root := t.TempDir()
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cert.WriteTestCert(t, filepath.Join(root, "custom.pem"), notAfter, []string{"custom.example.com"})

	got, err := ScanAll(Config{
		CertbotRoot:    filepath.Join(t.TempDir(), "missing"),
		RecursiveRoots: []string{root},
	})
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 cert from recursive scan, got %d", len(got))
	}
}
