package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScan(t *testing.T) {
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
	if got[0].Domain != "a.example.com" || got[1].Domain != "b.example.com" {
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
