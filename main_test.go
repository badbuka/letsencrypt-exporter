package main

import (
	"os"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("LETSENCRYPT_PATH", "")
	t.Setenv("CERT_PATHS", "")
	t.Setenv("CERT_RECURSIVE_PATHS", "")
	t.Setenv("PORT", "")
	t.Setenv("HOSTNAME", "")
	t.Setenv("DEBUG", "")
	os.Unsetenv("LETSENCRYPT_PATH")
	os.Unsetenv("CERT_PATHS")
	os.Unsetenv("CERT_RECURSIVE_PATHS")
	os.Unsetenv("PORT")
	os.Unsetenv("HOSTNAME")
	os.Unsetenv("DEBUG")

	cfg, err := loadConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LetsencryptPath != "/etc/letsencrypt" {
		t.Errorf("unexpected default path: %q", cfg.LetsencryptPath)
	}
	if cfg.Port != 8622 {
		t.Errorf("unexpected default port: %d", cfg.Port)
	}
	if cfg.Debug {
		t.Errorf("unexpected default debug value: %v", cfg.Debug)
	}
}

func TestLoadConfigEnv(t *testing.T) {
	t.Setenv("LETSENCRYPT_PATH", "/srv/le")
	t.Setenv("CERT_PATHS", "/a.pem,/b.pem")
	t.Setenv("CERT_RECURSIVE_PATHS", "/srv/certs")
	t.Setenv("PORT", "9100")
	t.Setenv("HOSTNAME", "edge-7")
	t.Setenv("DEBUG", "true")

	cfg, err := loadConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LetsencryptPath != "/srv/le" || cfg.Port != 9100 || cfg.Hostname != "edge-7" || !cfg.Debug {
		t.Errorf("env not applied: %+v", cfg)
	}
	if cfg.CertPaths != "/a.pem,/b.pem" || cfg.CertRecursivePaths != "/srv/certs" {
		t.Errorf("cert path env not applied: %+v", cfg)
	}
}

func TestParseList(t *testing.T) {
	got := parseList(" /a.pem , , /b.pem ")
	if len(got) != 2 || got[0] != "/a.pem" || got[1] != "/b.pem" {
		t.Fatalf("parseList: %#v", got)
	}
	if parseList("") != nil {
		t.Fatalf("expected nil for empty list")
	}
}

func TestLoadConfigFlagsOverrideEnv(t *testing.T) {
	t.Setenv("LETSENCRYPT_PATH", "/srv/le")
	t.Setenv("PORT", "9100")
	t.Setenv("HOSTNAME", "edge-7")
	t.Setenv("DEBUG", "true")

	cfg, err := loadConfig([]string{
		"-letsencrypt-path", "/opt/le",
		"-port", "9999",
		"-hostname", "override",
		"-debug=false",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LetsencryptPath != "/opt/le" || cfg.Port != 9999 || cfg.Hostname != "override" || cfg.Debug {
		t.Errorf("flags did not override env: %+v", cfg)
	}
}
