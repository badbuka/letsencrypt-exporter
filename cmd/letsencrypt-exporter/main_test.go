package main

import (
	"os"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("LETSENCRYPT_PATH", "")
	t.Setenv("PORT", "")
	t.Setenv("HOSTNAME", "")
	os.Unsetenv("LETSENCRYPT_PATH")
	os.Unsetenv("PORT")
	os.Unsetenv("HOSTNAME")

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
}

func TestLoadConfigEnv(t *testing.T) {
	t.Setenv("LETSENCRYPT_PATH", "/srv/le")
	t.Setenv("PORT", "9100")
	t.Setenv("HOSTNAME", "edge-7")

	cfg, err := loadConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LetsencryptPath != "/srv/le" || cfg.Port != 9100 || cfg.Hostname != "edge-7" {
		t.Errorf("env not applied: %+v", cfg)
	}
}

func TestLoadConfigFlagsOverrideEnv(t *testing.T) {
	t.Setenv("LETSENCRYPT_PATH", "/srv/le")
	t.Setenv("PORT", "9100")
	t.Setenv("HOSTNAME", "edge-7")

	cfg, err := loadConfig([]string{
		"-letsencrypt-path", "/opt/le",
		"-port", "9999",
		"-hostname", "override",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LetsencryptPath != "/opt/le" || cfg.Port != 9999 || cfg.Hostname != "override" {
		t.Errorf("flags did not override env: %+v", cfg)
	}
}
