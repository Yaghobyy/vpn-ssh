//go:build windows

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSettingsRoundTripProtectsCredentials(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())

	want := AppSettings{
		Host:       "vpn.example.com",
		Port:       2222,
		Username:   "alice",
		Password:   "not-plain-text-password",
		PrivateKey: "private-key-material",
		ProxyPort:  1081,
		Mode:       "full",
		DNS:        []string{"9.9.9.9", "149.112.112.112"},
		UseIPv6:    true,
		AuthMethod: "key",
	}

	app := &App{}
	if err := app.SaveSettings(want); err != nil {
		t.Fatalf("SaveSettings() error = %v", err)
	}
	got := app.LoadSettings()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadSettings() = %+v, want %+v", got, want)
	}

	path := filepath.Join(os.Getenv("APPDATA"), "SSH Tunnel", "settings.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(data), want.Password) || strings.Contains(string(data), want.PrivateKey) {
		t.Fatal("credentials were written to settings in plain text")
	}
}
