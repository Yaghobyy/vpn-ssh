package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"ssh-tunnel/internal/tunnel"
)

// App struct
type App struct {
	ctx     context.Context
	service *tunnel.Service
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{service: tunnel.NewService()}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

type ConnectRequest struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	PrivateKey string   `json:"privateKey"`
	ProxyPort  int      `json:"proxyPort"`
	Mode       string   `json:"mode"`
	DNS        []string `json:"dns"`
	UseIPv6    bool     `json:"useIPv6"`
}

type ConnectionStatus struct {
	State         string `json:"state"`
	Address       string `json:"address"`
	Proxy         string `json:"proxy"`
	Message       string `json:"message"`
	UploadBytes   uint64 `json:"uploadBytes"`
	DownloadBytes uint64 `json:"downloadBytes"`
}

type AppSettings struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	PrivateKey string   `json:"privateKey"`
	ProxyPort  int      `json:"proxyPort"`
	Mode       string   `json:"mode"`
	DNS        []string `json:"dns"`
	UseIPv6    bool     `json:"useIPv6"`
	AuthMethod string   `json:"authMethod"`
}

type persistedAppSettings struct {
	Host                string   `json:"host"`
	Port                int      `json:"port"`
	Username            string   `json:"username"`
	EncryptedPassword   []byte   `json:"password"`
	EncryptedPrivateKey []byte   `json:"privateKey"`
	ProxyPort           int      `json:"proxyPort"`
	Mode                string   `json:"mode"`
	DNS                 []string `json:"dns"`
	UseIPv6             bool     `json:"useIPv6"`
	AuthMethod          string   `json:"authMethod"`
}

func defaultAppSettings() AppSettings {
	return AppSettings{
		Port:       22,
		ProxyPort:  1080,
		Mode:       "proxy",
		DNS:        []string{"1.1.1.1", "1.0.0.1"},
		AuthMethod: "password",
	}
}

func settingsFilePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "SSH Tunnel", "settings.json"), nil
}

func (a *App) LoadSettings() AppSettings {
	path, err := settingsFilePath()
	if err != nil {
		return defaultAppSettings()
	}
	data, err := os.ReadFile(path)
	var stored persistedAppSettings
	if err != nil || json.Unmarshal(data, &stored) != nil {
		return defaultAppSettings()
	}
	settings := AppSettings{
		Host:      stored.Host,
		Port:      stored.Port,
		Username:  stored.Username,
		ProxyPort: stored.ProxyPort,
		Mode:      stored.Mode,
		DNS:       stored.DNS,
		UseIPv6:   stored.UseIPv6,
	}
	settings.Password, _ = unprotectSecret(stored.EncryptedPassword)
	settings.PrivateKey, _ = unprotectSecret(stored.EncryptedPrivateKey)
	settings.AuthMethod = stored.AuthMethod
	defaults := defaultAppSettings()
	if settings.Port < 1 || settings.Port > 65535 {
		settings.Port = defaults.Port
	}
	if settings.ProxyPort < 1 || settings.ProxyPort > 65535 {
		settings.ProxyPort = defaults.ProxyPort
	}
	if settings.Mode != "full" {
		settings.Mode = defaults.Mode
	}
	if settings.AuthMethod != "key" {
		settings.AuthMethod = defaults.AuthMethod
	}
	if len(settings.DNS) == 0 {
		settings.DNS = defaults.DNS
	}
	return settings
}

func (a *App) SaveSettings(settings AppSettings) error {
	path, err := settingsFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	encryptedPassword, err := protectSecret([]byte(settings.Password))
	if err != nil {
		return err
	}
	encryptedPrivateKey, err := protectSecret([]byte(settings.PrivateKey))
	if err != nil {
		return err
	}
	stored := persistedAppSettings{
		Host:                settings.Host,
		Port:                settings.Port,
		Username:            settings.Username,
		EncryptedPassword:   encryptedPassword,
		EncryptedPrivateKey: encryptedPrivateKey,
		ProxyPort:           settings.ProxyPort,
		Mode:                settings.Mode,
		DNS:                 settings.DNS,
		UseIPv6:             settings.UseIPv6,
		AuthMethod:          settings.AuthMethod,
	}
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (a *App) Connect(request ConnectRequest) ConnectionStatus {
	if strings.TrimSpace(request.Host) == "" || strings.TrimSpace(request.Username) == "" {
		return ConnectionStatus{State: "error", Message: "Host and username are required"}
	}
	status := a.service.Connect(tunnel.Config{
		Host: request.Host, Port: request.Port, Username: request.Username,
		Password: request.Password, PrivateKey: request.PrivateKey, ProxyPort: request.ProxyPort,
		Mode: request.Mode,
		DNS:  request.DNS, UseIPv6: request.UseIPv6,
	})
	return toConnectionStatus(status)
}

func (a *App) CancelConnect() {
	a.service.CancelConnect()
}

func (a *App) Disconnect() ConnectionStatus {
	return toConnectionStatus(a.service.Disconnect())
}

func (a *App) Status() ConnectionStatus {
	return toConnectionStatus(a.service.Status())
}

func toConnectionStatus(status tunnel.Status) ConnectionStatus {
	return ConnectionStatus{
		State: status.State, Address: status.Address, Proxy: status.Proxy, Message: status.Message,
		UploadBytes: status.UploadBytes, DownloadBytes: status.DownloadBytes,
	}
}
