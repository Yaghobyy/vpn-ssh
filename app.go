package main

import (
	"context"
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
}

type ConnectionStatus struct {
	State   string `json:"state"`
	Address string `json:"address"`
	Proxy   string `json:"proxy"`
	Message string `json:"message"`
}

func (a *App) Connect(request ConnectRequest) ConnectionStatus {
	if strings.TrimSpace(request.Host) == "" || strings.TrimSpace(request.Username) == "" {
		return ConnectionStatus{State: "error", Message: "Host and username are required"}
	}
	status := a.service.Connect(tunnel.Config{
		Host: request.Host, Port: request.Port, Username: request.Username,
		Password: request.Password, PrivateKey: request.PrivateKey, ProxyPort: request.ProxyPort,
		Mode: request.Mode,
		DNS:  request.DNS,
	})
	return toConnectionStatus(status)
}

func (a *App) Disconnect() ConnectionStatus {
	return toConnectionStatus(a.service.Disconnect())
}

func (a *App) Status() ConnectionStatus {
	return toConnectionStatus(a.service.Status())
}

func toConnectionStatus(status tunnel.Status) ConnectionStatus {
	return ConnectionStatus{State: status.State, Address: status.Address, Proxy: status.Proxy, Message: status.Message}
}
