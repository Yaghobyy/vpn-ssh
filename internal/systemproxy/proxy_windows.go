//go:build windows

package systemproxy

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const internetSettingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type Manager struct {
	mu          sync.Mutex
	active      bool
	pacServer   *http.Server
	pacListener net.Listener
	previous    settings
}

type settings struct {
	enable        uint32
	server        string
	override      string
	autoConfigURL string
}

func NewManager() *Manager {
	manager := &Manager{}
	manager.cleanupLegacyProxy()
	return manager
}

func (m *Manager) Enable(proxyAddress string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active {
		return nil
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open Windows proxy settings: %w", err)
	}
	defer key.Close()

	m.previous = settings{
		enable:        readDWORD(key, "ProxyEnable"),
		server:        readString(key, "ProxyServer"),
		override:      readString(key, "ProxyOverride"),
		autoConfigURL: readString(key, "AutoConfigURL"),
	}

	pacURL, err := m.startPAC(proxyAddress)
	if err != nil {
		return fmt.Errorf("create proxy PAC file: %w", err)
	}
	if err = key.SetDWordValue("ProxyEnable", 0); err != nil {
		m.stopPAC()
		return fmt.Errorf("disable direct Windows proxy: %w", err)
	}
	if err = key.SetStringValue("AutoConfigURL", pacURL); err != nil {
		m.stopPAC()
		return fmt.Errorf("set Windows PAC URL: %w", err)
	}
	if err = notifySettingsChanged(); err != nil {
		m.stopPAC()
		return err
	}
	m.active = true
	return nil
}

func (m *Manager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return nil
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open Windows proxy settings: %w", err)
	}
	defer key.Close()
	if err = key.SetDWordValue("ProxyEnable", m.previous.enable); err != nil {
		m.stopPAC()
		return fmt.Errorf("restore Windows proxy state: %w", err)
	}
	if err = key.SetStringValue("ProxyServer", m.previous.server); err != nil {
		m.stopPAC()
		return fmt.Errorf("restore Windows proxy server: %w", err)
	}
	if err = key.SetStringValue("ProxyOverride", m.previous.override); err != nil {
		m.stopPAC()
		return fmt.Errorf("restore Windows proxy exceptions: %w", err)
	}
	if err = key.SetStringValue("AutoConfigURL", m.previous.autoConfigURL); err != nil {
		m.stopPAC()
		return fmt.Errorf("restore Windows PAC URL: %w", err)
	}
	if err = notifySettingsChanged(); err != nil {
		m.stopPAC()
		return err
	}
	m.active = false
	m.stopPAC()
	return nil
}

func readDWORD(key registry.Key, name string) uint32 {
	value, _, err := key.GetIntegerValue(name)
	if err != nil {
		return 0
	}
	return uint32(value)
}

func readString(key registry.Key, name string) string {
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return value
}

func (m *Manager) cleanupLegacyProxy() {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return
	}
	defer key.Close()
	if readDWORD(key, "ProxyEnable") != 1 || !strings.HasPrefix(readString(key, "ProxyServer"), "socks=127.0.0.1:") {
		return
	}
	if key.SetDWordValue("ProxyEnable", 0) != nil || key.SetStringValue("ProxyServer", "") != nil {
		return
	}
	if readString(key, "ProxyOverride") == "<local>" {
		_ = key.SetStringValue("ProxyOverride", "")
	}
	_ = notifySettingsChanged()
}

func (m *Manager) startPAC(proxyAddress string) (string, error) {
	contents := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || isInNet(host, "127.0.0.0", "255.0.0.0") || isInNet(host, "10.0.0.0", "255.0.0.0") || isInNet(host, "172.16.0.0", "255.240.0.0") || isInNet(host, "192.168.0.0", "255.255.0.0")) {
        return "DIRECT";
    }
    return %q;
}
`, "SOCKS5 "+proxyAddress)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/proxy.pac" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		_, _ = writer.Write([]byte(contents))
	})}
	m.pacListener, m.pacServer = listener, server
	go func() { _ = server.Serve(listener) }()
	return "http://" + listener.Addr().String() + "/proxy.pac", nil
}

func (m *Manager) stopPAC() {
	if m.pacServer != nil {
		_ = m.pacServer.Close()
		m.pacServer = nil
	}
	if m.pacListener != nil {
		_ = m.pacListener.Close()
		m.pacListener = nil
	}
}

func notifySettingsChanged() error {
	dll := windows.NewLazySystemDLL("wininet.dll")
	proc := dll.NewProc("InternetSetOptionW")
	if err := dll.Load(); err != nil {
		return fmt.Errorf("load wininet.dll: %w", err)
	}
	for _, option := range []uintptr{39, 37} {
		result, _, callErr := proc.Call(0, option, 0, 0)
		if result == 0 {
			return fmt.Errorf("notify Windows proxy settings: %w", callErr)
		}
	}
	return nil
}
