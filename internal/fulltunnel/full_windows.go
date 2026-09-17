//go:build windows

package fulltunnel

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const adapterName = "SSH Tunnel"

type Manager struct {
	mu         sync.Mutex
	started    bool
	routeHost  string
	routeAdded bool
}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Start(proxyAddress, sshHost string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}
	if !isAdministrator() {
		return fmt.Errorf("Full Tunnel requires Administrator privileges")
	}
	host := sshHost
	if parsed := net.ParseIP(sshHost); parsed == nil {
		resolved, err := net.LookupHost(sshHost)
		if err != nil || len(resolved) == 0 {
			return fmt.Errorf("resolve VPS address for route exclusion: %v", err)
		}
		host = resolved[0]
	}
	if net.ParseIP(host) == nil || strings.Contains(host, ":") {
		return fmt.Errorf("Full Tunnel currently requires an IPv4 VPS address")
	}
	if err := configureRoutes(host); err != nil {
		return err
	}
	m.routeHost = host
	m.routeAdded = true

	engine.Insert(&engine.Key{
		Device:    "tun://" + adapterName,
		Proxy:     "socks5://" + proxyAddress,
		MTU:       1500,
		TUNPostUp: `powershell -NoProfile -NonInteractive -Command "New-NetIPAddress -InterfaceAlias 'SSH Tunnel' -IPAddress 10.66.0.2 -PrefixLength 24 -ErrorAction SilentlyContinue; New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias 'SSH Tunnel' -NextHop 10.66.0.1 -RouteMetric 5 -ErrorAction SilentlyContinue; New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias 'SSH Tunnel' -NextHop 10.66.0.1 -RouteMetric 5 -ErrorAction SilentlyContinue"`,
	})
	engine.Start()
	m.started = true
	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return nil
	}
	engine.Stop()
	cleanup := `Get-NetRoute -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; Get-NetIPAddress -InterfaceAlias 'SSH Tunnel' -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue`
	if m.routeAdded {
		cleanup += fmt.Sprintf("; Get-NetRoute -DestinationPrefix '%s/32' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue", m.routeHost)
	}
	_ = runPowerShell(cleanup)
	m.started = false
	m.routeHost = ""
	m.routeAdded = false
	return nil
}

func configureRoutes(sshHost string) error {
	script := fmt.Sprintf(`$default = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' } | Sort-Object RouteMetric | Select-Object -First 1; if ($null -eq $default) { throw 'No default route with a gateway found' }; if (-not (Get-NetRoute -DestinationPrefix '%s/32' -ErrorAction SilentlyContinue)) { New-NetRoute -DestinationPrefix '%s/32' -NextHop $default.NextHop -InterfaceIndex $default.InterfaceIndex -PolicyStore ActiveStore -RouteMetric 1 -ErrorAction Stop | Out-Null }`, sshHost, sshHost)
	if err := runPowerShell(script); err != nil {
		return fmt.Errorf("preserve SSH route before Full Tunnel: %w", err)
	}
	return nil
}

func isAdministrator() bool {
	return runPowerShell(`$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }`) == nil
}

func runPowerShell(script string) error {
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
