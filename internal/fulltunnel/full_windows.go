//go:build windows

package fulltunnel

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	wireguardtun "golang.zx2c4.com/wireguard/tun"
)

const adapterName = "SSHTunnel"

type Manager struct {
	mu           sync.Mutex
	started      bool
	routeHost    string
	routeAdded   bool
	ipv6Disabled []string
	process      *exec.Cmd
	done         chan error
	logFile      *os.File
}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Start(proxyAddress, sshHost string, useIPv6 bool) error {
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
	ipv6Disabled, err := disableIPv6(!useIPv6)
	if err != nil {
		return fmt.Errorf("configure IPv6: %w", err)
	}
	defer func() {
		if !m.started {
			_ = restoreIPv6(ipv6Disabled)
		}
	}()
	if err := configureRoutes(host); err != nil {
		return err
	}
	wireguardtun.WintunTunnelType = adapterName
	preflight, err := wireguardtun.CreateTUN(adapterName, 1500)
	if err != nil {
		_ = removeRoute(host)
		return fmt.Errorf("Wintun adapter is unavailable: %w", err)
	}
	if err := preflight.Close(); err != nil {
		_ = removeRoute(host)
		return fmt.Errorf("close Wintun preflight adapter: %w", err)
	}
	m.routeHost = host
	m.routeAdded = true

	helperPath, err := helperExecutable()
	if err != nil {
		_ = removeRoute(host)
		return err
	}
	process := exec.Command(helperPath, "--device", "tun://"+adapterName, "--proxy", "socks5://"+proxyAddress)
	process.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	logPath := filepath.Join(os.TempDir(), "ssh-tunnel-engine.log")
	logFile, logErr := os.Create(logPath)
	if logErr != nil {
		_ = removeRoute(host)
		return fmt.Errorf("create tun2socks log: %w", logErr)
	}
	process.Stdout, process.Stderr = logFile, logFile
	if startErr := process.Start(); startErr != nil {
		_ = logFile.Close()
		_ = removeRoute(host)
		return fmt.Errorf("start tun2socks helper: %w", startErr)
	}
	m.process = process
	m.done = make(chan error, 1)
	m.logFile = logFile
	go func() { m.done <- process.Wait() }()
	if err := waitForAdapter(process, m.done, logFile); err != nil {
		_ = process.Process.Kill()
		_ = logFile.Close()
		_ = removeRoute(host)
		return err
	}
	if err := configureAdapterRoutes(useIPv6); err != nil {
		_ = process.Process.Kill()
		logFile.Close()
		_ = removeRoute(host)
		return fmt.Errorf("%w (see %s)", err, logPath)
	}
	m.ipv6Disabled = ipv6Disabled
	m.started = true
	return nil
}

func waitForAdapter(process *exec.Cmd, done <-chan error, logFile *os.File) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			return fmt.Errorf("tun2socks helper stopped before adapter was ready: %w: %s", err, readLog(logFile))
		default:
		}
		if err := runPowerShell(`if (-not (Get-NetAdapter -Name 'SSHTunnel' -ErrorAction SilentlyContinue)) { exit 1 }`); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("Wintun adapter did not appear within 10 seconds: %s", readLog(logFile))
}

func readLog(file *os.File) string {
	if file == nil {
		return ""
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ""
	}
	contents, _ := io.ReadAll(file)
	return strings.TrimSpace(string(contents))
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return nil
	}
	if m.process != nil && m.process.Process != nil {
		_ = m.process.Process.Kill()
		if m.done != nil {
			<-m.done
		}
		if m.logFile != nil {
			_ = m.logFile.Close()
		}
		m.process = nil
		m.done = nil
		m.logFile = nil
	}
	cleanup := `Get-NetRoute -DestinationPrefix '0.0.0.0/1','128.0.0.0/1','::/1','8000::/1' -InterfaceAlias 'SSHTunnel' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; Get-NetIPAddress -InterfaceAlias 'SSHTunnel' -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue`
	if m.routeAdded {
		cleanup += fmt.Sprintf("; Get-NetRoute -DestinationPrefix '%s/32' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue", m.routeHost)
	}
	_ = runPowerShell(cleanup)
	_ = restoreIPv6(m.ipv6Disabled)
	m.started = false
	m.routeHost = ""
	m.routeAdded = false
	m.ipv6Disabled = nil
	return nil
}

func helperExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate application executable: %w", err)
	}
	helper := filepath.Join(filepath.Dir(executable), "ssh-tunnel-engine.exe")
	if _, err = os.Stat(helper); err != nil {
		return "", fmt.Errorf("tun2socks helper is missing: %s", helper)
	}
	return helper, nil
}

func removeRoute(sshHost string) error {
	return runPowerShell(fmt.Sprintf("Get-NetRoute -DestinationPrefix '%s/32' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue", sshHost))
}

func configureAdapterRoutes(useIPv6 bool) error {
	script := `if (-not (Get-NetIPAddress -InterfaceAlias 'SSHTunnel' -IPAddress 10.66.0.2 -ErrorAction SilentlyContinue)) { New-NetIPAddress -InterfaceAlias 'SSHTunnel' -IPAddress 10.66.0.2 -PrefixLength 24 -ErrorAction Stop | Out-Null }; if (-not (Get-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias 'SSHTunnel' -ErrorAction SilentlyContinue)) { New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias 'SSHTunnel' -NextHop 10.66.0.1 -RouteMetric 5 -ErrorAction Stop | Out-Null }; if (-not (Get-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias 'SSHTunnel' -ErrorAction SilentlyContinue)) { New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias 'SSHTunnel' -NextHop 10.66.0.1 -RouteMetric 5 -ErrorAction Stop | Out-Null }`
	if useIPv6 {
		script += `; if (-not (Get-NetIPAddress -InterfaceAlias 'SSHTunnel' -IPAddress fd00::2 -ErrorAction SilentlyContinue)) { New-NetIPAddress -InterfaceAlias 'SSHTunnel' -IPAddress fd00::2 -PrefixLength 64 -ErrorAction Stop | Out-Null }; if (-not (Get-NetRoute -DestinationPrefix '::/1' -InterfaceAlias 'SSHTunnel' -ErrorAction SilentlyContinue)) { New-NetRoute -DestinationPrefix '::/1' -InterfaceAlias 'SSHTunnel' -NextHop 'fd00::1' -RouteMetric 5 -ErrorAction Stop | Out-Null }; if (-not (Get-NetRoute -DestinationPrefix '8000::/1' -InterfaceAlias 'SSHTunnel' -ErrorAction SilentlyContinue)) { New-NetRoute -DestinationPrefix '8000::/1' -InterfaceAlias 'SSHTunnel' -NextHop 'fd00::1' -RouteMetric 5 -ErrorAction Stop | Out-Null }`
	}
	if err := runPowerShell(script); err != nil {
		return fmt.Errorf("configure Full Tunnel adapter: %w", err)
	}
	return nil
}

func disableIPv6(disable bool) ([]string, error) {
	if !disable {
		return nil, nil
	}
	script := `$changed = @(); Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike 'Loopback*' -and $_.Name -ne 'SSHTunnel' } | ForEach-Object { $binding = Get-NetAdapterBinding -Name $_.Name -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue; if ($binding -and $binding.Enabled) { Disable-NetAdapterBinding -Name $_.Name -ComponentID 'ms_tcpip6' -Confirm:$false -ErrorAction Stop; $changed += $_.Name } }; $changed | ConvertTo-Json -Compress`
	output, err := runPowerShellOutput(script)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(output) == "" || strings.TrimSpace(output) == "null" {
		return nil, nil
	}
	var names []string
	if err := json.Unmarshal([]byte(output), &names); err != nil {
		var name string
		if json.Unmarshal([]byte(output), &name) != nil {
			return nil, fmt.Errorf("parse disabled IPv6 adapters: %w", err)
		}
		names = []string{name}
	}
	return names, nil
}

func restoreIPv6(names []string) error {
	for _, name := range names {
		script := fmt.Sprintf("Enable-NetAdapterBinding -Name '%s' -ComponentID 'ms_tcpip6' -Confirm:$false -ErrorAction Stop", strings.ReplaceAll(name, "'", "''"))
		if err := runPowerShell(script); err != nil {
			return err
		}
	}
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
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runPowerShellOutput(script string) (string, error) {
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}
