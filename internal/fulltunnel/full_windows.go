//go:build windows

package fulltunnel

import (
	"encoding/json"
	"errors"
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
	mu             sync.Mutex
	started        bool
	adapterTouched bool
	routeHost      string
	routeAdded     bool
	ipv6Disabled   []string
	process        *exec.Cmd
	done           chan error
	logFile        *os.File
}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Start(proxyAddress, sshHost string, useIPv6 bool) (startErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}
	if !isAdministrator() {
		return fmt.Errorf("Full Tunnel requires Administrator privileges")
	}
	if m.hasResources() {
		if err := m.cleanupLocked(); err != nil {
			return fmt.Errorf("clean up previous Full Tunnel attempt: %w", err)
		}
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
	m.ipv6Disabled = ipv6Disabled
	defer func() {
		if !m.started {
			if err := m.cleanupLocked(); err != nil {
				startErr = errors.Join(startErr, fmt.Errorf("clean up failed Full Tunnel setup: %w", err))
			}
		}
	}()
	routeAdded, err := configureRoutes(host)
	if err != nil {
		return err
	}
	m.routeHost = host
	m.routeAdded = routeAdded
	wireguardtun.WintunTunnelType = adapterName
	preflight, err := wireguardtun.CreateTUN(adapterName, 1500)
	if err != nil {
		return fmt.Errorf("Wintun adapter is unavailable: %w", err)
	}
	if err := preflight.Close(); err != nil {
		return fmt.Errorf("close Wintun preflight adapter: %w", err)
	}

	helperPath, err := helperExecutable()
	if err != nil {
		return err
	}
	process := exec.Command(helperPath, "--device", "tun://"+adapterName, "--proxy", "socks5://"+proxyAddress)
	process.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	logPath := filepath.Join(os.TempDir(), "ssh-tunnel-engine.log")
	logFile, logErr := os.Create(logPath)
	if logErr != nil {
		return fmt.Errorf("create tun2socks log: %w", logErr)
	}
	process.Stdout, process.Stderr = logFile, logFile
	if startErr := process.Start(); startErr != nil {
		_ = logFile.Close()
		return fmt.Errorf("start tun2socks helper: %w", startErr)
	}
	m.process = process
	m.adapterTouched = true
	m.done = make(chan error, 1)
	m.logFile = logFile
	go func() {
		m.done <- process.Wait()
		close(m.done)
	}()
	if err := waitForAdapter(process, m.done, logFile); err != nil {
		return err
	}
	if err := configureAdapterRoutes(useIPv6); err != nil {
		return fmt.Errorf("%w (see %s)", err, logPath)
	}
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
	if !m.hasResources() {
		return nil
	}
	return m.cleanupLocked()
}

func (m *Manager) hasResources() bool {
	return m.started || m.adapterTouched || m.routeAdded || len(m.ipv6Disabled) > 0 || m.process != nil || m.logFile != nil
}

func (m *Manager) cleanupLocked() error {
	var cleanupErr error
	if m.process != nil && m.process.Process != nil {
		if err := m.process.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
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
	cleanup := ""
	if m.adapterTouched || m.started {
		cleanup = `$routes = Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq 'SSHTunnel' -and $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') }; $routes | Remove-NetRoute -Confirm:$false -ErrorAction Stop; $addresses = Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq 'SSHTunnel' -and $_.IPAddress -in @('10.66.0.2','fd00::2') }; $addresses | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop`
	}
	if m.routeAdded {
		if cleanup != "" {
			cleanup += "; "
		}
		cleanup += fmt.Sprintf("Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -eq '%s/32' } | Remove-NetRoute -Confirm:$false -ErrorAction Stop", m.routeHost)
	}
	if cleanup != "" {
		if err := runPowerShell(cleanup); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if err := cleanupStaleAdapterAddresses(); err != nil {
		cleanupErr = errors.Join(cleanupErr, err)
	}
	if err := restoreIPv6(m.ipv6Disabled); err != nil {
		cleanupErr = errors.Join(cleanupErr, err)
	}
	m.started = false
	if cleanupErr == nil {
		m.adapterTouched = false
		m.routeHost = ""
		m.routeAdded = false
		m.ipv6Disabled = nil
	}
	return cleanupErr
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
	if err := cleanupStaleAdapterAddresses(); err != nil {
		return fmt.Errorf("clean up disconnected Full Tunnel adapters: %w", err)
	}
	script := `$addresses = @(Get-NetIPAddress -ErrorAction SilentlyContinue); $conflict = $addresses | Where-Object { $_.IPAddress -eq '10.66.0.2' -and $_.InterfaceAlias -ne 'SSHTunnel' }; if ($conflict) { throw "Tunnel IP 10.66.0.2 is already assigned to another adapter: $($conflict.InterfaceAlias -join ', ')" }; if (-not ($addresses | Where-Object { $_.InterfaceAlias -eq 'SSHTunnel' -and $_.IPAddress -eq '10.66.0.2' })) { New-NetIPAddress -InterfaceAlias 'SSHTunnel' -IPAddress 10.66.0.2 -PrefixLength 24 -ErrorAction Stop | Out-Null }; $routes = @(Get-NetRoute -ErrorAction SilentlyContinue); if (-not ($routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/1' -and $_.InterfaceAlias -eq 'SSHTunnel' })) { New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias 'SSHTunnel' -NextHop 10.66.0.1 -RouteMetric 5 -ErrorAction Stop | Out-Null }; if (-not ($routes | Where-Object { $_.DestinationPrefix -eq '128.0.0.0/1' -and $_.InterfaceAlias -eq 'SSHTunnel' })) { New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias 'SSHTunnel' -NextHop 10.66.0.1 -RouteMetric 5 -ErrorAction Stop | Out-Null }`
	if useIPv6 {
		script += `; $addresses = @(Get-NetIPAddress -ErrorAction SilentlyContinue); $conflict = $addresses | Where-Object { $_.IPAddress -eq 'fd00::2' -and $_.InterfaceAlias -ne 'SSHTunnel' }; if ($conflict) { throw "Tunnel IP fd00::2 is already assigned to another adapter: $($conflict.InterfaceAlias -join ', ')" }; if (-not ($addresses | Where-Object { $_.InterfaceAlias -eq 'SSHTunnel' -and $_.IPAddress -eq 'fd00::2' })) { New-NetIPAddress -InterfaceAlias 'SSHTunnel' -IPAddress fd00::2 -PrefixLength 64 -ErrorAction Stop | Out-Null }; $routes = @(Get-NetRoute -ErrorAction SilentlyContinue); if (-not ($routes | Where-Object { $_.DestinationPrefix -eq '::/1' -and $_.InterfaceAlias -eq 'SSHTunnel' })) { New-NetRoute -DestinationPrefix '::/1' -InterfaceAlias 'SSHTunnel' -NextHop 'fd00::1' -RouteMetric 5 -ErrorAction Stop | Out-Null }; if (-not ($routes | Where-Object { $_.DestinationPrefix -eq '8000::/1' -and $_.InterfaceAlias -eq 'SSHTunnel' })) { New-NetRoute -DestinationPrefix '8000::/1' -InterfaceAlias 'SSHTunnel' -NextHop 'fd00::1' -RouteMetric 5 -ErrorAction Stop | Out-Null }`
	}
	if err := runPowerShell(script); err != nil {
		return fmt.Errorf("configure Full Tunnel adapter: %w", err)
	}
	return nil
}

func cleanupStaleAdapterAddresses() error {
	script := `$stale = Get-NetAdapter | Where-Object { $_.Name -match '^SSHTunnel( \d+)?$' -and $_.InterfaceDescription -eq 'tun2socks Tunnel' -and $_.Status -eq 'Disconnected' }; $routes = Get-NetRoute -ErrorAction SilentlyContinue; $addresses = Get-NetIPAddress -ErrorAction SilentlyContinue; foreach ($adapter in $stale) { $routes | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex -and $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') } | Remove-NetRoute -Confirm:$false -ErrorAction Stop; $addresses | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex -and $_.IPAddress -in @('10.66.0.2','fd00::2') } | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop }`
	return runPowerShell(script)
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

func configureRoutes(sshHost string) (bool, error) {
	script := fmt.Sprintf(`$default = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' } | Sort-Object RouteMetric | Select-Object -First 1; if ($null -eq $default) { throw 'No default route with a gateway found' }; $created = $false; if (-not (Get-NetRoute -DestinationPrefix '%s/32' -ErrorAction SilentlyContinue)) { New-NetRoute -DestinationPrefix '%s/32' -NextHop $default.NextHop -InterfaceIndex $default.InterfaceIndex -PolicyStore ActiveStore -RouteMetric 1 -ErrorAction Stop | Out-Null; $created = $true }; $created`, sshHost, sshHost)
	output, err := runPowerShellOutput(script)
	if err != nil {
		return false, fmt.Errorf("preserve SSH route before Full Tunnel: %w", err)
	}
	return strings.EqualFold(output, "true"), nil
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
