//go:build windows

package dnsmanager

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

type Manager struct {
	mu       sync.Mutex
	active   bool
	previous map[string][]string
}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Apply(servers []string, interfaceAlias string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active {
		return nil
	}
	if len(servers) == 0 {
		return fmt.Errorf("at least one DNS server is required")
	}
	aliases, err := m.targetAliases(interfaceAlias)
	if err != nil {
		return err
	}
	previous, err := m.snapshot(aliases)
	if err != nil {
		return err
	}
	serverList := quotePowerShell(strings.Join(servers, "','"))
	for _, alias := range aliases {
		script := fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses ('%s') -ErrorAction Stop", quotePowerShell(alias), serverList)
		if err := runPowerShell(script); err != nil {
			m.restoreLocked(previous)
			return fmt.Errorf("set DNS on %s: %w", alias, err)
		}
	}
	m.previous = previous
	m.active = true
	return nil
}

func (m *Manager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return nil
	}
	err := m.restoreLocked(m.previous)
	if err == nil {
		m.active = false
		m.previous = nil
	}
	return err
}

func (m *Manager) targetAliases(interfaceAlias string) ([]string, error) {
	if interfaceAlias != "" {
		return []string{interfaceAlias}, nil
	}
	output, err := runPowerShellOutput(`Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike 'Loopback*' } | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress`)
	if err != nil {
		return nil, fmt.Errorf("find active network adapters: %w", err)
	}
	var aliases []string
	if err := json.Unmarshal([]byte(output), &aliases); err != nil {
		var alias string
		if json.Unmarshal([]byte(output), &alias) == nil && alias != "" {
			aliases = []string{alias}
		} else {
			return nil, fmt.Errorf("parse active network adapters: %w", err)
		}
	}
	if len(aliases) == 0 {
		return nil, fmt.Errorf("no active network adapter found")
	}
	return aliases, nil
}

func (m *Manager) snapshot(aliases []string) (map[string][]string, error) {
	previous := make(map[string][]string, len(aliases))
	for _, alias := range aliases {
		script := fmt.Sprintf("(Get-DnsClientServerAddress -InterfaceAlias '%s' -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses | ConvertTo-Json -Compress", quotePowerShell(alias))
		output, err := runPowerShellOutput(script)
		if err != nil {
			return nil, fmt.Errorf("read DNS on %s: %w", alias, err)
		}
		var servers []string
		if strings.TrimSpace(output) != "" {
			if err := json.Unmarshal([]byte(output), &servers); err != nil {
				var server string
				if json.Unmarshal([]byte(output), &server) == nil && server != "" {
					servers = []string{server}
				} else {
					return nil, fmt.Errorf("parse DNS on %s: %w", alias, err)
				}
			}
		}
		previous[alias] = servers
	}
	return previous, nil
}

func (m *Manager) restoreLocked(previous map[string][]string) error {
	for alias, servers := range previous {
		var script string
		if len(servers) == 0 {
			script = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ResetServerAddresses -ErrorAction Stop", quotePowerShell(alias))
		} else {
			quoted := make([]string, len(servers))
			for index, server := range servers {
				quoted[index] = quotePowerShell(server)
			}
			script = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses ('%s') -ErrorAction Stop", quotePowerShell(alias), strings.Join(quoted, "','"))
		}
		if err := runPowerShell(script); err != nil {
			return fmt.Errorf("restore DNS on %s: %w", alias, err)
		}
	}
	return nil
}

func quotePowerShell(value string) string { return strings.ReplaceAll(value, "'", "''") }

func runPowerShellOutput(script string) (string, error) {
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func runPowerShell(script string) error {
	_, err := runPowerShellOutput(script)
	return err
}
