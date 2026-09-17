//go:build !windows

package dnsmanager

import "errors"

type Manager struct{}

func NewManager() *Manager { return &Manager{} }
func (*Manager) Apply([]string, string) error {
	return errors.New("DNS management is only supported on Windows")
}
func (*Manager) Restore() error { return nil }
