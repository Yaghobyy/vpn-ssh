//go:build !windows

package fulltunnel

import "errors"

type Manager struct{}

func NewManager() *Manager { return &Manager{} }
func (*Manager) Start(string, string) error {
	return errors.New("Full Tunnel is only supported on Windows")
}
func (*Manager) Stop() error { return nil }
