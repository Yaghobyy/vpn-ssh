//go:build !windows

package fulltunnel

import "errors"

type Manager struct{}

func NewManager() *Manager          { return &Manager{} }
func (*Manager) Done() <-chan error { return nil }
func (*Manager) Start(string, string, bool) error {
	return errors.New("Full Tunnel is only supported on Windows")
}
func (*Manager) Stop() error { return nil }
