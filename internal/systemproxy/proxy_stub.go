//go:build !windows

package systemproxy

import "errors"

type Manager struct{}

func NewManager() *Manager { return &Manager{} }
func (*Manager) Enable(string) error {
	return errors.New("system proxy mode is only supported on Windows")
}
func (*Manager) Disable() error { return nil }
