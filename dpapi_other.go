//go:build !windows

package main

import "errors"

func protectSecret(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, nil
	}
	return nil, errors.New("secure credential storage is only available on Windows")
}

func unprotectSecret([]byte) (string, error) {
	return "", errors.New("secure credential storage is only available on Windows")
}
