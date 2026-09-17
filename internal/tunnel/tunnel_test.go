package tunnel

import (
	"bufio"
	"bytes"
	"testing"
)

func TestReadSOCKSAddressDomain(t *testing.T) {
	request := []byte{3, 11}
	request = append(request, []byte("example.com")...)
	request = append(request, 1, 187)

	address, err := readSOCKSAddress(bufio.NewReader(bytes.NewReader(request)))
	if err != nil {
		t.Fatalf("readSOCKSAddress returned error: %v", err)
	}
	if address != "example.com:443" {
		t.Fatalf("expected example.com:443, got %s", address)
	}
}

func TestAuthMethodRequiresCredentials(t *testing.T) {
	if _, err := authMethod(Config{Username: "root"}); err == nil {
		t.Fatal("expected missing credentials error")
	}
}

func TestNewServiceStartsDisconnected(t *testing.T) {
	status := NewService().Status()
	if status.State != "disconnected" {
		t.Fatalf("expected disconnected state, got %s", status.State)
	}
}
