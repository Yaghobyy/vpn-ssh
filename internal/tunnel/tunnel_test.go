package tunnel

import (
	"bufio"
	"bytes"
	"testing"

	"golang.org/x/crypto/ssh"
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

func TestTrafficStatsTrackDirectionsAndReset(t *testing.T) {
	service := NewService()
	client := new(ssh.Client)
	service.startTraffic(client)
	service.addTraffic(client, true, 1536)
	service.addTraffic(client, false, 4096)

	status := service.Status()
	if status.UploadBytes != 1536 || status.DownloadBytes != 4096 {
		t.Fatalf("unexpected traffic totals: upload=%d download=%d", status.UploadBytes, status.DownloadBytes)
	}

	service.resetTraffic()
	service.addTraffic(client, true, 100)
	status = service.Status()
	if status.UploadBytes != 0 || status.DownloadBytes != 0 {
		t.Fatalf("expected reset traffic totals, got upload=%d download=%d", status.UploadBytes, status.DownloadBytes)
	}
}
