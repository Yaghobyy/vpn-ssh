package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"

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

func TestDialSSHContextCanCancelHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, dialErr := dialSSHContext(ctx, listener.Addr().String(), &ssh.ClientConfig{
			User: "test", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
		})
		result <- dialErr
	}()

	var serverConnection net.Conn
	select {
	case serverConnection = <-accepted:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("SSH TCP connection was not accepted")
	}
	defer serverConnection.Close()

	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected canceled SSH handshake to return an error")
		}
	case <-time.After(time.Second):
		t.Fatal("SSH handshake did not stop after cancellation")
	}
}
