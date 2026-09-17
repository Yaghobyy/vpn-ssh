package tunnel

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"ssh-tunnel/internal/dnsmanager"
	"ssh-tunnel/internal/fulltunnel"
	"ssh-tunnel/internal/systemproxy"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	Host       string
	Port       int
	Username   string
	Password   string
	PrivateKey string
	ProxyPort  int
	Mode       string
	DNS        []string
}

type Status struct {
	State   string
	Address string
	Proxy   string
	Message string
}

type Service struct {
	mu       sync.RWMutex
	client   *ssh.Client
	listener net.Listener
	cancel   context.CancelFunc
	status   Status
	proxy    *systemproxy.Manager
	full     *fulltunnel.Manager
	dns      *dnsmanager.Manager
}

func NewService() *Service {
	return &Service{status: Status{State: "disconnected", Message: "Ready to connect"}, proxy: systemproxy.NewManager(), full: fulltunnel.NewManager(), dns: dnsmanager.NewManager()}
}

func (s *Service) Connect(config Config) Status {
	s.Disconnect()
	if config.Port == 0 {
		config.Port = 22
	}
	if config.ProxyPort == 0 {
		config.ProxyPort = 1080
	}
	if config.Mode == "" {
		config.Mode = "proxy"
	}
	if len(config.DNS) == 0 {
		config.DNS = []string{"1.1.1.1", "1.0.0.1"}
	}
	auth, err := authMethod(config)
	if err != nil {
		return s.setStatus(Status{State: "error", Message: err.Error()})
	}
	address := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
		User: config.Username, Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 12 * time.Second,
	})
	if err != nil {
		return s.setStatus(Status{State: "error", Message: fmt.Sprintf("SSH connection failed: %v", err)})
	}

	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(config.ProxyPort)))
	if err != nil {
		client.Close()
		return s.setStatus(Status{State: "error", Message: fmt.Sprintf("SOCKS5 listener failed: %v", err)})
	}
	if config.Mode == "full" {
		if err = s.full.Start(listener.Addr().String(), config.Host); err != nil {
			listener.Close()
			client.Close()
			return s.setStatus(Status{State: "error", Message: err.Error()})
		}
		if err = s.dns.Apply(config.DNS, ""); err != nil {
			_ = s.full.Stop()
			listener.Close()
			client.Close()
			return s.setStatus(Status{State: "error", Message: fmt.Sprintf("set DNS: %v", err)})
		}
	} else if err = s.proxy.Enable(listener.Addr().String()); err != nil {
		listener.Close()
		client.Close()
		return s.setStatus(Status{State: "error", Message: fmt.Sprintf("enable Windows system proxy: %v", err)})
	} else if err = s.dns.Apply(config.DNS, ""); err != nil {
		_ = s.proxy.Disable()
		listener.Close()
		client.Close()
		return s.setStatus(Status{State: "error", Message: fmt.Sprintf("set DNS: %v", err)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.client, s.listener, s.cancel = client, listener, cancel
	s.status = Status{State: "connected", Address: address, Proxy: listener.Addr().String(), Message: "SSH tunnel is active"}
	s.mu.Unlock()
	go s.acceptLoop(ctx, listener)
	go s.keepAlive(ctx, client)
	return s.Status()
}

func (s *Service) Disconnect() Status {
	s.mu.Lock()
	cancel, listener, client := s.cancel, s.listener, s.client
	s.cancel, s.listener, s.client = nil, nil, nil
	s.status = Status{State: "disconnected", Message: "Disconnected"}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if listener != nil {
		listener.Close()
	}
	if client != nil {
		client.Close()
	}
	if err := s.dns.Restore(); err != nil {
		return s.setStatus(Status{State: "error", Message: fmt.Sprintf("restore DNS: %v", err)})
	}
	if err := s.full.Stop(); err != nil {
		return s.setStatus(Status{State: "error", Message: fmt.Sprintf("stop Full Tunnel: %v", err)})
	}
	if err := s.proxy.Disable(); err != nil {
		return s.setStatus(Status{State: "error", Message: fmt.Sprintf("restore Windows system proxy: %v", err)})
	}
	return s.Status()
}

func (s *Service) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *Service) setStatus(status Status) Status {
	s.mu.Lock()
	s.status = status
	s.mu.Unlock()
	return status
}

func (s *Service) acceptLoop(ctx context.Context, listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go s.handleSOCKS5(ctx, connection)
	}
}

func (s *Service) handleSOCKS5(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	reader := bufio.NewReader(connection)
	version, err := reader.ReadByte()
	if err != nil || version != 5 {
		return
	}
	methodCount, err := reader.ReadByte()
	if err != nil || methodCount == 0 {
		return
	}
	methods := make([]byte, methodCount)
	if _, err = io.ReadFull(reader, methods); err != nil {
		return
	}
	if _, err = connection.Write([]byte{5, 0}); err != nil {
		return
	}
	if version, err = reader.ReadByte(); err != nil || version != 5 {
		return
	}
	command, err := reader.ReadByte()
	if err != nil || command != 1 {
		writeSOCKSError(connection, 7)
		return
	}
	if _, err = reader.ReadByte(); err != nil {
		return
	}
	address, err := readSOCKSAddress(reader)
	if err != nil {
		writeSOCKSError(connection, 8)
		return
	}

	s.mu.RLock()
	client := s.client
	s.mu.RUnlock()
	if client == nil {
		writeSOCKSError(connection, 1)
		return
	}
	remote, err := client.Dial("tcp", address)
	if err != nil {
		writeSOCKSError(connection, 5)
		return
	}
	defer remote.Close()
	if _, err = connection.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(remote, reader); _ = remote.Close() }()
	_, _ = io.Copy(connection, remote)
	select {
	case <-ctx.Done():
	default:
	}
}

func (s *Service) keepAlive(ctx context.Context, client *ssh.Client) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				s.setStatus(Status{State: "error", Message: "SSH connection lost"})
				return
			}
		}
	}
}

func authMethod(config Config) (ssh.AuthMethod, error) {
	if strings.TrimSpace(config.PrivateKey) != "" {
		signer, err := ssh.ParsePrivateKey([]byte(config.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	}
	if config.Password == "" {
		return nil, errors.New("password or private key is required")
	}
	return ssh.Password(config.Password), nil
}

func readSOCKSAddress(reader *bufio.Reader) (string, error) {
	addressType, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	var host string
	switch addressType {
	case 1:
		address := make([]byte, 4)
		if _, err = io.ReadFull(reader, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case 3:
		length, readErr := reader.ReadByte()
		if readErr != nil {
			return "", readErr
		}
		address := make([]byte, length)
		if _, err = io.ReadFull(reader, address); err != nil {
			return "", err
		}
		host = string(address)
	case 4:
		address := make([]byte, 16)
		if _, err = io.ReadFull(reader, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	default:
		return "", errors.New("unsupported SOCKS5 address type")
	}
	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(reader, portBytes); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))), nil
}

func writeSOCKSError(connection net.Conn, code byte) {
	_, _ = connection.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}
