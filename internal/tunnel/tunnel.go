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
	UseIPv6    bool
}

type Status struct {
	State         string
	Address       string
	Proxy         string
	Message       string
	UploadBytes   uint64
	DownloadBytes uint64
}

type Service struct {
	lifecycleMu   sync.Mutex
	attemptMu     sync.Mutex
	attemptCancel context.CancelFunc
	mu            sync.RWMutex
	client        *ssh.Client
	listener      net.Listener
	cancel        context.CancelFunc
	status        Status
	proxy         *systemproxy.Manager
	full          *fulltunnel.Manager
	dns           *dnsmanager.Manager
	dnsProxy      *dnsForwarder
	trafficMu     sync.RWMutex
	trafficClient *ssh.Client
	uploadBytes   uint64
	downloadBytes uint64
}

func NewService() *Service {
	return &Service{status: Status{State: "disconnected", Message: "Ready to connect"}, proxy: systemproxy.NewManager(), full: fulltunnel.NewManager(), dns: dnsmanager.NewManager()}
}

func (s *Service) Connect(config Config) Status {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.disconnectLocked(nil, "Disconnected")

	attemptCtx, attemptCancel := context.WithCancel(context.Background())
	s.attemptMu.Lock()
	s.attemptCancel = attemptCancel
	s.attemptMu.Unlock()
	defer func() {
		attemptCancel()
		s.attemptMu.Lock()
		s.attemptCancel = nil
		s.attemptMu.Unlock()
	}()
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
	client, err := dialSSHContext(attemptCtx, address, &ssh.ClientConfig{
		User: config.Username, Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 12 * time.Second,
	})
	if err != nil {
		if attemptCtx.Err() != nil {
			return s.setStatus(Status{State: "disconnected", Message: "Connection attempt canceled"})
		}
		return s.setStatus(Status{State: "error", Message: fmt.Sprintf("SSH connection failed: %v", err)})
	}
	stopClose := context.AfterFunc(attemptCtx, func() { _ = client.Close() })
	defer stopClose()

	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(config.ProxyPort)))
	if err != nil {
		client.Close()
		if attemptCtx.Err() != nil {
			return s.setStatus(Status{State: "disconnected", Message: "Connection attempt canceled"})
		}
		return s.setStatus(Status{State: "error", Message: fmt.Sprintf("SOCKS5 listener failed: %v", err)})
	}
	if config.Mode == "full" {
		if err = s.full.Start(listener.Addr().String(), config.Host, config.UseIPv6); err != nil {
			if attemptCtx.Err() != nil {
				return s.cancelConnectionAttempt(client, listener)
			}
			_ = listener.Close()
			_ = client.Close()
			return s.setStatus(Status{State: "error", Message: err.Error()})
		}
		if attemptCtx.Err() != nil {
			return s.cancelConnectionAttempt(client, listener)
		}
		s.dnsProxy, err = startDNSForwarder(client, config.DNS)
		if err != nil {
			if attemptCtx.Err() != nil {
				return s.cancelConnectionAttempt(client, listener)
			}
			_ = s.full.Stop()
			_ = listener.Close()
			_ = client.Close()
			return s.setStatus(Status{State: "error", Message: fmt.Sprintf("start DNS forwarder: %v", err)})
		}
		if err = s.dns.Apply([]string{"10.66.0.2"}, "SSHTunnel"); err != nil {
			if attemptCtx.Err() != nil {
				return s.cancelConnectionAttempt(client, listener)
			}
			_ = s.dnsProxy.Close()
			s.dnsProxy = nil
			_ = s.full.Stop()
			_ = listener.Close()
			_ = client.Close()
			return s.setStatus(Status{State: "error", Message: fmt.Sprintf("set DNS: %v", err)})
		}
	} else if err = s.proxy.Enable(listener.Addr().String()); err != nil {
		if attemptCtx.Err() != nil {
			return s.cancelConnectionAttempt(client, listener)
		}
		_ = listener.Close()
		_ = client.Close()
		return s.setStatus(Status{State: "error", Message: fmt.Sprintf("enable Windows system proxy: %v", err)})
	} else if err = s.dns.Apply(config.DNS, ""); err != nil {
		if attemptCtx.Err() != nil {
			return s.cancelConnectionAttempt(client, listener)
		}
		_ = s.proxy.Disable()
		_ = listener.Close()
		_ = client.Close()
		return s.setStatus(Status{State: "error", Message: fmt.Sprintf("set DNS: %v", err)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.attemptMu.Lock()
	if attemptCtx.Err() != nil {
		s.attemptMu.Unlock()
		cancel()
		return s.cancelConnectionAttempt(client, listener)
	}
	stopClose()
	s.attemptCancel = nil
	s.mu.Lock()
	s.client, s.listener, s.cancel = client, listener, cancel
	s.status = Status{State: "connected", Address: address, Proxy: listener.Addr().String(), Message: "SSH tunnel is active"}
	s.startTraffic(client)
	s.mu.Unlock()
	s.attemptMu.Unlock()
	go s.acceptLoop(ctx, listener)
	go s.keepAlive(ctx, client)
	go s.watchSSH(ctx, client)
	if config.Mode == "full" {
		go s.watchFullTunnel(ctx, client, s.full.Done())
	}
	return s.Status()
}

func dialSSHContext(ctx context.Context, address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	dialer := net.Dialer{Timeout: config.Timeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	if config.Timeout > 0 {
		if err := connection.SetDeadline(time.Now().Add(config.Timeout)); err != nil {
			stopClose()
			_ = connection.Close()
			return nil, err
		}
	}
	sshConnection, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if err != nil {
		stopClose()
		_ = connection.Close()
		return nil, err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		stopClose()
		_ = sshConnection.Close()
		return nil, err
	}
	if ctx.Err() != nil {
		stopClose()
		_ = sshConnection.Close()
		return nil, ctx.Err()
	}
	stopClose()
	return ssh.NewClient(sshConnection, channels, requests), nil
}

func (s *Service) CancelConnect() {
	s.attemptMu.Lock()
	if s.attemptCancel != nil {
		s.attemptCancel()
	}
	s.attemptMu.Unlock()
}

func (s *Service) cancelConnectionAttempt(client *ssh.Client, listener net.Listener) Status {
	if listener != nil {
		_ = listener.Close()
	}
	if client != nil {
		_ = client.Close()
	}
	return s.disconnectLocked(nil, "Connection attempt canceled")
}

func (s *Service) Disconnect() Status {
	s.CancelConnect()
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.disconnectLocked(nil, "Disconnected")
}

func (s *Service) disconnectLocked(expectedClient *ssh.Client, message string) Status {
	s.mu.Lock()
	if expectedClient != nil && s.client != expectedClient {
		status := s.status
		s.mu.Unlock()
		return status
	}
	cancel, listener, client := s.cancel, s.listener, s.client
	s.cancel, s.listener, s.client = nil, nil, nil
	s.status = Status{State: "disconnected", Message: message}
	s.resetTraffic()
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
	if s.dnsProxy != nil {
		_ = s.dnsProxy.Close()
		s.dnsProxy = nil
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

func (s *Service) disconnectUnexpected(client *ssh.Client, message string) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.disconnectLocked(client, message)
}

func (s *Service) Status() Status {
	s.mu.RLock()
	status := s.status
	s.mu.RUnlock()
	s.trafficMu.RLock()
	status.UploadBytes = s.uploadBytes
	status.DownloadBytes = s.downloadBytes
	s.trafficMu.RUnlock()
	return status
}

func (s *Service) addTraffic(client *ssh.Client, upload bool, count int) {
	if count <= 0 {
		return
	}
	s.trafficMu.Lock()
	if s.trafficClient == client {
		if upload {
			s.uploadBytes += uint64(count)
		} else {
			s.downloadBytes += uint64(count)
		}
	}
	s.trafficMu.Unlock()
}

func (s *Service) startTraffic(client *ssh.Client) {
	s.trafficMu.Lock()
	s.trafficClient = client
	s.uploadBytes = 0
	s.downloadBytes = 0
	s.trafficMu.Unlock()
}

func (s *Service) resetTraffic() {
	s.startTraffic(nil)
}

type trafficCountingWriter struct {
	destination io.Writer
	service     *Service
	client      *ssh.Client
	upload      bool
}

func (writer trafficCountingWriter) Write(buffer []byte) (int, error) {
	count, err := writer.destination.Write(buffer)
	writer.service.addTraffic(writer.client, writer.upload, count)
	return count, err
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
	go func() {
		_, _ = io.Copy(trafficCountingWriter{destination: remote, service: s, client: client, upload: true}, reader)
		_ = remote.Close()
	}()
	_, _ = io.Copy(trafficCountingWriter{destination: connection, service: s, client: client}, remote)
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
				s.disconnectUnexpected(client, fmt.Sprintf("SSH connection lost: %v", err))
				return
			}
		}
	}
}

func (s *Service) watchSSH(ctx context.Context, client *ssh.Client) {
	err := client.Wait()
	if ctx.Err() != nil {
		return
	}
	message := "SSH server closed the connection"
	if err != nil {
		message = fmt.Sprintf("SSH connection lost: %v", err)
	}
	s.disconnectUnexpected(client, message)
}

func (s *Service) watchFullTunnel(ctx context.Context, client *ssh.Client, done <-chan error) {
	if done == nil {
		return
	}
	select {
	case err, ok := <-done:
		if ctx.Err() != nil {
			return
		}
		message := "Full Tunnel helper stopped unexpectedly"
		if ok && err != nil {
			message = fmt.Sprintf("Full Tunnel helper stopped: %v", err)
		}
		s.disconnectUnexpected(client, message)
	case <-ctx.Done():
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
