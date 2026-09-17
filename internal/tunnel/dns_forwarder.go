package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

type dnsForwarder struct {
	conn    *net.UDPConn
	client  *ssh.Client
	servers []string
	stop    chan struct{}
	once    sync.Once
}

func startDNSForwarder(client *ssh.Client, servers []string) (*dnsForwarder, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("at least one DNS server is required")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 53})
	if err != nil {
		return nil, fmt.Errorf("listen on UDP port 53: %w", err)
	}
	forwarder := &dnsForwarder{conn: conn, client: client, servers: append([]string(nil), servers...), stop: make(chan struct{})}
	go forwarder.serve()
	return forwarder, nil
}

func (f *dnsForwarder) serve() {
	buffer := make([]byte, 4096)
	for {
		count, address, err := f.conn.ReadFromUDP(buffer)
		if err != nil {
			select {
			case <-f.stop:
				return
			default:
				continue
			}
		}
		request := append([]byte(nil), buffer[:count]...)
		go f.forward(request, address)
	}
}

func (f *dnsForwarder) forward(request []byte, address *net.UDPAddr) {
	for _, server := range f.servers {
		response, err := f.query(server, request)
		if err != nil {
			continue
		}
		_, _ = f.conn.WriteToUDP(response, address)
		return
	}
}

func (f *dnsForwarder) query(server string, request []byte) ([]byte, error) {
	connection, err := f.client.Dial("tcp", net.JoinHostPort(server, strconv.Itoa(53)))
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if len(request) > 65535 {
		return nil, fmt.Errorf("DNS request is too large")
	}
	length := []byte{byte(len(request) >> 8), byte(len(request))}
	if _, err = connection.Write(append(length, request...)); err != nil {
		return nil, err
	}
	var responseLength uint16
	if err = binary.Read(connection, binary.BigEndian, &responseLength); err != nil {
		return nil, err
	}
	response := make([]byte, responseLength)
	if _, err = io.ReadFull(connection, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (f *dnsForwarder) Close() error {
	var err error
	f.once.Do(func() {
		close(f.stop)
		err = f.conn.Close()
	})
	return err
}
