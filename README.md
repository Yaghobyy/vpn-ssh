# SSH Tunnel

SSH Tunnel is a Windows desktop client for routing application or system traffic through an SSH connection to a VPS. It is built with Go and [Wails](https://wails.io/) and provides a small graphical interface for connecting, monitoring, and disconnecting the tunnel.

The application supports two connection modes:

- **Proxy:** creates a local SOCKS5 proxy and configures the Windows proxy through a temporary PAC file.
- **Full Tunnel:** creates a Wintun adapter and routes system traffic through the SSH-backed SOCKS5 proxy with `tun2socks`.

## Features

- SSH password authentication
- SSH private-key authentication
- Configurable SSH and local SOCKS5 ports
- SOCKS5 support for IPv4, IPv6, and domain-name destinations
- Windows system-proxy integration with restoration on disconnect
- Full Tunnel mode using Wintun and `tun2socks`
- Optional IPv6 routing in Full Tunnel mode
- Configurable DNS providers, including Cloudflare, Google, Quad9, AdGuard, and OpenDNS
- DNS forwarding through the SSH connection in Full Tunnel mode
- SSH keepalive requests every 20 seconds
- Connection status and error reporting in the Wails UI
- In-memory credentials only; profiles are not persisted to disk

## Requirements

- Windows 10 or later
- Go 1.26.3 or a compatible newer Go toolchain
- Node.js and npm
- Wails CLI v2
- Administrator privileges for Full Tunnel mode
- The official Wintun DLL for Full Tunnel mode

Proxy mode changes the current user's Windows Internet proxy settings. Full Tunnel mode changes routes, DNS settings, and network adapter configuration, then attempts to restore them when the tunnel is disconnected.

## Getting started

Clone the repository and install the frontend dependencies:

```powershell
git clone <repository-url>
cd "vpn ssh"
cd frontend
npm install
cd ..
```

Start the application in development mode:

```powershell
wails dev
```

In the application:

1. Enter the VPS hostname or IPv4 address, SSH port, and username.
2. Select password or private-key authentication.
3. Choose **Proxy** or **Full Tunnel** mode.
4. Select a DNS provider and connect.

The default local SOCKS5 endpoint is `127.0.0.1:1080`. In Proxy mode, applications that use the Windows system proxy will be routed through the tunnel. In Full Tunnel mode, system routes are redirected through the Wintun adapter.

## Building

Build the Windows application with:

```powershell
wails build
```

The output is generated under `build/bin`. To use Full Tunnel mode, place the official Wintun DLL beside the application executable:

```text
build/bin/vpn ssh.exe
build/bin/wintun.dll
```

The Full Tunnel helper executable must also be available beside the main executable:

```text
build/bin/ssh-tunnel-engine.exe
```

## Testing

Run the Go unit tests with:

```powershell
go test ./...
```

The current tests cover SOCKS5 address parsing, credential validation, and the initial service state.

## Project structure

```text
.
├── app.go                         Wails bindings and connection API
├── main.go                        Desktop application entry point
├── cmd/ssh-tunnel-engine          tun2socks helper entry point
├── internal/tunnel                 SSH, SOCKS5, keepalive, and DNS forwarding
├── internal/fulltunnel             Wintun and system route management
├── internal/systemproxy            Windows PAC and proxy settings management
├── internal/dnsmanager              Windows DNS snapshot and restoration
└── frontend/src                    Wails frontend and connection form
```

## Security notes

This project is currently an MVP and should be used only in controlled environments:

- SSH host-key verification is currently disabled with `ssh.InsecureIgnoreHostKey()`. Do not use this configuration for untrusted networks or production workloads until known-host verification is implemented.
- Passwords and private keys are kept in memory for the active session and are not stored as profiles.
- Full Tunnel modifies system networking configuration and should be tested carefully on a machine where you can recover network settings.
- Disconnect the tunnel before removing or replacing its executable files.

## Roadmap

- Known-host verification and host-key management
- Secure connection profiles
- Kill-switch support
- More complete cross-platform support
- Expanded integration and network recovery tests

## License

No license has been added to the repository yet. Add a license before distributing the application publicly.