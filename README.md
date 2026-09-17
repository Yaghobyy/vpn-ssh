# SSH Tunnel

Windows desktop SSH tunnel client built with Go and Wails. The current implementation is phase one: it connects to a VPS and exposes a local SOCKS5 proxy, equivalent to `ssh -D`.

## Current scope

- SSH password or private key authentication
- Local SOCKS5 listener, defaulting to `127.0.0.1:1080`
- SSH keepalive requests every 20 seconds
- Wails UI with connect/disconnect state
- Unit coverage for SOCKS5 address parsing and credential validation

Full Tunnel/TUN, Windows system proxy changes, DNS management, secure profile storage, and kill switch are not implemented yet.

## Run

```powershell
wails dev
```

After connecting, configure an application or browser to use the SOCKS5 proxy shown in the UI. The current MVP uses `ssh.InsecureIgnoreHostKey()` and should only be used for controlled testing until known-host verification is added.

## Build

```powershell
wails build
```

The executable is generated under `build/bin`.

For Full Tunnel on Windows, keep the official `wintun.dll` (amd64) beside the executable:

```text
build/bin/vpn ssh.exe
build/bin/wintun.dll
```

The build output currently includes Wintun 0.14.1 for Windows amd64.