# 🛡️ MCP_Tunnel - Minecraft Protocol Tunnel

MCP_Tunnel is a lightweight proxy system that tunnels traffic through an encrypted channel disguised as Minecraft protocol traffic. It allows you to bypass firewalls and deep packet inspection (DPI) by making your traffic appear like normal Minecraft client-server connections.

# 🔧 How It Works

The system consists of three components working together:

```
Client Application (Browser, etc.)
↓
MCP_Tunnel Client (local proxy)
↓
Minecraft Server (disguised MCP_Tunnel Server)
↓
Actual Proxy Server (Tinyproxy, etc.)
↓
Internet
```

1. **Client**: Runs locally, accepts connections from applications

2. **Server**: Disguised as a Minecraft server, handles encrypted tunneling

3. **Honeypot**: Optional fake Minecraft server for monitoring/logging

# 🚀 Getting Started

## Prerequisites

- Rust (install via rustup)

- Tinyproxy or similar HTTP proxy (sudo apt install tinyproxy)

## Installation

```bash
git clone https://github.com/kauri-off/mcp_tunnel.git
cd mcp_tunnel
cargo build --release
```

# 🧩 Components

1. Honeypot (Fake Minecraft Server)

```bash
cargo run -- honeypot 0.0.0.0:25565
```

- Monitors connection attempts

- Logs usernames and IP addresses

- Disconnects players after collecting information

2. Server (Proxy Gateway)

```bash
cargo run -- server --bind 0.0.0.0:25565 --proxy 127.0.0.1:8888
```

- Requires config.json (auto-generated on first run)

- Handles Minecraft protocol handshake

- Encrypts traffic using ChaCha20-Poly1305

- Forwards traffic to actual proxy server

3. Client (Local Proxy)

```bash
cargo run -- client \
--bind 127.0.0.1:1080 \
--server 123.45.67.89:25565 \
--name your-username \
--secret your-secret-key \
--trust-new
```

- Creates local SOCKS5 proxy

- Encrypts traffic as Minecraft protocol

- Connects to "Minecraft" server (actually MCP_Tunnel Server)

# 🔐 Configuration

## Server Configuration (config.json)

```json
{
  "users": [
    {
      "name": "your-username",
      "secret": "16-byte-hex-secret"
    }
  ],
  "rsa_private_key": "auto-generated"
}
```

## Generating Secrets

Use 16-byte random hex strings:

```bash
openssl rand -hex 16
# Example: 7c6e5e6386f7458f7596da1f8ec50ae7
```

## Trust Model

- First connection requires --trust-new flag

- Server fingerprint stored in known_hosts

- Subsequent connections verify against known fingerprint

# 🧪 Testing Your Setup

1. Start Tinyproxy:

```bash
sudo systemctl start tinyproxy
```

2. Start MCP_Tunnel Server:

```bash
cargo run --release -- server --bind 0.0.0.0:25565 --proxy 127.0.0.1:8888
```

3. Start MCP_Tunnel Client:

```bash
cargo run --release -- client \
 --bind 127.0.0.1:1080 \
 --server 123.45.67.89:25565 \
 --name test \
 --secret 7c6e5e6386f7458f7596da1f8ec50ae7 \
 --trust-new
```

4. Configure applications to use http://127.0.0.1:1080

# 🛠️ Technical Details

## Encryption Layers

- Initial Handshake: RSA-1024 key exchange

- CFB8 Stream: AES-128-CFB8 encryption

- ChaCha20-Poly1305: Final encryption layer

## Protocol Support

- Minecraft 1.21.1 (Protocol 767)

- Full encryption and compression support

- Proxy protocol tunneling
