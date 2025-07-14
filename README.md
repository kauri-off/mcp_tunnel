# 🛡️ MCP_Tunnel - Minecraft Protocol Tunnel

MCP_Tunnel is a lightweight proxy system that tunnels traffic through an encrypted channel disguised as Minecraft protocol traffic. It bypasses firewalls and deep packet inspection (DPI) by making traffic appear as normal Minecraft client-server connections.

# 🔧 How It Works

The system tunnels traffic through three components:

```text
Client Application → MCP_Tunnel Client → Minecraft Server (disguised MCP_Tunnel Server) → Actual Proxy Server → Internet
```

1. **Client Application**: Browser or other internet-enabled app

2. **MCP_Tunnel Client**: Local proxy that encrypts traffic as Minecraft protocol

3. **MCP_Tunnel Server**: Disguised as Minecraft server, handles decryption and forwarding

4. **Actual Proxy**: Tinyproxy or similar HTTP proxy server

# 🧩 Key Components

**1. Honeypot (Fake Minecraft Server)**

```bash
cargo run -- honeypot 0.0.0.0:25565
```

- Monitors connection attempts

- Logs usernames and IP addresses

- Disconnects players after collecting information

**2. Server (Proxy Gateway)**

```bash
cargo run -- server --bind 0.0.0.0:25565 --proxy 127.0.0.1:8888
```

- Handles Minecraft protocol handshake

- Encrypts traffic using ChaCha20-Poly1305

- Forwards traffic to actual proxy server

**3. Client (Local Proxy)**

```bash
cargo run -- client --bind 127.0.0.1:1080 --server 123.45.67.89:25565 --name your-username --secret your-secret-key
```

- Creates an encrypted tunnel

- Encrypts traffic as Minecraft protocol

- Connects to "Minecraft" server (actually MCP_Tunnel Server)

# 🚀 Getting Started

## Prerequisites

- Rust (install via rustup)

- Tinyproxy: sudo apt install tinyproxy

## Installation

```bash
git clone https://github.com/kauri-off/mcp_tunnel.git
cd mcp_tunnel
cargo build --release
```

## Configuration

**Server config.json (auto-generated):**

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

**Generate Secrets:**

```bash
openssl rand -hex 16 # Example output: 7c6e5e6386f7458f7596da1f8ec50ae7
```

# 🔒 Security Model

- First connection requires manual fingerprint verification

- Server fingerprints stored in known_hosts file

- Subsequent connections verify against known fingerprint

- Warns on changed fingerprints (potential MITM attack)

# 🧪 Testing Setup

1. Start Tinyproxy: `sudo systemctl start tinyproxy`

2. Start MCP_Tunnel Server:

```bash
cargo run --release -- server --bind 0.0.0.0:25565 --proxy 127.0.0.1:8888
```

3. Start MCP_Tunnel Client:

```bash
cargo run --release -- client --bind 127.0.0.1:1080 \
 --server 123.45.67.89:25565 \
 --name test \
 --secret 7c6e5e6386f7458f7596da1f8ec50ae7
```

4. Configure applications to use `http://127.0.0.1:1080`

# ⚙️ Technical Details

## Encryption Layers:

- RSA-1024 key exchange

- AES-128-CFB8 stream encryption

- ChaCha20-Poly1305 final encryption

## Protocol Support:

- Minecraft 1.21.1 (Protocol 767)

- Full encryption

- Proxy protocol tunneling

# 🌐 Use Cases

- Bypass restrictive network firewalls

- Evade DPI detection in censored regions

- Secure public Wi-Fi connections

- Monitor suspicious connection attempts (honeypot mode)
