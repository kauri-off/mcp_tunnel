# 🛡️ MCP_Tunnel

MCP_Tunnel is a lightweight proxy system that tunnels traffic through an encrypted channel disguised as Minecraft protocol traffic. It allows you to bypass firewalls and DPI by making your traffic appear like a normal Minecraft client-server connection.

# 🌐 Features

🧦 SOCKS5 proxy on the client side.

🔐 Uses AES-128-CFB8

🎮 Obfuscation layer that mimics Minecraft protocol.

🚀 Lightweight and low latency.

✨ Designed for bypassing network censorship and filtering.

# 📖 How It Works

1. MCP_Tunnel Client acts as a SOCKS5 proxy and accepts connections from local applications.

2. It encrypts and wraps outgoing traffic into Minecraft-like packets (handshake/login/play states).

3. MCP_Tunnel Server listens for incoming connections on port 25565 (or any port) and unwraps the Minecraft-masked traffic.

4. The server forwards the real traffic to the target destination and relays responses back.
