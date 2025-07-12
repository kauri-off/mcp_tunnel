use async_encrypted_stream::{encrypted_stream, ReadHalf, WriteHalf};
use chacha20poly1305::aead::stream::{DecryptorLE31, EncryptorLE31};
use chacha20poly1305::XChaCha20Poly1305;
use log::{error, info, warn};
use mcp_tunnel::fingerprint_md5;
use minecraft_protocol::cfb8_stream::CFB8Stream;
use minecraft_protocol::packet::RawPacket;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{rand_core::OsRng, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::{fs, select};

use crate::packets::p767::{c2s, s2c};

#[derive(Clone, Deserialize, Serialize)]
struct Config {
    users: Vec<User>,
    rsa_private_key: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct User {
    name: String,
    secret: String,
}

pub async fn start_server(bind_addr: String, proxy_addr: String) {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    info!("Starting server...");

    // Load config from file
    let mut config: Config = match fs::read_to_string("config.json").await {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|_| {
            error!("Failed to parse config.json, using default config");
            Config {
                users: vec![],
                rsa_private_key: None,
            }
        }),
        Err(_) => {
            warn!("config.json not found, creating default config");
            let default_config = Config {
                users: vec![User {
                    name: "test".to_string(),
                    secret: "7c6e5e6386f7458f7596da1f8ec50ae7".to_string(),
                }],
                rsa_private_key: None,
            };
            fs::write(
                "config.json",
                serde_json::to_string_pretty(&default_config).unwrap(),
            )
            .await
            .expect("Failed to write default config");
            default_config
        }
    };

    // Validate user secrets
    for user in &config.users {
        if hex::decode(&user.secret).map(|s| s.len()).unwrap_or(0) != 16 {
            error!(
                "Invalid secret length for user {}. Must be 16-byte hex string",
                user.name
            );
        }
    }

    // Load or generate RSA key
    let private_key = match config.rsa_private_key {
        Some(ref pem) => RsaPrivateKey::from_pkcs1_pem(pem).unwrap_or_else(|_| {
            error!("Invalid RSA private key in config, generating new one");
            generate_and_save_rsa_key(&mut config)
        }),
        None => generate_and_save_rsa_key(&mut config),
    };

    let public_key = RsaPublicKey::from(&private_key);
    info!(
        "Server fingerprint: {}",
        fingerprint_md5(&public_key).unwrap()
    );

    let tcp_listener = TcpListener::bind(&bind_addr).await.unwrap();
    info!("Listening on {}", bind_addr);

    while let Ok((stream, addr)) = tcp_listener.accept().await {
        info!("New connection from {}", addr);
        tokio::spawn(process_new_stream(
            stream,
            addr,
            private_key.clone(),
            proxy_addr.clone(),
            config.clone(),
        ));
    }
}

fn generate_and_save_rsa_key(config: &mut Config) -> RsaPrivateKey {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 1024).expect("Failed to generate RSA key");
    let pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
        .expect("Failed to encode RSA key")
        .to_string();

    config.rsa_private_key = Some(pem.clone());
    std::fs::write(
        "config.json",
        serde_json::to_string_pretty(config).expect("Failed to serialize config"),
    )
    .expect("Failed to save config");

    private_key
}

async fn process_new_stream(
    mut stream: TcpStream,
    addr: SocketAddr,
    private_key: RsaPrivateKey,
    proxy_addr: String,
    config: Config,
) -> anyhow::Result<()> {
    let handshake: c2s::Handshake = RawPacket::read(&mut stream)
        .await?
        .as_uncompressed()?
        .convert()?;

    match handshake.intent.0 {
        1 => process_status(stream, addr).await,
        2 => process_login(stream, addr, private_key, proxy_addr, config).await,
        _ => Ok(()),
    }
}

async fn process_login(
    mut client_stream: TcpStream,
    addr: SocketAddr,
    private_key: RsaPrivateKey,
    proxy_addr: String,
    config: Config,
) -> anyhow::Result<()> {
    let login_start: c2s::LoginStart = RawPacket::read(&mut client_stream)
        .await?
        .as_uncompressed()?
        .convert()?;

    info!("Login attempt from: {}", login_start.name);

    let public_key = RsaPublicKey::from(&private_key);
    let public_key_der = public_key.to_public_key_der()?;

    let verify_token: [u8; 4] = rand::random();

    let encryption_request = s2c::EncryptionRequest {
        server_id: "".to_string(),
        public_key: public_key_der.as_bytes().to_vec(),
        verify_token: verify_token.to_vec(),
        should_authenticate: false,
    };

    RawPacket::from_packetio(&encryption_request)?
        .write(&mut client_stream)
        .await?;

    let encryption_response: c2s::EncryptionResponse = RawPacket::read(&mut client_stream)
        .await?
        .as_uncompressed()?
        .convert()?;

    let shared_secret =
        private_key.decrypt(rsa::Pkcs1v15Encrypt, &encryption_response.shared_secret)?;
    let verify_token_resp =
        private_key.decrypt(rsa::Pkcs1v15Encrypt, &encryption_response.verify_token)?;

    if verify_token_resp != verify_token {
        println!("Verify token mismatch for {}", addr);
        return Ok(());
    }

    if let Err(reason) = verify_secret(&login_start.name, &shared_secret, &verify_token, &config) {
        warn!("Authentication failed for {}: {}", login_start.name, reason);
        let shared_secret: &[u8; 16] = shared_secret.as_slice().try_into()?;
        let mut encrypted_stream = CFB8Stream::new_from_tcp(client_stream, shared_secret)?;

        RawPacket::from_packetio(&s2c::LoginDisconnect {
            reason: json!({
                "text": "You are not white-listed on this server!"
            })
            .to_string(),
        })?
        .write(&mut encrypted_stream)
        .await?;

        return Ok(());
    }

    assert_eq!(shared_secret.len(), 20); // Must always be true, because verify_secret checks it

    let shared_secret: &[u8; 16] = shared_secret[4..20].try_into()?;
    let mut cfb8_client_stream = CFB8Stream::new_from_tcp(client_stream, shared_secret)?;

    let key: [u8; 32] = rand::random();
    let nonce: [u8; 20] = rand::random();

    let change_protocol = s2c::ChangeProtocol {
        key: key.to_vec(),
        nonce: nonce.to_vec(),
    };

    RawPacket::from_packetio(&change_protocol)?
        .write(&mut cfb8_client_stream)
        .await?;

    let (rx, tx) = cfb8_client_stream.split_inner();
    let (mut client_rx, mut client_tx): (
        ReadHalf<_, DecryptorLE31<XChaCha20Poly1305>>,
        WriteHalf<_, EncryptorLE31<XChaCha20Poly1305>>,
    ) = encrypted_stream(rx, tx, key.as_ref().into(), nonce.as_ref().into());

    let (mut proxy_rx, mut proxy_tx) = TcpSocket::new_v4()?
        .connect(proxy_addr.parse().unwrap())
        .await?
        .into_split();

    let c2s_thread =
        tokio::spawn(async move { tokio::io::copy(&mut client_rx, &mut proxy_tx).await });
    let s2c_thread =
        tokio::spawn(async move { tokio::io::copy(&mut proxy_rx, &mut client_tx).await });

    select! {
        _ = c2s_thread => {
            return Ok(())
        },
        _ = s2c_thread => {
            return Ok(())
        }
    };
}

fn verify_secret(
    username: &str,
    shared_secret: &[u8],
    verify_token: &[u8; 4],
    config: &Config,
) -> Result<(), &'static str> {
    if shared_secret.len() != 20 {
        return Err("Invalid shared secret length");
    }
    if &shared_secret[..4] != verify_token {
        return Err("Token mismatch");
    }

    config
        .users
        .iter()
        .find(|u| u.name == username)
        .ok_or("User not found")
        .and_then(|user| {
            if user.secret == hex::encode(&shared_secret[4..]) {
                Ok(())
            } else {
                Err("Secret mismatch")
            }
        })
}

async fn process_status(mut stream: TcpStream, _addr: SocketAddr) -> anyhow::Result<()> {
    while let Ok(packet) = RawPacket::read(&mut stream).await {
        let packet = packet.as_uncompressed()?;

        match packet.packet_id.0 {
            0 => {
                RawPacket::from_packetio(&s2c::StatusResponse {
                    response: json!({
                      "version": {
                        "name": "1.21.1",
                        "protocol": 767
                      },
                      "players": {
                        "max": 20,
                        "online": 0,
                      },
                      "description": "A Minecraft Server",
                      "enforcesSecureChat": true
                    })
                    .to_string(),
                })?
                .write(&mut stream)
                .await?;
            }
            1 => {
                packet.to_raw_packet()?.write(&mut stream).await?;
            }
            _ => return Ok(()),
        };
    }

    Ok(())
}
