use std::{collections::HashMap, io::Write, net::SocketAddr, path::Path, sync::Arc};

use anyhow::anyhow;
use async_encrypted_stream::{encrypted_stream, ReadHalf, WriteHalf};
use chacha20poly1305::{
    aead::stream::{DecryptorLE31, EncryptorLE31},
    XChaCha20Poly1305,
};
use mcp_tunnel::fingerprint_md5;
use minecraft_protocol::{cfb8_stream::CFB8Stream, packet::RawPacket, varint::VarInt};
use rsa::{pkcs8::DecodePublicKey, rand_core::OsRng, RsaPublicKey};
use sha1::{Digest, Sha1};
use tokio::{
    fs,
    net::{TcpListener, TcpSocket, TcpStream},
    select,
    sync::Mutex,
};

use crate::packets::p767::{c2s, s2c};

const KNOWN_HOSTS_FILE: &str = "known_hosts";

pub struct AppState {
    known_hosts: Mutex<HashMap<String, String>>, // [address] = fingerprint
    known_hosts_path: String,
}

impl AppState {
    pub async fn new() -> anyhow::Result<Arc<Self>> {
        let known_hosts_path = std::env::current_dir()?
            .join(KNOWN_HOSTS_FILE)
            .to_str()
            .unwrap()
            .to_string();

        let mut known_hosts = HashMap::new();
        if Path::new(&known_hosts_path).exists() {
            let contents = fs::read_to_string(&known_hosts_path).await?;
            for line in contents.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    known_hosts.insert(parts[0].to_string(), parts[1].to_string());
                }
            }
        }

        Ok(Arc::new(Self {
            known_hosts: Mutex::new(known_hosts),
            known_hosts_path,
        }))
    }
}

pub async fn start_client(bind_addr: String, server_addr: String, name: String, secret: String) {
    let state = AppState::new().await.unwrap();
    let listener = TcpListener::bind(&bind_addr).await.unwrap();

    while let Ok((stream, _addr)) = listener.accept().await {
        tokio::spawn(process_socket(
            stream,
            server_addr.clone(),
            name.clone(),
            secret.clone(),
            state.clone(),
        ));
    }
}

async fn process_socket(
    client_stream: TcpStream,
    server_addr: String,
    name: String,
    secret: String,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = server_addr.parse()?;
    let mut remote_stream = TcpSocket::new_v4()?.connect(addr.clone()).await?;

    let handshake = c2s::Handshake {
        protocol_version: VarInt(767),
        server_address: addr.ip().to_string(),
        server_port: addr.port(),
        intent: VarInt(2),
    };

    RawPacket::from_packetio(&handshake)?
        .write(&mut remote_stream)
        .await?;

    let login_start = c2s::LoginStart {
        name: name.clone(),
        uuid: calc_hash_u128(&name),
    };

    RawPacket::from_packetio(&login_start)?
        .write(&mut remote_stream)
        .await?;

    let encryption_request: s2c::EncryptionRequest = RawPacket::read(&mut remote_stream)
        .await?
        .as_uncompressed()?
        .convert()?;

    let public_key = RsaPublicKey::from_public_key_der(&encryption_request.public_key)?;

    let fingerprint = fingerprint_md5(&public_key)?;

    // Verify or record host key
    match check_known_host(&state, &server_addr, &fingerprint).await {
        Ok(()) => {}
        Err(stored_fingerprint) => {
            let (is_new_server, warning_message) = if stored_fingerprint.is_empty() {
                (
                    true,
                    format!(
                        "\n⚠️  The authenticity of host '{}' can't be established.\n\
                     Server fingerprint: {}\n\
                     Are you sure you want to continue connecting? (yes/no): ",
                        server_addr, fingerprint
                    ),
                )
            } else {
                (
                    false,
                    format!(
                        "\n⚠️  WARNING: SERVER IDENTIFICATION HAS CHANGED! ⚠️\n\
                     This could indicate a man-in-the-middle attack!\n\
                     Server: {}\n\
                     Previous fingerprint: {}\n\
                     Current fingerprint:  {}\n\n\
                     Are you sure you want to continue connecting? (yes/no): ",
                        server_addr, stored_fingerprint, fingerprint
                    ),
                )
            };

            print!("{}", warning_message);
            std::io::stdout().flush()?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            if input.trim().eq_ignore_ascii_case("yes") {
                add_known_host(&state, &server_addr, &fingerprint).await?;
                println!(
                    "✅ Host key {} for {}",
                    if is_new_server { "added" } else { "updated" },
                    server_addr
                );
            } else {
                return Err(anyhow!("Host key verification failed for {}", server_addr));
            }
        }
    }

    let shared_secret: [u8; 16] = hex::decode(&secret)?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("Expected 16 bytes but got {}", v.len()))?;

    let mut secret: Vec<u8> = Vec::new();
    secret.extend(&encryption_request.verify_token);
    secret.extend(&shared_secret);

    let mut rng = OsRng;
    let encrypted_shared_secret = public_key.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &secret)?;
    let encrypted_verify_token = public_key.encrypt(
        &mut rng,
        rsa::Pkcs1v15Encrypt,
        &encryption_request.verify_token,
    )?;

    let encryption_response = c2s::EncryptionResponse {
        shared_secret: encrypted_shared_secret,
        verify_token: encrypted_verify_token,
    };

    RawPacket::from_packetio(&encryption_response)?
        .write(&mut remote_stream)
        .await?;

    let mut cfb8_stream = CFB8Stream::new_from_tcp(remote_stream, &shared_secret)?;

    let change_protocol: s2c::ChangeProtocol = RawPacket::read(&mut cfb8_stream)
        .await?
        .as_uncompressed()?
        .convert()?;

    let (mut client_rx, mut client_tx) = client_stream.into_split();
    let (rx, tx) = cfb8_stream.split_inner();

    let key: [u8; 32] = change_protocol.key.as_slice().try_into()?;
    let nonce: [u8; 20] = change_protocol.nonce.as_slice().try_into()?;

    let (mut remote_rx, mut remote_tx): (
        ReadHalf<_, DecryptorLE31<XChaCha20Poly1305>>,
        WriteHalf<_, EncryptorLE31<XChaCha20Poly1305>>,
    ) = encrypted_stream(rx, tx, key.as_ref().into(), nonce.as_ref().into());

    let c2s_thread =
        tokio::spawn(async move { tokio::io::copy(&mut client_rx, &mut remote_tx).await });
    let s2c_thread =
        tokio::spawn(async move { tokio::io::copy(&mut remote_rx, &mut client_tx).await });

    select! {
        _ = c2s_thread => {
            return Ok(())
        },
        _ = s2c_thread => {
            return Ok(())
        }
    };
}

fn calc_hash_u128(name: &str) -> u128 {
    let mut hasher = Sha1::new();
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);

    u128::from_be_bytes(bytes)
}

async fn check_known_host(
    state: &Arc<AppState>,
    server_addr: &str,
    fingerprint: &str,
) -> Result<(), String> {
    let known_hosts = state.known_hosts.lock().await;
    match known_hosts.get(server_addr) {
        Some(stored) if stored == fingerprint => Ok(()),
        Some(stored) => Err(stored.clone()),
        None => Err(String::new()),
    }
}

async fn add_known_host(
    state: &Arc<AppState>,
    server_addr: &str,
    fingerprint: &str,
) -> anyhow::Result<()> {
    let mut known_hosts = state.known_hosts.lock().await;

    known_hosts.insert(server_addr.to_string(), fingerprint.to_string());

    let mut contents = String::new();
    for (addr, fp) in known_hosts.iter() {
        contents.push_str(&format!("{} {}\n", addr, fp));
    }

    fs::write(&state.known_hosts_path, contents).await?;
    Ok(())
}
