use minecraft_protocol::encrypted_stream::EncryptedStream;
use minecraft_protocol::packet::RawPacket;
use rsa::pkcs8::EncodePublicKey;
use rsa::{rand_core::OsRng, RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

use crate::packets::p767::{c2s, s2c};

pub async fn start_server() {
    // TODO: Get rsa key from config
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();

    let tcp_listener = TcpListener::bind("127.0.0.1:7777").await.unwrap();

    while let Ok((stream, addr)) = tcp_listener.accept().await {
        tokio::spawn(process_new_stream(stream, addr, private_key.clone()));
    }
}

pub async fn process_new_stream(
    mut stream: TcpStream,
    addr: SocketAddr,
    private_key: RsaPrivateKey,
) -> anyhow::Result<()> {
    let handshake: c2s::Handshake = RawPacket::read(&mut stream)
        .await?
        .as_uncompressed()?
        .convert()?;

    match handshake.intent.0 {
        1 => process_status(stream, addr).await.unwrap(),
        2 => process_login(stream, addr, private_key).await.unwrap(),
        _ => return Ok(()),
    };

    Ok(())
}

async fn process_login(
    mut stream: TcpStream,
    addr: SocketAddr,
    private_key: RsaPrivateKey,
) -> anyhow::Result<()> {
    let _login_start: c2s::LoginStart = RawPacket::read(&mut stream)
        .await?
        .as_uncompressed()?
        .convert()?;

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
        .write(&mut stream)
        .await?;

    let encryption_response: c2s::EncryptionResponse = RawPacket::read(&mut stream)
        .await?
        .as_uncompressed()?
        .convert()?;

    let shared_secret_vec =
        private_key.decrypt(rsa::Pkcs1v15Encrypt, &encryption_response.shared_secret)?;
    let verify_token_resp =
        private_key.decrypt(rsa::Pkcs1v15Encrypt, &encryption_response.verify_token)?;

    if verify_token_resp != verify_token {
        println!("Verify token mismatch for {}", addr);
        return Ok(());
    }

    let shared_secret: &[u8; 16] = shared_secret_vec.as_slice().try_into()?;

    let mut encrypted_stream = EncryptedStream::new_from_tcp(stream, shared_secret)?;

    // Check if login_start.username is in config
    // If yes, compare shared_secret_vec with config
    // If its the same, process real key exchange using EncryptedStream

    if false { // Check for user config
    } else {
        RawPacket::from_packetio(&s2c::LoginDisconnect {
            reason: json!({
                "text": "You are not whitelisted"
            })
            .to_string(),
        })?
        .write(&mut encrypted_stream)
        .await?;
    }

    Ok(())
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
                        "sample": []
                      },
                      "description": {
                        "text": "A Minecraft Server"
                      },
                    }
                    )
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
