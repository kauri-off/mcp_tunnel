use std::net::SocketAddr;

use minecraft_protocol::encrypted_stream::EncryptedStream;
use minecraft_protocol::packet::RawPacket;
use rsa::pkcs8::EncodePublicKey;
use rsa::{rand_core::OsRng, RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};

use crate::packets::p767::{c2s, s2c};

pub async fn setup_temp_server(ip: &str) {
    let conn = TcpListener::bind(ip).await.unwrap();
    println!("Started listening on {}", ip);

    while let Ok((mut stream, addr)) = conn.accept().await {
        let handshake: c2s::Handshake = RawPacket::read(&mut stream)
            .await
            .unwrap()
            .as_uncompressed()
            .unwrap()
            .convert()
            .unwrap();

        if handshake.intent.0 == 1 {
            println!(
                "New connection [{}] {} -> status",
                handshake.protocol_version.0, addr
            );
            let _ = tokio::spawn(process_status(stream, handshake.protocol_version.0)).await;
        } else if handshake.intent.0 == 2 {
            println!(
                "New connection [{}] {} -> login",
                handshake.protocol_version.0, addr
            );
            let _ = tokio::spawn(process_login(stream, addr)).await;
        }
    }
}

async fn process_status(mut stream: TcpStream, protocol: i32) {
    while let Ok(packet) = RawPacket::read(&mut stream).await {
        let packet_id = packet.clone().as_uncompressed().unwrap().packet_id;

        if packet_id.0 == 0 {
            RawPacket::from_packetio(&s2c::StatusResponse {
                response: json!({
                  "version": {
                    "name": "minecraft_rust_core",
                    "protocol": protocol
                  },
                  "players": {
                    "max": 20,
                    "online": 2,
                    "sample": [
                    {
                        "name": "Notch",
                        "id": "4ed1f46b-be04-bc75-6bcb-17c0c7ce3e46"
                    },
                    {
                        "name": "jeb_",
                        "id": "8362a4ff-bb3b-ecf6-f65e-2b3c17e3d7df"
                    }
                    ]

                  },
                  "description": {
                    "text": "§aMojang`s private server"
                  },
                //   "favicon": "data:image/png;base64,<base64-encoded-favicon>"
                }
                )
                .to_string(),
            })
            .unwrap()
            .write(&mut stream)
            .await
            .unwrap();
        } else if packet_id.0 == 1 {
            packet.write(&mut stream).await.unwrap();
        }
    }
}

async fn process_login(mut stream: TcpStream, addr: SocketAddr) {
    // Read LoginStart
    let login_start: c2s::LoginStart = RawPacket::read(&mut stream)
        .await
        .unwrap()
        .as_uncompressed()
        .unwrap()
        .convert()
        .unwrap();
    dbg!(&login_start);

    // Generate rsa pair
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 1024).expect("failed to generate private key");
    let public_key = RsaPublicKey::from(&private_key);
    let public_key_der = public_key
        .to_public_key_der()
        .expect("failed to create DER");

    // Send EncryptionRequest
    let verify_token: [u8; 4] = rand::random();

    let encryption_request = s2c::EncryptionRequest {
        server_id: "".to_string(),
        public_key: public_key_der.as_bytes().to_vec(),
        verify_token: verify_token.to_vec(),
        should_authenticate: false,
    };

    RawPacket::from_packetio(&encryption_request)
        .unwrap()
        .write(&mut stream)
        .await
        .unwrap();

    // Read EncryptionResponse
    let encrypted_response: c2s::EncryptionResponse = RawPacket::read(&mut stream)
        .await
        .unwrap()
        .as_uncompressed()
        .unwrap()
        .convert()
        .unwrap();

    // Verify EncryptionResponse
    let shared_secret_vec = private_key
        .decrypt(rsa::Pkcs1v15Encrypt, &encrypted_response.shared_secret)
        .unwrap();
    let verify_token_resp = private_key
        .decrypt(rsa::Pkcs1v15Encrypt, &encrypted_response.verify_token)
        .unwrap();

    assert_eq!(verify_token_resp, verify_token);

    let shared_secret: &[u8; 16] = shared_secret_vec
        .as_slice()
        .try_into()
        .expect("Vec length is not 16");

    let mut encrypted_stream = EncryptedStream::new(stream, shared_secret).unwrap();

    // Disconnect player

    RawPacket::from_packetio(&s2c::LoginDisconnect {
        reason: json!({
          "text": format!("§aHello, {} :). Your ip is ({})", &login_start.name, &addr)
        }
        )
        .to_string(),
    })
    .unwrap()
    .write(&mut encrypted_stream)
    .await
    .unwrap();
}
