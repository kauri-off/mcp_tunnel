use std::net::SocketAddr;

use log::{debug, error, info, warn};
use minecraft_protocol::cfb8_stream::CFB8Stream;
use minecraft_protocol::packet::RawPacket;
use rsa::pkcs8::EncodePublicKey;
use rsa::{rand_core::OsRng, RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};

use crate::packets::p767::{c2s, s2c};

pub async fn setup_honeypot(ip: &str) {
    // Initialize env_logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_target(false)
        .init();

    let mut rng = OsRng;
    debug!("Generating RSA key pair...");
    let private_key = RsaPrivateKey::new(&mut rng, 1024).expect("failed to generate private key");

    info!("RSA key pair generated");

    let conn = TcpListener::bind(ip).await.unwrap();
    info!("Started listening on {}", ip);

    while let Ok((stream, addr)) = conn.accept().await {
        println!("\n");
        info!("Accepted new connection from {}", addr);
        tokio::spawn(process_new_socket(stream, addr, private_key.clone()));
    }
}

async fn process_new_socket(mut stream: TcpStream, addr: SocketAddr, private_key: RsaPrivateKey) {
    debug!("Waiting for handshake from {}", addr);

    let handshake_res = RawPacket::read(&mut stream).await;
    if handshake_res.is_err() {
        error!(
            "Failed to read handshake from {}: {:?}",
            addr,
            handshake_res.err()
        );
        return;
    }

    let raw_handshake = handshake_res.unwrap();
    let handshake: c2s::Handshake = raw_handshake.as_uncompressed().unwrap().convert().unwrap();

    info!(
        "Handshake received from {}: protocol={}, intent={}",
        addr, handshake.protocol_version.0, handshake.intent.0
    );

    if handshake.intent.0 == 1 {
        info!("{} -> status request", addr);
        process_status(stream, handshake.protocol_version.0).await;
    } else if handshake.intent.0 == 2 {
        info!("{} -> login request", addr);
        process_login(stream, addr, private_key).await;
    } else {
        warn!("{} -> unknown intent: {}", addr, handshake.intent.0);
    }
}

async fn process_status(mut stream: TcpStream, protocol: i32) {
    debug!("Processing status for protocol {}", protocol);

    while let Ok(packet) = RawPacket::read(&mut stream).await {
        let packet_id = packet.clone().as_uncompressed().unwrap().packet_id;

        debug!("Status packet received: id={}", packet_id.0);

        if packet_id.0 == 0 {
            info!("Sending status response");
            RawPacket::from_packetio(&s2c::StatusResponse {
                response: json!({
                  "version": {
                    "name": "1.21.1",
                    "protocol": 767
                  },
                  "players": {
                    "max": 20,
                    "online": 1,
                    "sample": [
                        {"name": "radioheadfan5679", "id": "50abe2eb-d25c-4563-975d-c359caff7740"}
                    ]
                  },
                  "description": "A Minecraft Server",
                  "enforcesSecureChat": true
                })
                .to_string(),
            })
            .unwrap()
            .write(&mut stream)
            .await
            .unwrap();
        } else if packet_id.0 == 1 {
            info!("Responding to ping request");
            packet.write(&mut stream).await.unwrap();
        } else {
            warn!("Unknown packet id={} in status", packet_id.0);
        }
    }
    info!("Status processing finished");
}

async fn process_login(mut stream: TcpStream, addr: SocketAddr, private_key: RsaPrivateKey) {
    debug!("Reading LoginStart packet from {}", addr);

    let login_start_res = RawPacket::read(&mut stream).await;
    if login_start_res.is_err() {
        error!(
            "Failed to read LoginStart from {}: {:?}",
            addr,
            login_start_res.err()
        );
        return;
    }

    let login_start: c2s::LoginStart = login_start_res
        .unwrap()
        .as_uncompressed()
        .unwrap()
        .convert()
        .unwrap();

    info!("LoginStart: username={} from {}", login_start.name, addr);

    let public_key = RsaPublicKey::from(&private_key);
    let public_key_der = public_key
        .to_public_key_der()
        .expect("failed to create DER");

    // Send EncryptionRequest
    let verify_token: [u8; 4] = rand::random();
    debug!("Generated verify token: {:?}", verify_token);

    let encryption_request = s2c::EncryptionRequest {
        server_id: "".to_string(),
        public_key: public_key_der.as_bytes().to_vec(),
        verify_token: verify_token.to_vec(),
        should_authenticate: false,
    };

    info!("Sending EncryptionRequest to {}", addr);
    RawPacket::from_packetio(&encryption_request)
        .unwrap()
        .write(&mut stream)
        .await
        .unwrap();

    // Read EncryptionResponse
    debug!("Waiting for EncryptionResponse from {}", addr);
    let encrypted_response: c2s::EncryptionResponse = RawPacket::read(&mut stream)
        .await
        .unwrap()
        .as_uncompressed()
        .unwrap()
        .convert()
        .unwrap();

    info!("Received EncryptionResponse from {}", addr);

    // Verify EncryptionResponse
    let shared_secret_vec = private_key
        .decrypt(rsa::Pkcs1v15Encrypt, &encrypted_response.shared_secret)
        .unwrap();
    let verify_token_resp = private_key
        .decrypt(rsa::Pkcs1v15Encrypt, &encrypted_response.verify_token)
        .unwrap();

    if verify_token_resp != verify_token {
        error!("Verify token mismatch for {}", addr);
        return;
    }

    info!("Verify token validated for {}", addr);

    let shared_secret: &[u8; 16] = shared_secret_vec
        .as_slice()
        .try_into()
        .expect("Vec length is not 16");

    let mut encrypted_stream = CFB8Stream::new_from_tcp(stream, shared_secret).unwrap();
    info!("Encrypted stream established with {}", addr);

    // Disconnect player
    info!("Disconnecting player {} ({})", login_start.name, addr);

    RawPacket::from_packetio(&s2c::LoginDisconnect {
        reason: json!({
          "text": format!("§aHello, {} :). Your ip is ({})", &login_start.name, &addr)
        })
        .to_string(),
    })
    .unwrap()
    .write(&mut encrypted_stream)
    .await
    .unwrap();

    info!("Player {} disconnected", login_start.name);
}
