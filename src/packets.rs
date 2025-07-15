pub mod p767 {
    use minecraft_protocol::{Packet, varint::VarInt};

    pub mod c2s {

        use super::*;
        // ----------- HANDSHAKING -----------
        #[derive(Packet, Debug)]
        #[packet(0x00)]
        pub struct Handshake {
            pub protocol_version: VarInt,
            pub server_address: String,
            pub server_port: u16,
            pub intent: VarInt,
        }

        // ----------- STATUS -----------

        #[derive(Packet)]
        #[packet(0x00)]
        pub struct StatusRequest {}

        #[derive(Packet)]
        #[packet(0x01)]
        pub struct PingRequest {
            pub timestamp: i64,
        }

        // ----------- LOGIN -----------
        #[derive(Packet, Debug)]
        #[packet(0x00)]
        pub struct LoginStart {
            pub name: String,
            pub uuid: u128,
        }

        #[derive(Packet, Debug)]
        #[packet(0x01)]
        pub struct EncryptionResponse {
            pub shared_secret: Vec<u8>,
            pub verify_token: Vec<u8>,
        }
    }

    pub mod s2c {
        use super::*;

        // ----------- STATUS -----------
        #[derive(Packet)]
        #[packet(0x00)]
        pub struct StatusResponse {
            pub response: String,
        }

        #[derive(Packet)]
        #[packet(0x01)]
        pub struct PingResponse {
            pub timestamp: i64,
        }

        // ----------- LOGIN -----------
        #[derive(Packet, Debug)]
        #[packet(0x00)]
        pub struct LoginDisconnect {
            pub reason: String,
        }

        #[derive(Packet, Debug)]
        #[packet(0x01)]
        pub struct EncryptionRequest {
            pub server_id: String,
            pub public_key: Vec<u8>,
            pub verify_token: Vec<u8>,
            pub should_authenticate: bool,
        }

        #[derive(Packet, Debug)]
        #[packet(0x05)]
        pub struct ChangeProtocol {
            pub key: Vec<u8>,
            pub nonce: Vec<u8>,
        }
    }
}
