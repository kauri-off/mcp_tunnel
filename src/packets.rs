use minecraft_protocol::varint::VarInt;
use minecraft_protocol_derive::Packet;

#[derive(Packet)]
#[packet(0x00)]
pub struct Handshake {
    pub protocol_version: VarInt,
    pub server_address: String,
    pub server_port: u16,
    pub intent: VarInt,
}

#[derive(Packet)]
#[packet(0x00)]
pub struct StatusRequest {}

#[derive(Packet)]
#[packet(0x00)]
pub struct StatusResponse {
    pub response: String,
}
