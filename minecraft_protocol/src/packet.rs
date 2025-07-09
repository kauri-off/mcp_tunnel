use aes::cipher::AsyncStreamCipher;
use cipher::KeyIvInit;
use std::io::{self, Cursor, Read, Write};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    ser::SerializationError,
    varint::{VarInt, VarIntError},
};

type Aes128Cfb8Enc = cfb8::Encryptor<aes::Aes128>;
type Aes128Cfb8Dec = cfb8::Decryptor<aes::Aes128>;

pub trait PacketIO {
    fn write<W: Write + Unpin>(&self, writer: &mut W) -> Result<(), SerializationError>;

    fn read<R: Read + Unpin>(reader: &mut R) -> Result<Self, SerializationError>
    where
        Self: Sized;
}

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("DecryptionError")]
    DecryptionError,

    #[error("VarIntError: {0}")]
    VarIntError(#[from] VarIntError),

    #[error("IO Error: {0}")]
    IOError(#[from] io::Error),
}

#[derive(Debug)]
pub struct Packet {
    pub packet_id: VarInt,
    pub payload: Vec<u8>,
}

pub struct EncryptedPacket {
    pub encrypted_data: Vec<u8>,
}

pub struct RawPacket {
    pub data: Vec<u8>,
}

impl RawPacket {
    pub async fn read<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Self, PacketError> {
        let len = VarInt::read(reader).await?;
        let mut buf = vec![0; len.0 as usize];

        reader.read_exact(&mut buf).await?;

        Ok(Self { data: buf })
    }

    pub async fn write<W: AsyncWriteExt + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), PacketError> {
        VarInt(self.data.len() as i32).write(writer).await?;

        writer.write_all(&self.data).await?;

        Ok(())
    }

    pub fn as_encrypted(self) -> EncryptedPacket {
        EncryptedPacket {
            encrypted_data: self.data,
        }
    }

    pub fn as_unencrypted(self) -> Result<Packet, PacketError> {
        let mut cursor = Cursor::new(self.data);
        let packet_id = VarInt::read_sync(&mut cursor)?;
        let mut payload = Vec::new();
        std::io::Read::read_to_end(&mut cursor, &mut payload)?;

        Ok(Packet { packet_id, payload })
    }

    pub fn from_packetio<T: PacketIO>(packet: &T) -> Result<Self, SerializationError> {
        let mut buf = Vec::new();

        packet.write(&mut buf)?;
        Ok(Self { data: buf })
    }
}

impl Packet {
    pub fn encrypt(&self, shared_secret: &[u8; 16]) -> Result<EncryptedPacket, PacketError> {
        let mut raw_packet = self.to_raw_packet()?;

        Aes128Cfb8Enc::new(shared_secret.into(), shared_secret.into())
            .encrypt(&mut raw_packet.data);

        Ok(raw_packet.as_encrypted())
    }

    pub fn to_raw_packet(&self) -> Result<RawPacket, PacketError> {
        let mut buf = Vec::new();
        self.packet_id.write_sync(&mut buf)?;
        buf.extend(&self.payload);
        Ok(RawPacket { data: buf })
    }
}

impl EncryptedPacket {
    pub fn decrypt(&self, shared_secret: &[u8; 16]) -> Result<Packet, PacketError> {
        let mut buf = vec![0u8; self.encrypted_data.len()];

        Aes128Cfb8Dec::new(shared_secret.into(), shared_secret.into())
            .decrypt_b2b(&self.encrypted_data, &mut buf)
            .map_err(|_| PacketError::DecryptionError)?;

        Ok(RawPacket { data: buf }.as_unencrypted()?)
    }

    pub fn to_raw_packet(&self) -> RawPacket {
        RawPacket {
            data: self.encrypted_data.clone(),
        }
    }
}
