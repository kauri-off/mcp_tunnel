use std::io::Cursor;

use minecraft_protocol::packet::PacketIO;
use minecraft_protocol::{packet::RawPacket, varint::VarInt};

use serde_json::Value;
use tokio::net::TcpSocket;

use crate::packets::{Handshake, StatusRequest, StatusResponse};

mod packets;

#[tokio::main]
async fn main() {
    let mut conn = TcpSocket::new_v4()
        .unwrap()
        .connect("127.0.0.1:25565".parse().unwrap())
        .await
        .unwrap();

    let handshake = Handshake {
        protocol_version: VarInt(767),
        server_address: "127.0.0.1".to_string(),
        server_port: 25565,
        intent: VarInt(1),
    };

    RawPacket::from_packetio(&handshake)
        .unwrap()
        .write(&mut conn)
        .await
        .unwrap();

    RawPacket::from_packetio(&StatusRequest {})
        .unwrap()
        .write(&mut conn)
        .await
        .unwrap();

    let status_response = RawPacket::read(&mut conn)
        .await
        .unwrap()
        .as_unencrypted()
        .unwrap();

    let status_packet = StatusResponse::read(&mut Cursor::new(&status_response.payload)).unwrap();

    let value: Value = serde_json::from_str(&status_packet.response).unwrap();
    dbg!(&value);
}

#[cfg(test)]
mod tests {
    use minecraft_protocol::{
        packet::{Packet, PacketError},
        varint::VarIntError,
    };
    use tokio::io::BufReader;

    use super::*;
    use crate::packets::{Handshake, StatusResponse};
    use std::io::{self, Cursor};

    #[test]
    fn test_packet_serialization_deserialization() {
        // Handshake
        let handshake = Handshake {
            protocol_version: VarInt(404),
            server_address: "test.server".to_string(),
            server_port: 25565,
            intent: VarInt(1),
        };

        let mut buf = Vec::new();
        handshake.write(&mut buf).unwrap();
        let mut cursor = Cursor::new(buf);
        let packet_id = VarInt::read_sync(&mut cursor).unwrap();
        let decoded = Handshake::read(&mut cursor).unwrap();

        assert_eq!(decoded.protocol_version, handshake.protocol_version);
        assert_eq!(decoded.server_address, handshake.server_address);

        // StatusResponse
        let status = StatusResponse {
            response: r#"{"text":"Hello World"}"#.to_string(),
        };

        let mut buf = Vec::new();
        status.write(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let packet_id = VarInt::read_sync(&mut cursor).unwrap();
        let decoded = StatusResponse::read(&mut cursor).unwrap();

        assert_eq!(decoded.response, status.response);
    }

    #[tokio::test]
    async fn test_raw_packet_conversion() {
        let packet = Packet {
            packet_id: VarInt(0x42),
            payload: vec![1, 2, 3, 4, 5],
        };

        // Packet → RawPacket
        let raw = packet.to_raw_packet().unwrap();
        assert_eq!(raw.data[0], 0x42); // ID
        assert_eq!(&raw.data[1..], [1, 2, 3, 4, 5]);

        // RawPacket → Packet
        let converted = raw.as_unencrypted().unwrap();
        assert_eq!(converted.packet_id, packet.packet_id);
        assert_eq!(converted.payload, packet.payload);
    }

    #[test]
    fn test_encryption_decryption() {
        let shared_secret = [0u8; 16];
        let original = Packet {
            packet_id: VarInt(0x00),
            payload: b"test payload".to_vec(),
        };

        // Шифрование
        let encrypted = original.encrypt(&shared_secret).unwrap();
        assert_ne!(encrypted.encrypted_data, original.payload);

        // Дешифрование
        let decrypted = encrypted.decrypt(&shared_secret).unwrap();
        assert_eq!(decrypted.packet_id, original.packet_id);
        assert_eq!(decrypted.payload, original.payload);

        // Неверный ключ
        // let wrong_key = [2u8; 16];
        // match encrypted.decrypt(&wrong_key) {
        //     Err(PacketError::DecryptionError) => (), // Ожидаемая ошибка
        //     other => panic!("Unexpected result: {:?}", other),
        // }
    }

    #[tokio::test]
    async fn test_async_read_write() {
        let mut buffer = Vec::new();
        let mut original = RawPacket {
            data: vec![0x01, 0x02, 0x03, 0x04],
        };

        // Запись
        let mut writer = Cursor::new(&mut buffer);
        original.write(&mut writer).await.unwrap();

        // Проверка формата: [длина, данные]
        assert_eq!(buffer, vec![0x04, 0x01, 0x02, 0x03, 0x04]);

        // Чтение
        let mut reader = Cursor::new(&buffer);
        let read = RawPacket::read(&mut reader).await.unwrap();
        assert_eq!(read.data, original.data);
    }

    #[tokio::test]
    async fn test_handshake_workflow() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        // Клиент отправляет рукопожатие
        let handshake = Handshake {
            protocol_version: VarInt(404),
            server_address: "localhost".to_string(),
            server_port: 25565,
            intent: VarInt(1),
        };
        RawPacket::from_packetio(&handshake)
            .unwrap()
            .write(&mut client)
            .await
            .unwrap();

        // Сервер принимает пакет
        let received = RawPacket::read(&mut server)
            .await
            .unwrap()
            .as_unencrypted()
            .unwrap();

        // Проверка содержимого
        let decoded = Handshake::read(&mut Cursor::new(&received.payload)).unwrap();
        assert_eq!(decoded.server_address, "localhost");
    }

    #[tokio::test]
    async fn test_error_handling() {
        // Тест 1: Неполные данные при чтении RawPacket
        let mut reader = Cursor::new(vec![0xFF]); // Неполный VarInt
        assert!(RawPacket::read(&mut reader).await.is_err());

        // Тест 2: Неполный VarInt внутри пакета
        let invalid_raw = RawPacket { data: vec![0xFF] }; // Неполный VarInt
        let result = invalid_raw.as_unencrypted();

        // Проверяем конкретный тип ошибки
        match result {
            Err(PacketError::VarIntError(VarIntError::IOError(e))) => {
                assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
            }
            other => panic!("Unexpected result: {:?}", other),
        }

        // Тест 3: Пустой пакет
        let empty = RawPacket { data: vec![] };
        let result = empty.as_unencrypted();
        match result {
            Err(PacketError::VarIntError(VarIntError::IOError(e))) => {
                assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    // Тест кодирования/декодирования для различных значений
    #[test]
    fn test_varint_roundtrip() {
        let test_cases = vec![
            0,
            1,
            2,
            127, // Макс. 1-байтовое значение
            128, // Миним. 2-байтовое значение
            255,
            2147483647, // Максимальное i32
            -1,
            -2147483648, // Минимальное i32
            123456789,
        ];

        for value in test_cases {
            let varint = VarInt(value);
            let mut buf = Vec::new();
            varint.write_sync(&mut buf).unwrap();

            let mut cursor = Cursor::new(buf);
            let decoded = VarInt::read_sync(&mut cursor).unwrap();

            assert_eq!(decoded.0, value, "Roundtrip failed for {}", value);
        }
    }

    // Тест на обработку ошибок (слишком длинное значение)
    #[test]
    fn test_varint_too_long() {
        // Попытка прочитать 6 байт (максимум по протоколу - 5 байт)
        let data = vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
        let mut cursor = Cursor::new(data);

        let result = VarInt::read_sync(&mut cursor);
        assert!(matches!(result, Err(VarIntError::Position)));
    }

    // Тест на неполные данные
    #[tokio::test]
    async fn test_incomplete_varint() {
        // Только начало VarInt (CONTINUE_BIT установлен)
        let data = vec![0x80];
        let mut reader = BufReader::new(Cursor::new(data));

        let result = VarInt::read(&mut reader).await;
        assert!(matches!(result, Err(VarIntError::IOError(_))));
    }

    // Тест асинхронного чтения/записи
    #[tokio::test]
    async fn test_async_roundtrip() {
        let values = vec![0, 1, 127, 128, 255, 12345, -12345];

        for value in values {
            let varint = VarInt(value);
            let mut buf = Vec::new();
            varint.write(&mut buf).await.unwrap();

            let mut reader = Cursor::new(buf);
            let decoded = VarInt::read(&mut reader).await.unwrap();

            assert_eq!(decoded.0, value, "Async roundtrip failed for {}", value);
        }
    }

    // Тест на специфические кейсы из протокола Minecraft
    #[test]
    fn test_minecraft_specific_cases() {
        // Примеры из официальной документации
        let test_cases = vec![
            (0, vec![0x00]),
            (1, vec![0x01]),
            (2, vec![0x02]),
            (127, vec![0x7F]),
            (128, vec![0x80, 0x01]),
            (255, vec![0xFF, 0x01]),
            (25565, vec![0xDD, 0xC7, 0x01]),
            (2147483647, vec![0xFF, 0xFF, 0xFF, 0xFF, 0x07]),
            (-1, vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F]),
            (-2147483648, vec![0x80, 0x80, 0x80, 0x80, 0x08]),
        ];

        for (value, expected_bytes) in test_cases {
            // Тест кодирования
            let varint = VarInt(value);
            let mut buf = Vec::new();
            varint.write_sync(&mut buf).unwrap();
            assert_eq!(buf, expected_bytes, "Encoding failed for {}", value);

            // Тест декодирования
            let mut cursor = Cursor::new(&expected_bytes);
            let decoded = VarInt::read_sync(&mut cursor).unwrap();
            assert_eq!(decoded.0, value, "Decoding failed for {:?}", expected_bytes);
        }
    }

    // Тест на частичное чтение
    #[tokio::test]
    async fn test_partial_read() {
        // Корректное представление для -2147483648
        let data = vec![0x80, 0x80, 0x80, 0x80, 0x78];
        let mut reader = BufReader::new(Cursor::new(data));

        // Проверяем, что читается корректно
        let value = VarInt::read(&mut reader).await.unwrap();
        assert_eq!(value.0, -2147483648);
    }

    // Тест на запись/чтение последовательности
    #[tokio::test]
    async fn test_sequence() {
        let values = vec![
            VarInt(0),
            VarInt(1),
            VarInt(128),
            VarInt(-1),
            VarInt(2147483647),
        ];

        let mut buf = Vec::new();

        // Записываем последовательность
        for varint in &values {
            varint.write(&mut buf).await.unwrap();
        }

        // Читаем последовательно
        let mut reader = Cursor::new(buf);
        for expected in values {
            let decoded = VarInt::read(&mut reader).await.unwrap();
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn test_varint_incomplete_data() {
        // Проверка неполных данных
        let test_cases = vec![
            vec![0x80],       // Только CONTINUE_BIT
            vec![0x80, 0x80], // Не хватает последнего байта
            vec![0xFF, 0xFF], // Неполные данные для 3-байтового числа
        ];

        for data in test_cases {
            let mut cursor = Cursor::new(&data);
            let result = VarInt::read_sync(&mut cursor);

            match result {
                Err(VarIntError::IOError(e)) => {
                    assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
                }
                other => panic!("Unexpected result for {:?}: {:?}", data, other),
            }
        }
    }

    #[tokio::test]
    async fn test_async_varint_incomplete_data() {
        let data = vec![0x80];
        let mut reader = Cursor::new(data);

        match VarInt::read(&mut reader).await {
            Err(VarIntError::IOError(e)) => {
                assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }
}
