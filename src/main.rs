use clap::Parser;

use crate::{cli::Cli, temp_server::setup_temp_server};

mod cli;
mod packets;
mod temp_server;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli {
        Cli::TempServer { ip } => setup_temp_server(&ip).await,
    }
}

#[cfg(test)]
mod tests {
    use minecraft_protocol::{
        encrypted_stream::EncryptedStream,
        packet::{PacketError, PacketIO, RawPacket, UncompressedPacket},
        varint::{VarInt, VarIntError},
    };
    use openssl::symm::{Cipher, Crypter, Mode};
    use tokio::io::BufReader;

    use crate::packets::p767::{
        c2s::{self, Handshake},
        s2c::{self, StatusResponse},
    };
    use serde_json::Value;
    use std::io::{self, Cursor};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
        let _packet_id = VarInt::read_sync(&mut cursor).unwrap();
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
        let _packet_id = VarInt::read_sync(&mut cursor).unwrap();
        let decoded = StatusResponse::read(&mut cursor).unwrap();

        assert_eq!(decoded.response, status.response);
    }

    #[tokio::test]
    async fn test_raw_packet_conversion() {
        let packet = UncompressedPacket {
            packet_id: VarInt(0x42),
            payload: vec![1, 2, 3, 4, 5],
        };

        // Packet → RawPacket
        let raw = packet.to_raw_packet().unwrap();
        assert_eq!(raw.data[0], 0x42); // ID
        assert_eq!(&raw.data[1..], [1, 2, 3, 4, 5]);

        // RawPacket → Packet
        let converted = raw.as_uncompressed().unwrap();
        assert_eq!(converted.packet_id, packet.packet_id);
        assert_eq!(converted.payload, packet.payload);
    }

    #[tokio::test]
    async fn test_async_read_write() {
        let mut buffer = Vec::new();
        let original = RawPacket {
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
            .as_uncompressed()
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
        let result = invalid_raw.as_uncompressed();

        // Проверяем конкретный тип ошибки
        match result {
            Err(PacketError::VarIntError(VarIntError::IOError(e))) => {
                assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
            }
            other => panic!("Unexpected result: {:?}", other),
        }

        // Тест 3: Пустой пакет
        let empty = RawPacket { data: vec![] };
        let result = empty.as_uncompressed();
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

    const SHARED_SECRET: &'static [u8; 16] = &[0x42; 16];

    #[tokio::test]
    async fn test_small_data() {
        let (client, server) = tokio::io::duplex(1024);

        let mut client_stream = EncryptedStream::new(client, SHARED_SECRET).unwrap();
        let mut server_stream = EncryptedStream::new(server, SHARED_SECRET).unwrap();

        let data = b"Hello";
        client_stream.write_all(data).await.unwrap();
        client_stream.flush().await.unwrap();

        let mut buf = [0u8; 5];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, data);
    }

    #[tokio::test]
    async fn test_large_data() {
        let (client, server) = tokio::io::duplex(4096);

        let mut client_stream = EncryptedStream::new(client, SHARED_SECRET).unwrap();
        let mut server_stream = EncryptedStream::new(server, SHARED_SECRET).unwrap();

        // Generate 2048 bytes of data
        let data: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();
        client_stream.write_all(&data).await.unwrap();
        client_stream.flush().await.unwrap();

        let mut buf = vec![0u8; 2048];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, data);
    }

    #[tokio::test]
    async fn test_multiple_writes() {
        let (client, server) = tokio::io::duplex(1024);

        let mut client_stream = EncryptedStream::new(client, SHARED_SECRET).unwrap();
        let mut server_stream = EncryptedStream::new(server, SHARED_SECRET).unwrap();

        let data1 = b"Hello";
        let data2 = b", world!";
        client_stream.write_all(data1).await.unwrap();
        client_stream.write_all(data2).await.unwrap();
        client_stream.flush().await.unwrap();

        let mut buf = [0u8; 13];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"Hello, world!");
    }

    #[tokio::test]
    async fn test_full_minecraft_flow() {
        // Start test server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = EncryptedStream::new(socket, SHARED_SECRET).unwrap();

            // Read handshake
            let handshake: c2s::Handshake = RawPacket::read(&mut stream)
                .await
                .unwrap()
                .as_uncompressed()
                .unwrap()
                .convert()
                .unwrap();

            assert_eq!(handshake.protocol_version, VarInt(767));
            assert_eq!(handshake.server_address, "127.0.0.1");
            assert_eq!(handshake.server_port, 25565);
            assert_eq!(handshake.intent, VarInt(1));

            // Read status request
            let _: c2s::StatusRequest = RawPacket::read(&mut stream)
                .await
                .unwrap()
                .as_uncompressed()
                .unwrap()
                .convert()
                .unwrap();

            // Send status response
            let response = s2c::StatusResponse {
                response: r#"{"version":{"name":"1.20.1","protocol":757},"players":{"max":20,"online":0}}"#.to_string(),
            };
            RawPacket::from_packetio(&response)
                .unwrap()
                .write(&mut stream)
                .await
                .unwrap();
        });

        // Run client
        let client = tokio::spawn(async move {
            let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut stream = EncryptedStream::new(socket, SHARED_SECRET).unwrap();

            // Send handshake
            let handshake = c2s::Handshake {
                protocol_version: VarInt(767),
                server_address: "127.0.0.1".to_string(),
                server_port: 25565,
                intent: VarInt(1),
            };
            RawPacket::from_packetio(&handshake)
                .unwrap()
                .write(&mut stream)
                .await
                .unwrap();

            // Send status request
            RawPacket::from_packetio(&c2s::StatusRequest {})
                .unwrap()
                .write(&mut stream)
                .await
                .unwrap();

            // Read status response
            let status_response: s2c::StatusResponse = RawPacket::read(&mut stream)
                .await
                .unwrap()
                .as_uncompressed()
                .unwrap()
                .convert()
                .unwrap();

            // Parse and verify response
            let value: Value = serde_json::from_str(&status_response.response).unwrap();
            assert_eq!(value["version"]["name"], "1.20.1");
            assert_eq!(value["version"]["protocol"], 757);
            assert_eq!(value["players"]["max"], 20);
            assert_eq!(value["players"]["online"], 0);
        });

        // Wait for both to complete
        tokio::try_join!(server, client).unwrap();
    }

    #[tokio::test]
    async fn test_encryption_roundtrip() {
        let data = b"Test data for encryption roundtrip";
        let key = [0x56; 16];
        let iv = [0x78; 16];

        // Encrypt
        let mut encrypted = data.to_vec();
        {
            let cipher = Cipher::aes_128_cfb8();
            let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv)).unwrap();
            encrypter.pad(false);
            let mut out = vec![0; encrypted.len() + cipher.block_size()];
            let count = encrypter.update(&encrypted, &mut out).unwrap();
            encrypted = out[..count].to_vec();
        }

        // Decrypt
        let mut decrypted = encrypted.clone();
        {
            let cipher = Cipher::aes_128_cfb8();
            let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv)).unwrap();
            decrypter.pad(false);
            let mut out = vec![0; decrypted.len() + cipher.block_size()];
            let count = decrypter.update(&decrypted, &mut out).unwrap();
            decrypted = out[..count].to_vec();
        }

        assert_eq!(decrypted, data);
    }
}
