use hex::FromHex;
use minecraft_protocol::{ser::Deserialize, varint::VarInt};
use std::io::{Cursor, Read, Write};

#[derive(Debug, Clone)]
enum FieldType {
    VarInt,
    Bool,
    String,
    Bytes,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    I128,
    U128,
}

impl std::str::FromStr for FieldType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "varint" => Ok(FieldType::VarInt),
            "bool" => Ok(FieldType::Bool),
            "string" => Ok(FieldType::String),
            "bytes" => Ok(FieldType::Bytes),
            "i8" => Ok(FieldType::I8),
            "u8" => Ok(FieldType::U8),
            "i16" => Ok(FieldType::I16),
            "u16" => Ok(FieldType::U16),
            "i32" => Ok(FieldType::I32),
            "u32" => Ok(FieldType::U32),
            "i64" => Ok(FieldType::I64),
            "u64" => Ok(FieldType::U64),
            "i128" => Ok(FieldType::I128),
            "u128" => Ok(FieldType::U128),
            _ => Err(format!("Unsupported type: {}", s)),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Packet Decoder started. Enter hex strings or 'exit' to quit.");

    loop {
        print!("\nEnter hex: ");
        std::io::stdout().flush()?;
        let mut hex_input = String::new();
        std::io::stdin().read_line(&mut hex_input)?;
        let hex_input = hex_input.trim();

        if hex_input.eq_ignore_ascii_case("exit") {
            break;
        }

        // Decode hex
        let raw = match Vec::from_hex(hex_input) {
            Ok(data) => data,
            Err(e) => {
                println!("Invalid hex: {}", e);
                continue;
            }
        };

        let mut cursor = Cursor::new(raw);

        // Read packet ID (always first)
        let packet_id = match VarInt::read_sync(&mut cursor) {
            Ok(id) => id,
            Err(e) => {
                println!("Error reading packet ID: {}", e);
                continue;
            }
        };
        println!("Packet ID: {}", packet_id.0);

        // Get field types
        print!("Enter field types (comma-separated): ");
        std::io::stdout().flush()?;
        let mut types_input = String::new();
        std::io::stdin().read_line(&mut types_input)?;
        let types_input = types_input.trim();

        let fields: Vec<FieldType> = types_input
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse())
            .collect::<Result<_, _>>()
            .map_err(|e| format!("Invalid field type: {}", e))?;

        // Parse fields
        for (i, f) in fields.iter().enumerate() {
            match f {
                FieldType::VarInt => {
                    let v = VarInt::read_sync(&mut cursor)?;
                    println!("[{}] VarInt: {}", i, v.0);
                }
                FieldType::Bool => {
                    let b = bool::deserialize(&mut cursor)?;
                    println!("[{}] bool: {}", i, b);
                }
                FieldType::String => {
                    let s = String::deserialize(&mut cursor)?;
                    println!("[{}] String: {}", i, s);
                }
                FieldType::Bytes => {
                    let bs = Vec::<u8>::deserialize(&mut cursor)?;
                    println!("[{}] Bytes (len={}): {:?}", i, bs.len(), bs);
                }
                FieldType::I8 => {
                    let mut buf = [0u8; 1];
                    cursor.read_exact(&mut buf)?;
                    println!("[{}] i8: {}", i, i8::from_be_bytes(buf));
                }
                FieldType::U8 => {
                    let mut buf = [0u8; 1];
                    cursor.read_exact(&mut buf)?;
                    println!("[{}] u8: {}", i, buf[0]);
                }
                FieldType::I16 => {
                    let mut buf = [0u8; 2];
                    cursor.read_exact(&mut buf)?;
                    println!("[{}] i16: {}", i, i16::from_be_bytes(buf));
                }
                FieldType::U16 => {
                    let mut buf = [0u8; 2];
                    cursor.read_exact(&mut buf)?;
                    println!("[{}] u16: {}", i, u16::from_be_bytes(buf));
                }
                FieldType::I32 => {
                    let mut buf = [0u8; 4];
                    cursor.read_exact(&mut buf)?;
                    println!("[{}] i32: {}", i, i32::from_be_bytes(buf));
                }
                FieldType::U32 => {
                    let mut buf = [0u8; 4];
                    cursor.read_exact(&mut buf)?;
                    println!("[{}] u32: {}", i, u32::from_be_bytes(buf));
                }
                FieldType::I64 => {
                    let mut buf = [0u8; 8];
                    cursor.read_exact(&mut buf)?;
                    println!("[{}] i64: {}", i, i64::from_be_bytes(buf));
                }
                FieldType::U64 => {
                    let mut buf = [0u8; 8];
                    cursor.read_exact(&mut buf)?;
                    println!("[{}] u64: {}", i, u64::from_be_bytes(buf));
                }
                FieldType::I128 => {
                    let mut buf = [0u8; 16];
                    cursor.read_exact(&mut buf)?;
                    println!("[{}] i128: {}", i, i128::from_be_bytes(buf));
                }
                FieldType::U128 => {
                    let mut buf = [0u8; 16];
                    cursor.read_exact(&mut buf)?;
                    println!("[{}] u128: {}", i, u128::from_be_bytes(buf));
                }
            }
        }

        // Check remaining bytes
        let mut remaining = Vec::new();
        cursor.read_to_end(&mut remaining).unwrap();
        if !remaining.is_empty() {
            println!(
                "Warning: {} unparsed bytes remaining: {:X?}",
                remaining.len(),
                remaining
            );
        }
    }

    println!("Exiting...");
    Ok(())
}
