use chrono::Local;
use minecraft_protocol::packet::RawPacket;
use std::sync::Arc;
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

#[derive(Debug, Clone, Copy)]
enum Dir {
    C2S,
    S2C,
}

async fn process<W>(
    packet: RawPacket,
    writer: &mut W,
    dir: Dir,
    log_file: &Arc<Mutex<tokio::fs::File>>,
) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    // Логируем пакет
    let log_line = format!("[{:?}] {}\n", dir, hex::encode(&packet.data));

    {
        let mut file = log_file.lock().await;
        file.write_all(log_line.as_bytes()).await?;
        file.flush().await?;
    }

    // Отправляем пакет в другой сокет
    packet.write(writer).await?;

    Ok(())
}
async fn handle_connection(client: TcpStream, server: TcpStream) -> tokio::io::Result<()> {
    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let filename = format!("packets_{}.log", timestamp);
    let log_file = Arc::new(Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(filename)
            .await?,
    ));

    // split до Arc
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut server_reader, mut server_writer) = tokio::io::split(server);

    let log_file_c2s = log_file.clone();
    let log_file_s2c = log_file.clone();

    let c2s = tokio::spawn(async move {
        loop {
            match RawPacket::read(&mut client_reader).await {
                Ok(packet) => {
                    if let Err(e) =
                        process(packet, &mut server_writer, Dir::C2S, &log_file_c2s).await
                    {
                        eprintln!("C2S error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("C2S read error: {}", e);
                    break;
                }
            }
        }
    });

    let s2c = tokio::spawn(async move {
        loop {
            match RawPacket::read(&mut server_reader).await {
                Ok(packet) => {
                    if let Err(e) =
                        process(packet, &mut client_writer, Dir::S2C, &log_file_s2c).await
                    {
                        eprintln!("S2C error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("S2C read error: {}", e);
                    break;
                }
            }
        }
    });

    let _ = tokio::try_join!(c2s, s2c);

    Ok(())
}

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:25566").await?;
    println!("Listening on 0.0.0.0:25566");

    loop {
        let (client_socket, client_addr) = listener.accept().await?;
        println!("Client connected: {}", client_addr);

        // Здесь мы сразу соединяемся с целевым сервером
        let server_socket = TcpStream::connect("127.0.0.1:25565").await?;
        println!("Connected to target server");

        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_socket, server_socket).await {
                eprintln!("Connection error: {}", e);
            }
        });
    }
}
