use openssl::symm::{Cipher, Crypter, Mode};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub struct EncryptedStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub read_stream: EncryptedReadStream<R>,
    pub write_stream: EncryptedWriteStream<W>,
}

pub struct EncryptedReadStream<R>
where
    R: AsyncRead + Unpin,
{
    read_half: R,
    decrypter: Crypter,
}

pub struct EncryptedWriteStream<W>
where
    W: AsyncWrite + Unpin,
{
    write_half: W,
    encrypter: Crypter,
}

impl<W> EncryptedWriteStream<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn new(write_half: W, key: &[u8; 16]) -> io::Result<Self> {
        let encrypter = get_encrypter(key)?;

        Ok(Self {
            write_half,
            encrypter,
        })
    }
}

impl<R> EncryptedReadStream<R>
where
    R: AsyncRead + Unpin,
{
    pub fn new(read_half: R, key: &[u8; 16]) -> io::Result<Self> {
        let decrypter = get_decrypter(key)?;

        Ok(Self {
            read_half,
            decrypter,
        })
    }
}

fn get_encrypter(key: &[u8; 16]) -> io::Result<Crypter> {
    let cipher = Cipher::aes_128_cfb8();

    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(key))?;
    encrypter.pad(false);
    Ok(encrypter)
}

fn get_decrypter(key: &[u8; 16]) -> io::Result<Crypter> {
    let cipher = Cipher::aes_128_cfb8();

    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(key))?;
    decrypter.pad(false);
    Ok(decrypter)
}

impl<R, W> EncryptedStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(read_half: R, write_half: W, key: &[u8; 16]) -> io::Result<Self> {
        let read_stream = EncryptedReadStream::new(read_half, key)?;

        let write_stream = EncryptedWriteStream::new(write_half, key)?;

        Ok(Self {
            read_stream,
            write_stream,
        })
    }

    pub fn change_key(&mut self, key: &[u8; 16]) -> io::Result<()> {
        let encrypter = get_encrypter(key)?;
        let decrypter = get_decrypter(key)?;

        self.read_stream.decrypter = decrypter;
        self.write_stream.encrypter = encrypter;

        Ok(())
    }
}

impl EncryptedStream<OwnedReadHalf, OwnedWriteHalf> {
    pub fn new_from_tcp(
        stream: TcpStream,
        key: &[u8; 16],
    ) -> io::Result<EncryptedStream<OwnedReadHalf, OwnedWriteHalf>> {
        let (read_half, write_half) = stream.into_split();

        EncryptedStream::new(read_half, write_half, key)
    }
}

impl<R> AsyncRead for EncryptedReadStream<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pre_len = buf.filled().len();
        let poll = Pin::new(&mut self.read_half).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = poll {
            let new_data = &mut buf.filled_mut()[pre_len..];
            let mut output = vec![0; new_data.len()];
            self.decrypter
                .update(new_data, &mut output)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            new_data.copy_from_slice(&output);
        }

        poll
    }
}

impl<W> AsyncWrite for EncryptedWriteStream<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut encrypted = vec![0; buf.len() + 16];
        let count = self
            .encrypter
            .update(buf, &mut encrypted)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        encrypted.truncate(count);

        Pin::new(&mut self.write_half).poll_write(cx, &encrypted)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.write_half).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.write_half).poll_shutdown(cx)
    }
}

impl<R, W> AsyncRead for EncryptedStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.read_stream), cx, buf)
    }
}

impl<R, W> AsyncWrite for EncryptedStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.write_stream), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.write_stream), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.write_stream), cx)
    }
}
