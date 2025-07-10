use openssl::symm::{Cipher, Crypter, Mode};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct EncryptedStream<T: AsyncRead + AsyncWrite + Unpin> {
    stream: T,
    encrypter: Crypter,
    decrypter: Crypter,
}

impl<T: AsyncRead + AsyncWrite + Unpin> EncryptedStream<T> {
    pub fn new(stream: T, key: &[u8; 16]) -> io::Result<Self> {
        let cipher = Cipher::aes_128_cfb8();

        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(key))?;
        encrypter.pad(false);

        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(key))?;
        decrypter.pad(false);

        Ok(Self {
            stream,
            encrypter,
            decrypter,
        })
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for EncryptedStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pre_len = buf.filled().len();
        let poll = Pin::new(&mut self.stream).poll_read(cx, buf);

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

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for EncryptedStream<T> {
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

        Pin::new(&mut self.stream).poll_write(cx, &encrypted)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
