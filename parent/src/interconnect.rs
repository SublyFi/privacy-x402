use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

#[cfg(target_os = "linux")]
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterconnectMode {
    Tcp,
    Vsock,
}

impl InterconnectMode {
    pub fn from_env_var(name: &str, default: Self) -> Self {
        match std::env::var(name) {
            Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
                "tcp" => Self::Tcp,
                "vsock" => Self::Vsock,
                other => panic!("{name} must be 'tcp' or 'vsock', got {other}"),
            },
            Err(_) => default,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Vsock => "vsock",
        }
    }
}

pub enum InterconnectListener {
    Tcp(TcpListener),
    #[cfg(target_os = "linux")]
    Vsock(VsockListener),
}

impl InterconnectListener {
    pub async fn accept(&self) -> io::Result<(InterconnectStream, String)> {
        match self {
            Self::Tcp(listener) => {
                let (stream, addr) = listener.accept().await?;
                Ok((InterconnectStream::Tcp(stream), addr.to_string()))
            }
            #[cfg(target_os = "linux")]
            Self::Vsock(listener) => {
                let (stream, addr) = listener.accept().await?;
                Ok((
                    InterconnectStream::Vsock(stream),
                    format!("vsock:{}:{}", addr.cid(), addr.port()),
                ))
            }
        }
    }
}

pub enum InterconnectStream {
    Tcp(TcpStream),
    #[cfg(target_os = "linux")]
    Vsock(VsockStream),
}

impl AsyncRead for InterconnectStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for InterconnectStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub async fn connect_to_enclave(
    mode: InterconnectMode,
    enclave_cid: u32,
    enclave_port: u32,
) -> io::Result<InterconnectStream> {
    match mode {
        InterconnectMode::Tcp => {
            let addr = format!("127.0.0.1:{enclave_port}");
            Ok(InterconnectStream::Tcp(TcpStream::connect(addr).await?))
        }
        InterconnectMode::Vsock => connect_vsock(enclave_cid, enclave_port).await,
    }
}

pub async fn bind_parent_service(
    mode: InterconnectMode,
    port: u32,
) -> io::Result<InterconnectListener> {
    match mode {
        InterconnectMode::Tcp => {
            let addr = format!("127.0.0.1:{port}");
            Ok(InterconnectListener::Tcp(TcpListener::bind(addr).await?))
        }
        InterconnectMode::Vsock => bind_vsock(port),
    }
}

#[cfg(target_os = "linux")]
async fn connect_vsock(cid: u32, port: u32) -> io::Result<InterconnectStream> {
    let addr = VsockAddr::new(cid, port);
    Ok(InterconnectStream::Vsock(VsockStream::connect(addr).await?))
}

#[cfg(not(target_os = "linux"))]
async fn connect_vsock(_cid: u32, _port: u32) -> io::Result<InterconnectStream> {
    Err(vsock_unsupported())
}

#[cfg(target_os = "linux")]
fn bind_vsock(port: u32) -> io::Result<InterconnectListener> {
    let addr = VsockAddr::new(VMADDR_CID_ANY, port);
    Ok(InterconnectListener::Vsock(VsockListener::bind(addr)?))
}

#[cfg(not(target_os = "linux"))]
fn bind_vsock(_port: u32) -> io::Result<InterconnectListener> {
    Err(vsock_unsupported())
}

#[cfg(not(target_os = "linux"))]
fn vsock_unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "vsock interconnect mode requires a Linux Nitro-capable host",
    )
}
