use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

#[cfg(target_os = "linux")]
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY, VMADDR_CID_HOST};

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

#[derive(Clone, Copy, Debug)]
pub struct ParentInterconnect {
    mode: InterconnectMode,
    parent_cid: u32,
}

impl ParentInterconnect {
    pub fn from_env() -> Self {
        Self {
            mode: InterconnectMode::from_env_var(
                "SUBLY402_ENCLAVE_INTERCONNECT_MODE",
                InterconnectMode::Tcp,
            ),
            parent_cid: std::env::var("SUBLY402_PARENT_CID")
                .ok()
                .map(|value| {
                    value
                        .parse()
                        .unwrap_or_else(|_| panic!("SUBLY402_PARENT_CID must be a valid u32"))
                })
                .unwrap_or_else(default_parent_cid),
        }
    }

    pub fn local_dev() -> Self {
        Self {
            mode: InterconnectMode::Tcp,
            parent_cid: default_parent_cid(),
        }
    }

    pub fn mode(self) -> InterconnectMode {
        self.mode
    }

    pub async fn connect(
        self,
        port: u32,
        tcp_addr: impl Into<String>,
    ) -> io::Result<InterconnectStream> {
        match self.mode {
            InterconnectMode::Tcp => connect_tcp(tcp_addr.into()).await,
            InterconnectMode::Vsock => connect_vsock(self.parent_cid, port).await,
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

pub async fn bind_ingress_listener(
    mode: InterconnectMode,
    tcp_listen_addr: &str,
    port: u32,
) -> io::Result<InterconnectListener> {
    match mode {
        InterconnectMode::Tcp => Ok(InterconnectListener::Tcp(
            TcpListener::bind(tcp_listen_addr).await?,
        )),
        InterconnectMode::Vsock => bind_vsock(port),
    }
}

pub async fn connect_tcp(addr: impl AsRef<str>) -> io::Result<InterconnectStream> {
    Ok(InterconnectStream::Tcp(
        TcpStream::connect(addr.as_ref()).await?,
    ))
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

#[cfg(target_os = "linux")]
fn default_parent_cid() -> u32 {
    VMADDR_CID_HOST
}

#[cfg(not(target_os = "linux"))]
fn default_parent_cid() -> u32 {
    3
}

#[cfg(not(target_os = "linux"))]
fn vsock_unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "vsock interconnect mode requires a Linux Nitro-capable host",
    )
}
