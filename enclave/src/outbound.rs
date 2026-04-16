use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::http::{HeaderMap, HeaderValue, Method, StatusCode};
use hyper::Request;
use hyper_util::rt::TokioIo;
use reqwest::Url;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client::rpc_sender::{RpcSender, RpcTransportStats};
use solana_rpc_client_api::client_error::Result as ClientResult;
use solana_rpc_client_api::custom_error;
use solana_rpc_client_api::error_object::RpcErrorObject;
use solana_rpc_client_api::request::{RpcError, RpcRequest, RpcResponseErrorData};
use solana_rpc_client_api::response::RpcSimulateTransactionResult;
use solana_sdk::commitment_config::CommitmentConfig;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_rustls::TlsConnector;

use crate::interconnect::{connect_tcp, InterconnectMode, InterconnectStream, ParentInterconnect};

#[derive(Clone, Copy, Debug)]
pub struct OutboundTransport {
    parent_interconnect: ParentInterconnect,
    egress_port: u32,
}

pub struct OutboundResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

impl OutboundTransport {
    pub fn from_env(parent_interconnect: ParentInterconnect) -> Self {
        Self {
            parent_interconnect,
            egress_port: read_env_u32("A402_ENCLAVE_EGRESS_PORT", 5001),
        }
    }

    pub fn direct() -> Self {
        Self {
            parent_interconnect: ParentInterconnect::local_dev(),
            egress_port: 5001,
        }
    }

    pub fn solana_rpc_client(
        self,
        url: impl Into<String>,
        commitment: CommitmentConfig,
    ) -> RpcClient {
        RpcClient::new_sender(
            RelayedRpcSender::new(self, url.into()),
            solana_rpc_client::rpc_client::RpcClientConfig::with_commitment(commitment),
        )
    }

    pub async fn get_json<T>(&self, url: &str) -> Result<(StatusCode, T), String>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self
            .send(Method::GET, url, HeaderMap::new(), Vec::new())
            .await?;
        let body = serde_json::from_slice(&response.body)
            .map_err(|error| format!("failed to decode JSON response from {url}: {error}"))?;
        Ok((response.status, body))
    }

    pub async fn post_json<T>(&self, url: &str, payload: &T) -> Result<OutboundResponse, String>
    where
        T: serde::Serialize,
    {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = serde_json::to_vec(payload)
            .map_err(|error| format!("failed to serialize JSON request for {url}: {error}"))?;
        self.send(Method::POST, url, headers, body).await
    }

    pub async fn send(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<OutboundResponse, String> {
        let url =
            Url::parse(url).map_err(|error| format!("invalid outbound URL {url}: {error}"))?;
        let host = url
            .host_str()
            .ok_or_else(|| format!("outbound URL {url} is missing a host"))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| format!("outbound URL {url} is missing a port"))?;
        let stream = self
            .connect_target(&host, port)
            .await
            .map_err(|error| format!("failed to connect to {host}:{port}: {error}"))?;
        let path = request_path(&url);
        let host_header = host_header_value(&url)?;

        match url.scheme() {
            "http" => {
                let request = build_request(method, &path, host_header, headers, body)?;
                self.send_on_stream(stream, request).await
            }
            "https" => {
                let tls_stream = tls_connector()
                    .connect(server_name(&host)?, stream)
                    .await
                    .map_err(|error| format!("TLS handshake failed for {host}:{port}: {error}"))?;
                let request = build_request(method, &path, host_header, headers, body)?;
                self.send_on_stream(tls_stream, request).await
            }
            other => Err(format!("unsupported outbound URL scheme {other}")),
        }
    }

    async fn connect_target(&self, host: &str, port: u16) -> io::Result<InterconnectStream> {
        match self.parent_interconnect.mode() {
            InterconnectMode::Tcp => connect_tcp(format!("{host}:{port}")).await,
            InterconnectMode::Vsock => self.connect_via_parent_relay(host, port).await,
        }
    }

    async fn connect_via_parent_relay(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<InterconnectStream> {
        let relay_addr = format!("127.0.0.1:{}", self.egress_port);
        let mut stream = self
            .parent_interconnect
            .connect(self.egress_port, relay_addr)
            .await?;
        let target = format!("{host}:{port}\n");
        stream.write_all(target.as_bytes()).await?;

        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        let read = reader.read_line(&mut status).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "egress relay closed before acknowledging target",
            ));
        }
        let status = status.trim();
        if status != "OK" {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("egress relay returned {status}"),
            ));
        }
        Ok(reader.into_inner())
    }

    async fn send_on_stream<S>(
        &self,
        stream: S,
        request: Request<Full<Bytes>>,
    ) -> Result<OutboundResponse, String>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| format!("failed to start HTTP connection: {error}"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let response = sender
            .send_request(request)
            .await
            .map_err(|error| format!("HTTP request failed: {error}"))?;
        response_to_bytes(response).await
    }
}

pub struct RelayedRpcSender {
    transport: OutboundTransport,
    url: String,
    request_id: AtomicU64,
    stats: RwLock<RpcTransportStats>,
}

impl RelayedRpcSender {
    pub fn new(transport: OutboundTransport, url: String) -> Self {
        Self {
            transport,
            url,
            request_id: AtomicU64::new(0),
            stats: RwLock::new(RpcTransportStats::default()),
        }
    }
}

#[async_trait]
impl RpcSender for RelayedRpcSender {
    async fn send(
        &self,
        request: RpcRequest,
        params: serde_json::Value,
    ) -> ClientResult<serde_json::Value> {
        let request_start = Instant::now();
        let request_id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let payload = request.build_request_json(request_id, params);

        let response = self
            .transport
            .post_json(&self.url, &payload)
            .await
            .map_err(|error| RpcError::RpcRequestError(error.to_string()))?;

        {
            let mut stats = self.stats.write().unwrap();
            stats.request_count += 1;
            stats.elapsed_time += request_start.elapsed();
        }

        if !response.status.is_success() {
            return Err(RpcError::RpcRequestError(format!(
                "RPC request failed with HTTP status {}",
                response.status
            ))
            .into());
        }

        let mut json =
            serde_json::from_slice::<serde_json::Value>(&response.body).map_err(|error| {
                RpcError::RpcRequestError(format!("failed to decode RPC response JSON: {error}"))
            })?;

        if json["error"].is_object() {
            return match serde_json::from_value::<RpcErrorObject>(json["error"].clone()) {
                Ok(rpc_error_object) => {
                    let data = match rpc_error_object.code {
                        custom_error::JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE => {
                            match serde_json::from_value::<RpcSimulateTransactionResult>(
                                json["error"]["data"].clone(),
                            ) {
                                Ok(data) => {
                                    RpcResponseErrorData::SendTransactionPreflightFailure(data)
                                }
                                Err(_) => RpcResponseErrorData::Empty,
                            }
                        }
                        custom_error::JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY => {
                            match serde_json::from_value::<custom_error::NodeUnhealthyErrorData>(
                                json["error"]["data"].clone(),
                            ) {
                                Ok(custom_error::NodeUnhealthyErrorData { num_slots_behind }) => {
                                    RpcResponseErrorData::NodeUnhealthy { num_slots_behind }
                                }
                                Err(_) => RpcResponseErrorData::Empty,
                            }
                        }
                        _ => RpcResponseErrorData::Empty,
                    };

                    Err(RpcError::RpcResponseError {
                        code: rpc_error_object.code,
                        message: rpc_error_object.message,
                        data,
                    }
                    .into())
                }
                Err(error) => Err(RpcError::RpcRequestError(format!(
                    "failed to decode RPC error response: {} [{error}]",
                    serde_json::to_string(&json["error"])
                        .unwrap_or_else(|_| "<invalid>".to_string())
                ))
                .into()),
            };
        }

        Ok(json["result"].take())
    }

    fn get_transport_stats(&self) -> RpcTransportStats {
        self.stats.read().unwrap().clone()
    }

    fn url(&self) -> String {
        self.url.clone()
    }
}

fn build_request(
    method: Method,
    path: &str,
    host_header: HeaderValue,
    headers: HeaderMap,
    body: Vec<u8>,
) -> Result<Request<Full<Bytes>>, String> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .body(Full::new(Bytes::from(body)))
        .map_err(|error| format!("failed to build outbound HTTP request: {error}"))?;
    request.headers_mut().insert(HOST, host_header);
    request.headers_mut().extend(headers);
    Ok(request)
}

async fn response_to_bytes(
    response: hyper::Response<Incoming>,
) -> Result<OutboundResponse, String> {
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|error| format!("failed to read outbound HTTP response body: {error}"))?
        .to_bytes();
    Ok(OutboundResponse {
        status,
        body: body.to_vec(),
    })
}

fn request_path(url: &Url) -> String {
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

fn host_header_value(url: &Url) -> Result<HeaderValue, String> {
    let host = url
        .host_str()
        .ok_or_else(|| format!("outbound URL {url} is missing a host"))?;
    let value = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    HeaderValue::from_str(&value).map_err(|error| format!("invalid host header {value}: {error}"))
}

fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string()).map_err(|_| format!("invalid TLS server name {host}"))
}

fn tls_connector() -> TlsConnector {
    static TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    let config = TLS_CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    });
    TlsConnector::from(config.clone())
}

fn read_env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be a valid u32"))
        })
        .unwrap_or(default)
}
