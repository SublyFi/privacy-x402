use axum::body::Body;
use axum::http::{HeaderName, HeaderValue};
use axum::Router;
use base64::Engine;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperServerBuilder;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::env;
use std::fs::File;
use std::io::{self, BufReader};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{info, warn};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::interconnect::{InterconnectListener, InterconnectStream};

pub const INTERNAL_MTLS_FINGERPRINT_HEADER: &str = "x-a402-internal-mtls-fingerprint";

#[derive(Clone, Debug)]
pub struct TlsBindingInfo {
    pub public_key_spki_der: Vec<u8>,
    pub public_key_spki_pem: String,
    pub public_key_sha256: String,
}

#[derive(Clone)]
pub struct TlsRuntime {
    acceptor: TlsAcceptor,
    mtls_enabled: bool,
    binding: Option<TlsBindingInfo>,
}

impl TlsRuntime {
    pub fn from_env() -> Result<Option<Self>, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert_path = env::var("A402_ENCLAVE_TLS_CERT_PATH").ok();
        let key_path = env::var("A402_ENCLAVE_TLS_KEY_PATH").ok();
        let client_ca_path = env::var("A402_ENCLAVE_TLS_CLIENT_CA_PATH").ok();

        if cert_path.is_none() && key_path.is_none() && client_ca_path.is_none() {
            return Ok(None);
        }

        let cert_path = cert_path.ok_or_else(|| {
            "A402_ENCLAVE_TLS_CERT_PATH must be set when TLS is enabled".to_string()
        })?;
        let key_path = key_path.ok_or_else(|| {
            "A402_ENCLAVE_TLS_KEY_PATH must be set when TLS is enabled".to_string()
        })?;

        let certs = load_certs(&cert_path)?;
        let key = load_private_key(&key_path)?;
        let binding = certs.first().map(extract_tls_binding).transpose()?;

        let mut server_config = if let Some(client_ca_path) = client_ca_path {
            let roots = load_root_store(&client_ca_path)?;
            let verifier = WebPkiClientVerifier::builder(roots.into())
                .allow_unauthenticated()
                .build()
                .map_err(|error| format!("invalid client CA bundle {client_ca_path}: {error}"))?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|error| format!("invalid TLS certificate/key pair: {error}"))?
        } else {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|error| format!("invalid TLS certificate/key pair: {error}"))?
        };

        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Some(Self {
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            mtls_enabled: env::var("A402_ENCLAVE_TLS_CLIENT_CA_PATH").is_ok(),
            binding,
        }))
    }

    pub fn mtls_enabled(&self) -> bool {
        self.mtls_enabled
    }

    pub fn binding(&self) -> Option<&TlsBindingInfo> {
        self.binding.as_ref()
    }
}

pub async fn serve(
    listener: InterconnectListener,
    app: Router,
    runtime: Option<TlsRuntime>,
) -> io::Result<()> {
    info!(
        tls_enabled = runtime.is_some(),
        mtls_enabled = runtime
            .as_ref()
            .map(|runtime| runtime.mtls_enabled)
            .unwrap_or(false),
        "Enclave ingress listener enabled"
    );

    loop {
        let (stream, remote_label) = listener.accept().await?;
        let app = app.clone();
        let runtime = runtime.clone();

        tokio::spawn(async move {
            let result = match runtime {
                Some(runtime) => serve_tls_connection(stream, app, runtime).await,
                None => serve_plain_connection(stream, app).await,
            };
            if let Err(error) = result {
                warn!(remote = %remote_label, "failed to serve connection: {error}");
            }
        });
    }
}

async fn serve_tls_connection<S>(stream: S, app: Router, runtime: TlsRuntime) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tls_stream = runtime.acceptor.accept(stream).await?;
    let peer_fingerprint = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(certificate_fingerprint_hex);
    serve_http_connection(tls_stream, app, peer_fingerprint).await
}

async fn serve_plain_connection(stream: InterconnectStream, app: Router) -> io::Result<()> {
    serve_http_connection(stream, app, None).await
}

async fn serve_http_connection<S>(
    stream: S,
    app: Router,
    peer_fingerprint: Option<String>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request: hyper::Request<Incoming>| {
        let app = app.clone();
        let peer_fingerprint = peer_fingerprint.clone();

        async move {
            let mut request = request.map(Body::new);
            request
                .headers_mut()
                .remove(HeaderName::from_static(INTERNAL_MTLS_FINGERPRINT_HEADER));
            if let Some(fingerprint) = peer_fingerprint.as_ref() {
                request.headers_mut().insert(
                    HeaderName::from_static(INTERNAL_MTLS_FINGERPRINT_HEADER),
                    HeaderValue::from_str(fingerprint).expect("fingerprint header must be valid"),
                );
            }

            Ok::<_, Infallible>(app.oneshot(request).await.expect("router is infallible"))
        }
    });

    HyperServerBuilder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
        .map_err(io::Error::other)
}

fn certificate_fingerprint_hex(certificate: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(certificate.as_ref()))
}

fn extract_tls_binding(certificate: &CertificateDer<'_>) -> Result<TlsBindingInfo, String> {
    let (_, parsed) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|error| format!("failed to parse TLS certificate DER: {error}"))?;
    let spki_der = parsed.tbs_certificate.subject_pki.raw.to_vec();
    let public_key_sha256 = hex::encode(Sha256::digest(&spki_der));
    Ok(TlsBindingInfo {
        public_key_spki_pem: spki_der_to_pem(&spki_der),
        public_key_spki_der: spki_der,
        public_key_sha256,
    })
}

fn spki_der_to_pem(spki_der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(spki_der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 output must be utf-8"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file =
        File::open(path).map_err(|error| format!("failed to open TLS cert {path}: {error}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to parse TLS cert bundle {path}: {error}"))
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let file =
        File::open(path).map_err(|error| format!("failed to open TLS key {path}: {error}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| format!("failed to parse TLS key {path}: {error}"))?
        .ok_or_else(|| format!("TLS key {path} did not contain a private key"))
}

fn load_root_store(path: &str) -> Result<RootCertStore, String> {
    let certs = load_certs(path)?;
    let mut store = RootCertStore::empty();
    let (added, _ignored) = store.add_parsable_certificates(certs);
    if added == 0 {
        return Err(format!(
            "TLS client CA bundle {path} did not contain a parsable certificate"
        ));
    }
    Ok(store)
}
