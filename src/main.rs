mod webauthn;

use askama::Template;
use axum::{
  handler::HandlerWithoutStateExt,
  http::{uri::Scheme, StatusCode, Uri},
  response::{Html, IntoResponse, Redirect},
  routing::get,
  Router,
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;
use webauthn_rs::prelude::*;

fn expand_tilde(p: &Path) -> PathBuf {
  let s = p.to_string_lossy();
  if s.starts_with("~/") {
    if let Some(home) = std::env::var_os("HOME") {
      return PathBuf::from(home).join(s.strip_prefix("~/").unwrap());
    }
  } else if s == "~" {
    if let Some(home) = std::env::var_os("HOME") {
      return PathBuf::from(home);
    }
  }
  p.to_path_buf()
}

fn resolve_fqdn_cert_key(args: &Args) -> Result<(String, PathBuf, PathBuf), Box<dyn std::error::Error + Send + Sync>> {
  if let Some(ref dir) = args.letsencrypt {
    let dir = expand_tilde(dir);
    let fqdn = dir
      .file_name()
      .and_then(|n| n.to_str())
      .ok_or_else(|| {
        std::io::Error::new(
          std::io::ErrorKind::InvalidInput,
          format!("--letsencrypt path has no usable directory name: {}", dir.display()),
        )
      })?
      .to_string();
    let cert = dir.join("fullchain.pem");
    let key = dir.join("privkey.pem");
    if !cert.is_file() {
      return Err(
        std::io::Error::new(
          std::io::ErrorKind::NotFound,
          format!("missing {} (expected in --letsencrypt dir)", cert.display()),
        )
        .into(),
      );
    }
    if !key.is_file() {
      return Err(
        std::io::Error::new(
          std::io::ErrorKind::NotFound,
          format!("missing {} (expected in --letsencrypt dir)", key.display()),
        )
        .into(),
      );
    }
    return Ok((fqdn, cert, key));
  }
  let fqdn = args.fqdn.clone().ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "either --letsencrypt or all of --fqdn, --cert, --key are required",
    )
  })?;
  let cert = args.cert.clone().ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "either --letsencrypt or all of --fqdn, --cert, --key are required",
    )
  })?;
  let key = args.key.clone().ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "either --letsencrypt or all of --fqdn, --cert, --key are required",
    )
  })?;
  Ok((fqdn, cert, key))
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
  title: String,
  message: String,
}

#[derive(Parser, Debug)]
#[command(name = "local_ssl_rust", about = "HTTP/HTTPS server with redirect")]
struct Args {
  /// FQDN for redirect and page (e.g. example.local)
  #[arg(long, required_unless_present = "letsencrypt")]
  fqdn: Option<String>,

  /// HTTP port (redirect to HTTPS)
  #[arg(long, default_value = "80")]
  port_http: u16,

  /// HTTPS port
  #[arg(long, default_value = "443")]
  port_htts: u16,

  /// Path to TLS certificate (PEM)
  #[arg(long, required_unless_present = "letsencrypt")]
  cert: Option<PathBuf>,

  /// Path to TLS private key (PEM)
  #[arg(long, required_unless_present = "letsencrypt")]
  key: Option<PathBuf>,

  /// Use Let's Encrypt-style dir: FQDN = last path component, dir must contain fullchain.pem and privkey.pem
  #[arg(long)]
  letsencrypt: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
  tracing_subscriber::registry()
    .with(
      tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| format!("{}=info", env!("CARGO_CRATE_NAME")).into()),
    )
    .with(tracing_subscriber::fmt::layer())
    .init();

  let args = Args::parse();

  let (fqdn, cert, key) = resolve_fqdn_cert_key(&args)?;
  let cert = cert.clone();
  let key = key.clone();

  let tls_config = RustlsConfig::from_pem_file(cert, key).await.map_err(|e| format!("TLS config: {}", e))?;

  let fqdn = fqdn.clone();
  let port_https = args.port_htts;

  let origin_str = if port_https == 443 {
    format!("https://{}", fqdn)
  } else {
    format!("https://{}:{}", fqdn, port_https)
  };
  let origin = Url::parse(&origin_str).map_err(|e| format!("origin URL: {}", e))?;
  let webauthn = WebauthnBuilder::new(&fqdn, &origin)
    .map_err(|e| format!("webauthn builder: {}", e))?
    .build()
    .map_err(|e| format!("webauthn build: {}", e))?;
  let state = Arc::new(webauthn::AppState {
    webauthn,
    credentials: Arc::new(tokio::sync::RwLock::new(webauthn::load_credentials())),
    pending_reg: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
    pending_auth: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
  });

  // Bind HTTP on both IPv4 and IPv6 so "localhost" works (macOS often resolves to ::1)
  let http_addr_v4 = SocketAddr::from(([0, 0, 0, 0], args.port_http));
  let http_listener_v4 = tokio::net::TcpListener::bind(http_addr_v4).await.map_err(|e| {
    format!(
      "bind HTTP on {}: {} (is something else using the port? try: sudo lsof -i :{})",
      http_addr_v4, e, args.port_http
    )
  })?;
  tracing::info!("HTTP  (redirect) listening on {}", http_listener_v4.local_addr().unwrap());

  let fqdn_v4 = fqdn.clone();
  tokio::spawn(async move {
    redirect_http_to_https_with_listener(http_listener_v4, fqdn_v4, port_https).await;
  });

  let http_addr_v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], args.port_http));
  match tokio::net::TcpListener::bind(http_addr_v6).await {
    Ok(http_listener_v6) => {
      tracing::info!("HTTP  (redirect) listening on {}", http_listener_v6.local_addr().unwrap());
      let fqdn_v6 = fqdn.clone();
      tokio::spawn(async move {
        redirect_http_to_https_with_listener(http_listener_v6, fqdn_v6, port_https).await;
      });
    }
    Err(e) => {
      if cfg!(target_os = "macos") {
        return Err(format!("bind HTTP on {} (IPv6): {}", http_addr_v6, e).into());
      } else {
        tracing::warn!("failed to bind HTTP on {} (IPv6): {}, continuing without it", http_addr_v6, e);
      }
    }
  }

  let app = Router::new()
    .route("/", get(index_handler))
    .merge(webauthn::router(state));

  // HTTPS listeners: bind IPv4 and IPv6
  let addr_v4 = SocketAddr::from(([0, 0, 0, 0], port_https));
  let addr_v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port_https));
  tracing::info!("HTTPS listening on {}", addr_v4);

  let tls_config_v6 = tls_config.clone();
  let app_v6 = app.clone();
  tokio::spawn(async move {
    match axum_server::bind_rustls(addr_v6, tls_config_v6)
      .serve(app_v6.into_make_service())
      .await
    {
      Ok(()) => {}
      Err(e) => {
        if cfg!(target_os = "macos") {
          panic!("HTTPS IPv6 on {}: {}", addr_v6, e);
        } else {
          tracing::warn!("failed to bind HTTPS on {} (IPv6): {}, continuing without it", addr_v6, e);
        }
      }
    }
  });

  axum_server::bind_rustls(addr_v4, tls_config).serve(app.into_make_service()).await.map_err(|e| e.into())
}

async fn redirect_http_to_https_with_listener(listener: tokio::net::TcpListener, fqdn: String, https_port: u16) {
  let redirect = move |uri: Uri| {
    let fqdn = fqdn.clone();
    async move {
      match make_https_uri(uri, &fqdn, https_port) {
        Ok(u) => Ok(Redirect::permanent(u.to_string().as_str())),
        Err(_) => {
          tracing::warn!("failed to build HTTPS URI");
          Err(StatusCode::BAD_REQUEST)
        }
      }
    }
  };

  axum::serve(listener, redirect.into_make_service()).await.expect("HTTP server");
}

fn make_https_uri(uri: Uri, authority_host: &str, https_port: u16) -> Result<Uri, StatusCode> {
  let authority =
    if https_port == 443 { authority_host.to_string() } else { format!("{}:{}", authority_host, https_port) };
  let mut parts = uri.into_parts();
  parts.scheme = Some(Scheme::HTTPS);
  parts.authority = Some(authority.parse().map_err(|_| StatusCode::BAD_REQUEST)?);
  if parts.path_and_query.is_none() {
    parts.path_and_query = Some("/".parse().unwrap());
  }
  Uri::from_parts(parts).map_err(|_| StatusCode::BAD_REQUEST)
}

async fn index_handler() -> impl IntoResponse {
  let t =
    IndexTemplate { title: "You're secure".to_string(), message: "This connection is encrypted with TLS.".to_string() };
  match t.render() {
    Ok(html) => Html(html).into_response(),
    Err(e) => {
      tracing::error!(%e, "template render failed");
      (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
    }
  }
}
