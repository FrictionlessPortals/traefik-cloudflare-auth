//! ``traefik-cloudflare-auth``
//!
//! Auth server to verify Cloudflare Access JWT tokens for Traefik.

use anyhow::Result;
use axum::{http::StatusCode, response::IntoResponse, routing::get, Router, Server};
use std::{env, net::SocketAddr, str::FromStr};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Build our application with a route
    let app = Router::new()
        // `GET /` goes to `index.
        .route("/", get(index))
        // `GET /auth` goes to `auth_handler`
        .route("/auth", get(auth_handler));

    // Bind to given address environment variables.
    let address = env::var("LISTEN_ADDRESS").unwrap_or("127.0.0.1".into());
    let port = env::var("LISTEN_PORT").unwrap_or("8080".into());
    let socket = SocketAddr::from_str(&format!("{}:{}", address, port))?;

    // Start the server on the created socket.
    tracing::debug!("Listening on {}:{}", address, port);
    Server::bind(&socket).serve(app.into_make_service()).await?;

    Ok(())
}

/// Index handler used to produce help information.
async fn index() -> impl IntoResponse {
    // Return with a 200 and "Use /auth for authentication".
    (StatusCode::OK, "Use /auth for authentication")
}

/// Authentication handler used by Traefik
async fn auth_handler() -> impl IntoResponse {
    // Return with a 200 and "OK!"
    (StatusCode::OK, "OK!")
}
