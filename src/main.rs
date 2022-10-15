//! ``traefik-cloudflare-auth``
//!
//! Auth server to verify Cloudflare Access JWT tokens for Traefik.

use anyhow::Result;
use axum::{
    handler::Handler,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Extension, Router, Server,
};
use std::{env, net::SocketAddr, str::FromStr};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Get required environment variables.
    let auth_domain = env::var("AUTH_DOMAIN")?;

    // Build our application with a route
    let app = Router::new()
        // `GET /` goes to `index.
        .route("/", get(index))
        // `GET /auth` goes to `auth_handler`
        .route("/auth", get(auth_handler))
        .layer(Extension(auth_domain))
        // Fallback error handler
        .fallback(error_handler.into_service());

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

/// Authentication handler used by Traefik.
async fn auth_handler(
    headers: HeaderMap,
    Extension(auth_domain): Extension<String>,
) -> impl IntoResponse {
    // Attempt to extract from the given JWT header.
    let jwt_header = headers.get("Cf-Access-Jwt-Assertion");

    // Check if it exists, if not try the Cookie header.
    if let Some(jwt_value) = jwt_header {
        // JWT header does exist, validate using extracted value.
        return StatusCode::OK;
    } else {
        // JWT header doesn't exist, try using Cookie header.
        let cookie_header = headers.get("Cookie");
        if let Some(cookie_value) = cookie_header {
            return StatusCode::OK;
        } else {
            // Couldn't extract data for verification, return a `401`.
            return StatusCode::UNAUTHORIZED;
        }
    }
}

/// Error handler for the application.
async fn error_handler() -> impl IntoResponse {
    // Return with a 404 and "Not Found".
    (StatusCode::NOT_FOUND, "Not Found")
}
