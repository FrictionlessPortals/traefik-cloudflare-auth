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
use jwt::verify_token;
use std::{env, net::SocketAddr, str::FromStr};

// JWT Verification
mod jwt;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Get required environment variables.
    let auth_domain = env::var("AUTH_DOMAIN")?;

    // Fetch the authentication domain keys for JWT verification.
    jwt::fetch_keys(&auth_domain).await?;

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
    let address = env::var("LISTEN_ADDRESS").unwrap_or_else(|_| "127.0.0.1".into());
    let port = env::var("LISTEN_PORT").unwrap_or_else(|_| "8080".into());
    let socket = SocketAddr::from_str(&format!("{}:{}", address, port))?;

    // Start the server on the created socket.
    tracing::info!("Listening on {}:{}", address, port);
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
        // JWT header does exist, extract the header value.
        let jwt_value = match jwt_value.to_str() {
            Ok(v) => v,
            Err(e) => return (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
        };

        // Validate the JWT token using the extracted header value.
        let verification = match verify_token(jwt_value, &auth_domain) {
            Ok(c) => c,
            Err(e) => return (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
        };

        // Extract the user email and pass to Traefik to complete authentication.
        (StatusCode::OK, [("X-Auth-User", verification.email)], "OK").into_response()
    } else {
        // JWT header doesn't exist, try using Cookie header.
        let cookie_header = headers.get("Cookie");
        if let Some(_cookie_value) = cookie_header {
            (StatusCode::OK, "OK").into_response()
        } else {
            // Couldn't extract data for verification, return a `401`.
            (StatusCode::UNAUTHORIZED).into_response()
        }
    }
}

/// Error handler for the application.
async fn error_handler() -> impl IntoResponse {
    // Return with a 404 and "Not Found".
    (StatusCode::NOT_FOUND, "Not Found")
}
