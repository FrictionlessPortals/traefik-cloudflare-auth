//! ``traefik-cloudflare-auth``
//!
//! JWT Module to decode and verify incoming JWT tokens.

use anyhow::{anyhow, Result};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
    DecodingKey, Validation,
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

/// JWT Keyset from given authentication domain.
pub static JWT_KEY_SET: OnceCell<JwkSet> = OnceCell::new();

/// Our claims structure for the JWT token.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    // The audience tag for the application to which the token is issued.
    aud: Vec<String>,
    // The email address of the authenticated user.
    pub email: String,
    // The expiration timestamp for the token.
    exp: usize,
    // The issuance timestamp for the token.
    iat: usize,
    // The not-before timestamp for the token, used to checks if the token was received before it should be used.
    nbf: usize,
    // The Cloudflare Access domain URL for the application.
    iss: String,
    // The type of Access token (app for application token or org for global session token).
    r#type: String,
    // A nonce used to get the user’s identity.
    identity_nonce: String,
    // The ID of the user.
    pub sub: String,
    // The country where the user authenticated from.
    country: String,
}

/// Fetch JWT decoding keys from the authentication domain.
pub async fn fetch_keys(auth_domain: &str) -> Result<()> {
    // Form the URL for fetching keys.
    let keys_url = format!("{}/cdn-cgi/access/certs", auth_domain);

    // Fetch and parse the keys as a JwtSet.
    let key_set: JwkSet = reqwest::get(keys_url).await?.json().await?;

    // Set the global key set with updated key set.
    match JWT_KEY_SET.set(key_set) {
        Ok(_) => Ok(()),
        Err(_) => Err(anyhow!("failed to set global keyset")),
    }
}

/// Verify the given JWT token and return the verified `Claims`.
pub fn verify_token(token: &str, auth_domain: &str) -> Result<Claims> {
    // Get the global key set for verification.
    let key_set = match JWT_KEY_SET.get() {
        Some(x) => x,
        None => return Err(anyhow!("failed to get global keyset")),
    };

    // Decode the JWT header to get `kid` value.
    let header = decode_header(token)?;
    let kid = match header.kid {
        Some(k) => k,
        None => return Err(anyhow!("token missing kid in header")),
    };

    // Find the `kid` value in the key set.
    if let Some(key) = key_set.find(&kid) {
        // Match the given algorithm and make sure its RSA based.
        match key.algorithm {
            AlgorithmParameters::RSA(ref rsa) => {
                // Get the decoding key from the RSA components.
                let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?;

                // Create a new validation object from the algorithm type.
                // TODO: Enforce validation on the audience field.
                let mut validation = Validation::new(key.common.algorithm.unwrap());
                validation.set_issuer(&[auth_domain]);

                // Decode the given JWT token and return if successful.
                match decode::<Claims>(token, &decoding_key, &validation) {
                    Ok(claim) => Ok(claim.claims),
                    Err(e) => Err(e.into()),
                }
            }
            _ => Err(anyhow!("incorrect given algorithm")),
        }
    } else {
        // Return appropriate error message for missing key.
        Err(anyhow!("failed to find key with given kid"))
    }
}
