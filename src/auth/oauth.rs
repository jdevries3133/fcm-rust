//! [Google's guide for getting an access token as a service-account not using
//! an official client
//! library.](https://developers.google.com/identity/protocols/oauth2/service-account#httprest_1).

// TODO: disallow this again when finished
#![allow(unused)]

use base64::{
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Duration, Utc};
pub use firebase_credentials::AdminSdkCredentials;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::auth::oauth::jwt::{JWTClaims, JWTHeader, JWTPendingSignature, Jwt};

#[derive(Debug)]
pub struct OauthError {
    msg: String,
    variant: OauthErrorVariant,
}

#[derive(Debug)]
enum OauthErrorVariant {
    Crypto,
    Serde,
    Http,
    Authorization,
}

type OauthResult<Ok> = Result<Ok, OauthError>;

pub struct AccessToken {
    pub token: String,
    pub expiry_time: DateTime<Utc>,
}

#[derive(Serialize)]
struct Payload<'a> {
    grant_type: &'a str,
    assertion: &'a str,
}

#[derive(Deserialize)]
struct Response {
    access_token: String,
    expires_in: i64,
    token_type: String,
}

pub async fn authenticate(client: &Client, credentials: &AdminSdkCredentials) -> OauthResult<AccessToken> {
    let jwt_unsigned = JWTPendingSignature::new(&JWTHeader::new(&credentials), &JWTClaims::new(&credentials)).unwrap();
    let sig = credentials.sign(&jwt_unsigned).unwrap();
    let jwt = Jwt {
        sig,
        pending: jwt_unsigned,
    };
    let payload = Payload {
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: &jwt.serialize(),
    };
    let body_raw = serde_urlencoded::to_string(&payload).map_err(|e| OauthError {
        msg: format!("while serializing authorization request payload: {e}"),
        variant: OauthErrorVariant::Serde,
    })?;
    let req = client
        .post("https://oauth2.googleapis.com/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body_raw);
    let response = req.send().await.map_err(|e| OauthError {
        msg: format!("error response from authorization server: {e}"),
        variant: OauthErrorVariant::Http,
    })?;
    let response: Response = response.json().await.map_err(|e| OauthError {
        msg: format!("while deserializing JSON response from authorization server: {e}"),
        variant: OauthErrorVariant::Serde,
    })?;

    match response.token_type.as_ref() {
        "Bearer" => Ok(AccessToken {
            token: response.access_token,
            expiry_time: Utc::now() + Duration::seconds(response.expires_in),
        }),
        token_type => Err(OauthError {
            msg: format!("unexpected token type: {token_type}"),
            variant: OauthErrorVariant::Authorization,
        }),
    }
}

fn jsonb64<T: Serialize>(val: T, err_msg: &'static str) -> OauthResult<String> {
    let json = serde_json::to_string(&val).map_err(|e| OauthError {
        msg: format!("{err_msg}: {e}"),
        variant: OauthErrorVariant::Serde,
    })?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(&json))
}

mod firebase_credentials {

    use aws_lc_rs::{
        digest::{Digest, SHA256},
        hmac::HMAC_SHA256,
        rand::SystemRandom,
        signature::{KeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RSA_PSS_SHA256},
    };
    use base64::{
        engine::DecodePaddingMode,
        prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
        Engine,
    };
    use serde::Deserialize;

    use crate::auth::oauth::{jwt::JWTPendingSignature, OauthError, OauthErrorVariant, OauthResult};

    /// The entire contents included in the JSON file downloaded from the Firebase
    /// console (`project/{project-name}/settings/serviceaccounts/adminsdk`).
    ///
    /// Load the JSON string and deserialize it into this struct using
    /// [serde_json].
    #[derive(Debug, Deserialize)]
    pub struct AdminSdkCredentials {
        r#type: NonSecret,
        project_id: NonSecret,
        pub private_key_id: NonSecret,
        private_key: Secret,
        pub client_email: NonSecret,
        client_id: NonSecret,
        auth_uri: NonSecret,
        token_uri: NonSecret,
        auth_provider_x509_cert_url: NonSecret,
        client_x509_cert_url: NonSecret,
        universe_domain: NonSecret,
    }
    impl AdminSdkCredentials {
        /// Hint: [super::jwt::JWT] can be used to combine
        /// [JWTPendingSignature] + [Signature], and then serialize the combined
        /// result into a JWT.
        pub fn sign(&self, jwt: &JWTPendingSignature) -> OauthResult<Signature> {
            let privkey = &self.privkey_bytes()?;
            let key_pair = aws_lc_rs::signature::RsaKeyPair::from_pkcs8(privkey).map_err(|e| OauthError {
                msg: format!("Could not construct RsaKeyPair: {e}"),
                variant: OauthErrorVariant::Crypto,
            })?;

            // buf is a C-style "output argument." aws_lc_rs docs instruct us
            // to ensure its length matches the key pair's public modulus
            // length.
            let mut buf = vec![0; key_pair.public_modulus_len()];

            // let mut hash = aws_lc_rs::digest::Context::new(&SHA256);
            // hash.update(jwt.0.as_bytes());
            // let digest = hash.finish();

            key_pair
                .sign(
                    &RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    jwt.0.as_bytes(),
                    buf.as_mut_slice(),
                )
                .map_err(|e| OauthError {
                    msg: format!("Could not sign JWT: {e}"),
                    variant: OauthErrorVariant::Crypto,
                })?;

            Ok(Signature(buf))
        }

        #[cfg(test)]
        pub fn dangerously_expose_private_key_material(&self) -> OauthResult<Vec<u8>> {
            self.privkey_bytes()
        }
        fn privkey_bytes(&self) -> OauthResult<Vec<u8>> {
            let mut b64 = String::new();
            for line in self.private_key.0.lines() {
                if line.contains("BEGIN PRIVATE KEY") {
                    continue;
                }
                if line.contains("END PRIVATE KEY") {
                    continue;
                }
                b64.push_str(line);
            }
            BASE64_STANDARD.decode(&b64).map_err(|e| OauthError {
                msg: format!("Could not decode base64 private key: {e}"),
                variant: OauthErrorVariant::Crypto,
            })
        }
    }

    pub struct Signature(Vec<u8>);
    impl Signature {
        pub fn to_base64(&self) -> String {
            BASE64_URL_SAFE_NO_PAD.encode(&self.0)
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(transparent)]
    struct Secret(String);

    #[derive(Debug, Deserialize)]
    #[serde(transparent)]
    pub struct NonSecret(pub String);

    /// This is a bit wonky; the test utils here are consumed in [super::test].
    /// [test::fake_creds] constructs [AdminSdkCredentials] including private
    /// fields, which wouldn't be possible in [super::test].
    #[cfg(test)]
    pub mod test {
        use super::*;
        use aws_lc_rs::{
            encoding::AsDer,
            rsa::{KeyPair, KeySize},
        };

        fn fake_non_secret() -> NonSecret {
            NonSecret("test".into())
        }
        fn fake_privkey() -> String {
            let kp = KeyPair::generate(KeySize::Rsa2048).unwrap();
            let der = kp.as_der().unwrap();
            let b64 = BASE64_STANDARD.encode(&der.as_ref());
            let mut pem = String::new();
            pem.push_str("-----BEGIN PRIVATE KEY-----\n");
            for (idx, char) in b64.chars().enumerate() {
                if idx != 0 && idx % 64 == 0 {
                    pem.push('\n');
                };
                pem.push(char);
            }
            pem.push_str("\n-----END PRIVATE KEY-----\n");
            pem
        }
        pub fn fake_creds() -> AdminSdkCredentials {
            AdminSdkCredentials {
                r#type: fake_non_secret(),
                project_id: fake_non_secret(),
                private_key_id: fake_non_secret(),
                private_key: Secret(fake_privkey()),
                client_email: fake_non_secret(),
                client_id: fake_non_secret(),
                auth_uri: fake_non_secret(),
                token_uri: fake_non_secret(),
                auth_provider_x509_cert_url: fake_non_secret(),
                client_x509_cert_url: fake_non_secret(),
                universe_domain: fake_non_secret(),
            }
        }
    }
}

mod jwt {
    use crate::auth::oauth::{
        firebase_credentials::{AdminSdkCredentials, Signature},
        jsonb64, OauthError, OauthErrorVariant, OauthResult,
    };
    use chrono::{Duration, Utc};
    use serde::Serialize;

    /// Base64-encoded and signed JWT.
    pub struct Jwt {
        pub pending: JWTPendingSignature,
        pub sig: Signature,
    }
    impl Jwt {
        pub fn serialize(&self) -> String {
            format!("{}.{}", self.pending.0, self.sig.to_base64())
        }
    }
    /// The first two fully serialized fields of the JWT joined by a `.`. The
    /// signature is produced from these bytes.
    pub struct JWTPendingSignature(pub String);
    impl JWTPendingSignature {
        pub fn new(header: &JWTHeader, claims: &JWTClaims) -> OauthResult<Self> {
            Ok(JWTPendingSignature(
                [
                    jsonb64(header, "error encoding header")?,
                    jsonb64(claims, "error encoding claims")?,
                ]
                .join("."),
            ))
        }
    }

    #[derive(Serialize)]
    pub struct JWTHeader<'a> {
        alg: &'static str,
        typ: &'static str,
        kid: &'a str,
    }
    impl<'a> JWTHeader<'a> {
        pub fn new(sdk_credentials: &'a AdminSdkCredentials) -> Self {
            Self {
                alg: "RS256",
                typ: "JWT",
                kid: &sdk_credentials.private_key_id.0,
            }
        }
    }

    #[derive(Serialize)]
    pub struct JWTClaims<'a> {
        /// Issuer: Your service account's email from [super::AdminSdkCredentials].
        iss: &'a str,
        scope: &'a str,
        aud: &'a str,
        exp: i64,
        iat: i64,
    }
    impl<'a> JWTClaims<'a> {
        pub fn new(sdk_credentials: &'a AdminSdkCredentials) -> Self {
            let now = Utc::now();
            let exp = (now + Duration::hours(1)).timestamp();
            let iat = now.timestamp();
            Self {
                iss: &sdk_credentials.client_email.0,
                scope: "https://www.googleapis.com/auth/firebase.messaging",
                aud: "https://oauth2.googleapis.com/token",
                exp,
                iat,
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::future::IntoFuture;

    use super::*;
    use crate::auth::oauth::jwt::Jwt;
    use aws_lc_rs::{
        digest::SHA256,
        signature::{
            KeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RSA_PSS_2048_8192_SHA256,
            RSA_PSS_SHA256,
        },
    };

    #[test]
    fn test_sign_and_verify_jwt() {
        let creds = firebase_credentials::test::fake_creds();
        let header = jwt::JWTHeader::new(&creds);
        let claims = jwt::JWTClaims::new(&creds);
        let pending = jwt::JWTPendingSignature::new(&header, &claims).expect("can construct first two JWT fields");
        let signature = creds.sign(&pending).expect("signature to succeed");
        let jwt_token = Jwt {
            sig: signature,
            pending,
        }
        .serialize();

        let parts: Vec<&str> = jwt_token.split('.').collect();
        if parts.len() != 3 {
            panic!("jwt does not have 3 parts");
        }

        let header_claims = format!("{}.{}", parts[0], parts[1]);
        // let mut hash = aws_lc_rs::digest::Context::new(&SHA256);
        // hash.update(header_claims.as_bytes());
        // let digest = hash.finish();
        let signature = BASE64_URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| OauthError {
                msg: format!("Could not decode JWT signature: {e}"),
                variant: OauthErrorVariant::Crypto,
            })
            .unwrap();

        let privkey_bytes = creds.dangerously_expose_private_key_material().unwrap();
        let key_pair = aws_lc_rs::signature::RsaKeyPair::from_pkcs8(&privkey_bytes)
            .map_err(|e| OauthError {
                msg: format!("Could not construct RsaKeyPair for public key extraction: {e}"),
                variant: OauthErrorVariant::Crypto,
            })
            .unwrap();

        let public_key_der = key_pair.public_key().as_ref().to_vec();
        let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key_der);

        public_key
            .verify(header_claims.as_bytes(), &signature)
            .expect("verifies");
    }

    // #[tokio::test]
    // async fn test_tmp() {
    //     let creds: AdminSdkCredentials = serde_json::from_slice(
    //         &std::fs::read("../../Downloads/remind-reader-firebase-adminsdk-fbsvc-f8aa958c9c.json").unwrap(),
    //     )
    //     .unwrap();
    //     let client = reqwest::Client::new();
    //     authenticate(&client, &creds).await.unwrap();
    // }
}
