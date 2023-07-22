mod error;
mod from_tinker;

extern crate core;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use aes::Aes256;
use base64::{engine::general_purpose, Engine as _};
pub use error::AuthError;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use urlencoding::decode;

use crate::error::AResult;

// type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// The Auth struct is the main entry point for this library.
///
/// Example
/// ```ignore
/// let auth = Auth::from_tinker("/path/to/laravel/app")?;
///
/// let session_id = auth.get_session_id(cookie)?;
/// let redis_key = auth.get_redis_key(session_id)?;
/// let php_serialized_data = redis.get(redis_key)?;
///
/// let user_id = auth.get_user_id(&php_serialized_data)?;
/// ```
#[derive(Clone)]
pub struct Auth {
    app_key: Vec<u8>,
    /// The extra prefix that is added to the session_id to form the redis key.
    database_prefix: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Session {
    _token: String,
    /// The user_id of the logged in user.
    // The raw key name is funny. It is the result of the following:
    // ```php
    // $keyName = "login_web_" + sha1(\Illuminate\Auth\SessionGuard::class)
    //
    // // where
    // sha1(\Illuminate\Auth\SessionGuard::class) == "59ba36addc2b2f9401580f014c7f58ea4e30989d"
    // ```
    //
    // So this should hold constant for almost all Laravel apps.
    // The _web_ part can be dynamic, but is almost always web.
    #[serde(rename = "login_web_59ba36addc2b2f9401580f014c7f58ea4e30989d")]
    user_id: i64,
}

impl Auth {
    /// The passed app_key should be the value of the `APP_KEY` env variable.
    ///
    /// The leading `base64:` is optional.
    pub fn new(app_key: &str, database_prefix: impl Into<String>) -> AResult<Self> {
        let app_key = app_key.trim_start_matches("base64:");
        let app_key: Vec<u8> = general_purpose::STANDARD.decode(app_key)?;

        Ok(Self {
            app_key,
            database_prefix: database_prefix.into(),
        })
    }

    /// Returns the user_id of the logged in user from the serialized session data.
    /// Usually, this serialized session data is pulled from redis, using the session_id.
    pub fn get_user_id(&self, serialized_session_data: &str) -> AResult<i64> {
        let session = self.parse_session(serialized_session_data)?;
        Ok(session.user_id)
    }

    fn parse_session(&self, serialized_session_data: &str) -> AResult<Session> {
        // Unserialize twice
        let unserialized: String = php_serde::from_bytes(serialized_session_data.as_bytes())?;
        let unserialized: Session = php_serde::from_bytes(unserialized.as_bytes())?;

        Ok(unserialized)
    }

    /// Returns the session_id from the cookie.
    ///
    /// The session_id is then used to pull the serialized session data from redis.
    pub fn get_session_id(&self, cookie: &str) -> AResult<String> {
        let cookie = decode(cookie)?;
        let data = general_purpose::STANDARD.decode(cookie.as_bytes())?;
        let cookie = serde_json::from_slice::<Cookie>(&data)?;

        let mut key: [u8; 32] = [0; 32];
        key.copy_from_slice(&self.app_key);

        let mut v = cookie.value_data()?;
        Aes256CbcDec::new(&key.into(), &cookie.iv_data()?.into())
            .decrypt_padded_mut::<Pkcs7>(&mut v)?;

        let out = String::from_utf8(v)?;
        let out = out.trim_end_matches("\x0f");
        let parts = out
            .split("|")
            .skip(1)
            .next()
            .ok_or(AuthError::MissingSessionId)?;

        Ok(parts.to_string())
    }

    pub fn get_redis_key(&self, session_id: &str) -> AResult<String> {
        Ok(format!("{}:{}", self.database_prefix, session_id))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Cookie {
    iv: String,
    value: String,
    mac: String,
    tag: String,
}

impl Cookie {
    fn value_data(&self) -> Result<Vec<u8>, base64::DecodeError> {
        general_purpose::STANDARD.decode(&self.value)
    }

    fn iv_data(&self) -> Result<[u8; 16], base64::DecodeError> {
        let v = general_purpose::STANDARD.decode(&self.iv)?;
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&v);
        Ok(iv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() -> AResult<()> {
        dotenv::dotenv().ok();
        let app_key = std::env::var("APP_KEY").unwrap();
        // let cookie = std::env::var("COOKIE").unwrap();
        let a = Auth::new(&app_key, "test")?;
        // let session_id = a.get_session_id(&cookie);

        let t3 = std::env::var("PHP_SERIALIZED").unwrap();
        let result = a.get_user_id(&t3)?;
        assert_eq!(result, 5);

        Ok(())
    }

    #[test]
    #[ignore]
    fn it_works_real() -> AResult<()> {
        dotenv::dotenv().ok();
        let cookie = std::env::var("COOKIE2").unwrap();
        println!("{}", cookie);
        let auth = Auth::from_tinker(&std::env::var("LARAVEL_ENV_PATH").unwrap())?;

        let session = auth.get_session_id(&cookie)?;
        println!("session: {}", session);
        let key = auth.get_redis_key(&session)?;
        println!("    key: {}", key);

        // load from redis
        let serialized = std::env::var("PHP_SERIALIZED2").unwrap();

        let r = auth.get_user_id(&serialized)?;
        println!("{}", r);
        // let Auth::from_tinker("/");

        Ok(())
    }
}
