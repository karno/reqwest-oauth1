use std::collections::HashMap;

use reqwest::blocking::Response;
use serde::Deserialize;

use crate::{Error, Result, TokenReaderError, TokenReaderResult};

const OAUTH_TOKEN_KEY: &str = "oauth_token";

const OAUTH_TOKEN_SECRET_KEY: &str = "oauth_token_secret";

/// Represents response of token acquisition.
#[derive(Deserialize, Debug)]
pub struct TokenResponse {
    /// OAuth Token
    pub oauth_token: String,
    /// OAuth Token Secret
    pub oauth_token_secret: String,
    /// Other contents
    #[serde(flatten)]
    pub remain: HashMap<String, String>,
}

/// Add parse_oauth_token feature to reqwest::Response.
pub trait TokenReader: private::Sealed {
    fn parse_oauth_token(self) -> Result<TokenResponse>;
}

impl TokenReader for Response {
    fn parse_oauth_token(self) -> Result<TokenResponse> {
        let text = self.text();
        // let text = self.error_for_status()?.text().await?;
        // println!("{:#?}", text);
        Ok(read_oauth_token(text?)?)
    }
}

/// Add parse_oauth_token feature to Future of reqwest::Response.
pub trait TokenReaderBlocking: private::SealedWrapper {
    fn parse_oauth_token(self) -> Result<TokenResponse>;
}

impl<E> TokenReaderBlocking for std::result::Result<Response, E>
where
    E: Into<Error>,
{
    fn parse_oauth_token(self) -> Result<TokenResponse> {
        match self {
            Ok(resp) => resp.parse_oauth_token(),
            Err(err) => Err(err.into()),
        }
    }
}

fn read_oauth_token(text: String) -> TokenReaderResult<TokenResponse> {
    let mut destructured = text
        .split("&")
        .map(|e| e.splitn(2, "="))
        .map(|v| {
            let mut iter = v.into_iter();
            (
                iter.next().unwrap_or_default().to_string(),
                iter.next().unwrap_or_default().to_string(),
            )
        })
        .collect::<HashMap<String, String>>();
    let oauth_token = destructured.remove(OAUTH_TOKEN_KEY);
    let oauth_token_secret = destructured.remove(OAUTH_TOKEN_SECRET_KEY);
    match (oauth_token, oauth_token_secret) {
        (Some(t), Some(s)) => Ok(TokenResponse {
            oauth_token: t,
            oauth_token_secret: s,
            remain: destructured,
        }),
        (None, _) => Err(TokenReaderError::TokenKeyNotFound(OAUTH_TOKEN_KEY, text)),
        (_, _) => Err(TokenReaderError::TokenKeyNotFound(
            OAUTH_TOKEN_SECRET_KEY,
            text,
        )),
    }
}

mod private {
    use reqwest::blocking::Response;

    use crate::Error;

    pub trait Sealed {}
    impl Sealed for Response {}
    pub trait SealedWrapper {}
    // impl<T> SealedWrapper for T where T: Future<Output = reqwest::Result<Response>> {}
    impl<E> SealedWrapper for std::result::Result<Response, E> where E: Into<Error> {}
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn parse_response_typical() {
        let resp_str_sample = "oauth_token=Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik&oauth_token_secret=Kd75W4OQfb2oJTV0vzGzeXftVAwgMnEK9MumzYcM&oauth_callback_confirmed=true";
        for parsed in &[
            read_oauth_token(resp_str_sample.to_string()).unwrap(),
            serde_urlencoded::from_str::<TokenResponse>(resp_str_sample).unwrap(),
        ] {
            assert_eq!(
                parsed.oauth_token,
                "Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik"
            );
            assert_eq!(
                parsed.oauth_token_secret,
                "Kd75W4OQfb2oJTV0vzGzeXftVAwgMnEK9MumzYcM"
            );
            assert_eq!(parsed.remain.len(), 1);
            let oauth_callback_confirmed = parsed.remain.get("oauth_callback_confirmed").unwrap();
            assert_eq!(oauth_callback_confirmed, "true");
        }
    }

    #[test]
    fn parse_response_edge() {
        let resp_str_sample = "oauth_token==&oauth_token_secret=&keyonly=&keyonly2&=&&";
        for parsed in &[
            read_oauth_token(resp_str_sample.to_string()).unwrap(),
            serde_urlencoded::from_str::<TokenResponse>(resp_str_sample).unwrap(),
        ] {
            assert_eq!(parsed.oauth_token, "=");
            assert_eq!(parsed.oauth_token_secret, "");
            assert_eq!(parsed.remain.len(), 3);
            let keyonly = parsed.remain.get("keyonly").unwrap();
            assert_eq!(keyonly, "");
            let keyonly2 = parsed.remain.get("keyonly2").unwrap();
            assert_eq!(keyonly2, "");
            let empty = parsed.remain.get("").unwrap();
            assert_eq!(empty, "");
        }
    }

    #[test]
    fn parse_minimal() {
        let resp_str_sample = "oauth_token&oauth_token_secret";
        let parsed = read_oauth_token(resp_str_sample.to_string()).unwrap();
        assert_eq!(parsed.oauth_token, "");
        assert_eq!(parsed.oauth_token_secret, "");
        assert_eq!(parsed.remain.len(), 0);
    }

    #[test]
    fn parse_token_notfound() {
        let resp_str_sample = "oauth_token_secret=";
        let parsed = read_oauth_token(resp_str_sample.to_string());
        assert!(parsed.is_err());
        if let Err(TokenReaderError::TokenKeyNotFound(key, resp_str)) = parsed {
            assert_eq!(key, OAUTH_TOKEN_KEY);
            assert_eq!(resp_str, resp_str_sample)
        } else {
            assert!(false)
        }
    }

    #[test]
    fn parse_token_secret_notfound() {
        let resp_str_sample = "oauth_token=";
        let parsed = read_oauth_token(resp_str_sample.to_string());
        assert!(parsed.is_err());
        if let Err(TokenReaderError::TokenKeyNotFound(key, resp_str)) = parsed {
            assert_eq!(key, OAUTH_TOKEN_SECRET_KEY);
            assert_eq!(resp_str, resp_str_sample)
        } else {
            assert!(false)
        }
    }
}
