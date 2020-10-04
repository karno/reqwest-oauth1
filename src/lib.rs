/*!
reqwest-oauth1: reqwest ♡ oauth1-request.

Repository is here: https://github.com/karno/reqwest-oauth1

# Overview

This library provides OAuth 1.0a authorization capability to [reqwest](https://crates.io/crates/reqwest)
crate by providing the thin (partial-)compatible interface layer built with [oauth1-request](https://crates.io/crates/oauth1-request) crate.

# How to use

## Basic usecase 1 - sending the tweet

```rust
use reqwest-oauth1;
use reqwest;
use reqwest::multipart;

// prepare authorization info
let consumer_key = "[CONSUMER_KEY]";
let consumer_secret = "[CONSUMER_SECRET]";
let access_token = "[ACCESS_TOKEN]";
let token_secret = "[TOKEN_SECRET]";

let secrets = reqwest-oauth1::Secrets::new(consumer_key, consumer_secret)
  .token(access_token, token_secret);

// sample: send new tweet to twitter
let endpoint = "https://api.twitter.com/1.1/statuses/update.json";

let content = multipart::Form::new()
    .text("status", "Hello, Twitter!")?;

let client = reqwest::Client::new();
let resp = client
    // enable OAuth1 request
    .oauth1(secrets)
    .post(endpoint)
    .multipart(form)
    .send()?;
```

## Basic usecase 2 - Acquiring OAuth token & secret

```rust
use std::io;
use reqwest-oauth1;
use reqwest;

// prepare authorization info
let consumer_key = "[CONSUMER_KEY]";
let consumer_secret = "[CONSUMER_SECRET]";

let secrets = reqwest-oauth1::Secrets::new(consumer_key, consumer_secret);

// sample: request access token to twitter

// step 1: acquire request token & token secret
let endpoint_reqtoken = "https://api.twitter.com/oauth/request_token";

let client = reqwest::Client::new();
let resp = client
    .oauth1(secrets)
    .get(endpoint_reqtoken)
    .query(&[("oauth_callback", "oob")])
    .send()
    .parse_oauth_token()
    .await?;

// step 2. acquire user pin
let endpoint_authorize = "https://api.twitter.com/oauth/authorize?oauth_token=";
println!("please access to: {}{}", endpoint_authorize, resp.oauth_token);

println!("input pin: ");
let mut user_input = String::new();
io::stdin().read_line(&mut user_input)?;
let pin = user_input.trim();

// step 3. acquire access token
let secrets = Secrets::new(consumer_key, consumer_secret)
        .token(resp.oauth_token, resp.oauth_token_secret);
let endpoint_acctoken = "https://api.twitter.com/oauth/access_token";

let client = reqwest::Client::new();
let resp = client
    .oauth1(secrets)
    .get(endpoint_acctoken)
    .query(&[("oauth_verifier", pin)])
    .send()
    .parse_oauth_token()
    .await?;
println!(
    "your token and secret is: \n token: {}\n secret: {}",
    resp.oauth_token, resp.oauth_token_secret
);
println!("other attributes: {:#?}", resp.remain)
```


*/
mod client;
mod error;
mod request;
mod secrets;
mod signer;
mod token_reader;
#[cfg(test)]
// mod usage_test;

// exposed to external program
pub use client::{Client, OAuthClientProvider};
pub use error::{Error, Result, SignError, SignResult, TokenReaderError, TokenReaderResult};
pub use request::RequestBuilder;
pub use secrets::{Secrets, SecretsProvider};
pub use signer::{OAuthParameters, Signer};
pub use token_reader::{TokenReader, TokenReaderFuture, TokenResponse};

// exposed constant variables
/// Represents `oauth_callback`.
pub const OAUTH_CALLBACK_KEY: &str = "oauth_callback";
/// Represents `oauth_nonce`.
pub const OAUTH_NONCE_KEY: &str = "oauth_nonce";
/// Represents `oauth_timestamp`.
pub const OAUTH_TIMESTAMP_KEY: &str = "oauth_timestamp";
/// Represents `oauth_verifier`.
pub const OAUTH_VERIFIER_KEY: &str = "oauth_verifier";
/// Represents `oauth_version`.
pub const OAUTH_VERSION_KEY: &str = "oauth_version";
/// Represents `realm`.
pub const REALM_KEY: &str = "realm";

// crate-private constant variables
pub(crate) const OAUTH_KEY_PREFIX: &str = "oauth_";
pub(crate) const OAUTH_SIGNATURE_METHOD_KEY: &str = "oauth_signature_method";
pub(crate) const OAUTH_CONSUMER_KEY: &str = "oauth_consumer_key";
pub(crate) const OAUTH_TOKEN_KEY: &str = "oauth_token";
