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

let secrets = reqwest-oauth1::Secret::new(consumer_key, consumer_secret)
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

let secrets = reqwest-oauth1::Secret::new(consumer_key, consumer_secret);

// sample: request access token to twitter

// step 1: acquire request token & token secret
let endpoint_reqtoken = "https://api.twitter.com/oauth/request_token";

let client = reqwest::Client::new();
let req_token, req_secret = client
    .oauth1(secrets)
    .get(endpoint_reqtoken)
    .query(&["oauth_callback", "oob"])
    .send()?
    .parse_oauth_token()?;

// step 2. acquire user pin
let req_secrets = secrets.token(req_token, req_secret);
let endpoint_authorize = "https://api.twitter.com/oauth/authorize?oauth_token={}";

println!("open {} in your browser.",
    format!(endpoint_authorize,
        req_secrets.token)
    ));
println!("input pin: ");
let mut user_input = String::new();
io::stdin().read_line(&user_input)?;
let pin = user_input.trim();

// step 3. acquire access token
let endpoint_acctoken = "https://api.twitter.com/oauth/access_token";

let client = reqwest::Client::new();
let access_token, token_secret = client
    .oauth1(secrets)
    .get(endpoint_acctoken)
    .query(&["oauth_verifier", pin])
    .send()?
    .parse_oauth_token()?;
println!("your token and secret is: \n token: {}\n secret: {}",
    &access_token,
    &token_secret);
```


*/
mod client;
mod request;
mod secrets;
mod signer;

// exposed to external program
pub use client::*;
pub use request::*;
pub use secrets::*;
pub use signer::*;
