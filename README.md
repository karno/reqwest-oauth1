# reqwest-oauth1: reqwest ♡ oauth1-request

Add feature of OAuth1 request to [reqwest](https://crates.io/crates/reqwest)  with [oauth1-request](https://crates.io/crates/oauth1-request).

This library provides partial compatible interface of reqwest.

You can use this almost same as reqwest, and signing with OAuth1 authorization protocol.

    Note: this crate is currently supporting the asynchronous Client (reqwest::Client) only.

## Installation

Add dependency of `reqwest-oauth1` to your `Cargo.toml` as belows:

```Cargo.toml
[dependencies]
reqwest-oauth1 = "*"
```

## How to use

### At a glance overview

1. Add reference to crate `reqwest-oauth1` in your code like `use reqwest-oauth1;`
2. Prepare OAuth keys: `consumer_key`, `consumer_secret`, `access_token`, and `token_secret`.
3. Add `oauth1`  method into your method chain of `reqwest`'s.

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

### OAuth key acquisition

This library also includes support for getting `access_token` and `token_secret`.

Please note there still needs the `consumer_key` and the `consumer_secret` and you have to get these keys somehow.

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

### Another option

You can use `sign` method as follows instead of use `oauth1` method.

```rust
// instantiate our wrapper Client directly
let client = reqwest::Client::new();
let resp = client
    .post(endpoint)
    .multipart(form)
    // ... and add secrets to generate signature
    .sign(secrets)
    .send()?;
```

### Customization of OAuth Autentication Method

When you calling `oauth1` method in `Client`, or `sign` method in `RequestBuilder`, you can call `*_with_params` method with some parameters instead of original method.

## License

Licensed under either of

* Apache License, Version 2.0
([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.


Note: This library contains derived artifacts from seanmonster's [`reqwest`](https://crates.io/crates/reqwest).
It is distributed under the either of MIT License or Apache License.
See [LICENSE-REQWEST-MIT](./LICENSE-REQUEST-MIT) and [LICENSE-REQWEST-APACHE](./LICENSE-REQUEST-APACHE) for further information.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.