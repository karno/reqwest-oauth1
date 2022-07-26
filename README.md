# reqwest-oauth1: reqwest ♡ oauth1-request

Add OAuth1 signature to [reqwest](https://crates.io/crates/reqwest) with [oauth1-request](https://crates.io/crates/oauth1-request).

This library provides partial compatible interface of reqwest.

You can use this almost same as reqwest, and signing with OAuth1 authorization protocol.

> Note: this crate is currently supporting the asynchronous Client (reqwest::Client) only.

## Installation

Add dependency of `reqwest-oauth1` to your `Cargo.toml` as belows:

```Cargo.toml
[dependencies]
reqwest-oauth1 = "*"
```

## How to use

### At a glance overview

1. Add reference to crate `reqwest_oauth1` in your code like `use reqwest_oauth1;`
2. Prepare OAuth keys: `consumer_key`, `consumer_secret`, `access_token`, and `token_secret`.
3. Add `oauth1` method into your method chain of `reqwest`'s.

```rust
use reqwest;
use reqwest::multipart;
use reqwest_oauth1::OAuthClientProvider;

// prepare authorization info
let consumer_key = "[CONSUMER_KEY]";
let consumer_secret = "[CONSUMER_SECRET]";
let access_token = "[ACCESS_TOKEN]";
let token_secret = "[TOKEN_SECRET]";

let secrets = reqwest_oauth1::Secrets::new(consumer_key, consumer_secret)
  .token(access_token, token_secret);

// sample: send new tweet to twitter
let endpoint = "https://api.twitter.com/1.1/statuses/update.json";

let content = multipart::Form::new()
    .text("status", "Hello, Twitter!");

let client = reqwest::Client::new();
let resp = client
    // enable OAuth1 request
    .oauth1(secrets)
    .post(endpoint)
    .multipart(content)
    .send()
    .await?;
```

### OAuth key acquisition

This library also includes support for getting `access_token` and `token_secret`.

Please note there still needs the `consumer_key` and the `consumer_secret` and you have to get these keys somehow.

```rust
use std::io;
use reqwest;
use reqwest_oauth1::OAuthClientProvider;

// prepare authorization info
let consumer_key = "[CONSUMER_KEY]";
let consumer_secret = "[CONSUMER_SECRET]";

let secrets = reqwest_oauth1::Secrets::new(consumer_key, consumer_secret);

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
let secrets = secrets.token(req_token, req_secret);
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
println!("other attributes: {:#?}", resp.remain);
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
    .send()
    .await?;
```

### Detailed behavior

You can specify `oauth_*` parameters both of in `OAuthParameters` or get/post query.

If you specify the parameter with both of them, the parameters specified as get/post query will supersede the parameters passed with `OAuthParameters`.

```rust
let params = reqwest_oauth1::OAuthParameters::new()
    .nonce("ThisNonceWillBeSuperseded");
let req = reqwest::Client::new()
    .oauth1_with_params(secrets, paras)
    .get(endpoint)
    .query(&[("nonce", "ThisNonceWillSupersedeTheOldOne")])
    ...
```

However, these parameter can not specify as the get/post query.

- `oauth_signature_method` : Could be configured only with the `OAuthParameters`.
- `oauth_consumer_key`, `oauth_token` : Could be configured as the `Secrets`.
- `oauth_timestamp` with non-`u64` values: the OAuth1 protocol is not allowed it.
- `oauth_version` with neither of `"1.0"` or just `""` : the OAuth1 protocol is not allowed it.
- any `oauth_*` parameter that is not defined in OAuth1 protocol: currently not supported.

### Customization of OAuth Autentication Method

When you calling `oauth1` method in `Client`, or `sign` method in `RequestBuilder`, you can call `*_with_params` method with some parameters instead of original method.

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Note: This library contains derived artifacts from seanmonster's [`reqwest`](https://crates.io/crates/reqwest).
It is distributed under the either of MIT License or Apache License.
See [LICENSE-REQWEST-MIT](./LICENSE-REQUEST-MIT) and [LICENSE-REQWEST-APACHE](./LICENSE-REQUEST-APACHE) for further information.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Known Issue

This library still depends on the older version `0.3.3` of `oauth1-request`.
This depends on the raw implementation of the oauth1 signing method, however, the recent versions of `oauth1-request` hide their raw interface. Therefore, we can't migrate to a newer version of them.

Currently, severe vulnerabilities have not reported on those versions, so I think we can still use older versions, but your contributions are always welcome.
