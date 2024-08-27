//use reqwest_oauth1;
use reqwest;

use std::{collections::HashMap, io};
use tokio;

const CONSUMER_KEY: &str = "[CONSUMER_KEY]";
const CONSUMER_SECRET: &str = "[CONSUMER_SECRET]";

#[cfg(feature = "blocking")]
use reqwest::blocking::Client as ReqwestClient;

#[cfg(not(feature = "blocking"))]
use crate::{OAuthClientProvider, Secrets, TokenReaderFuture};

#[cfg(feature = "blocking")]
use crate::{OAuthClientProvider, Secrets, TokenReaderBlocking};

#[cfg(not(feature = "blocking"))]
use reqwest::Client as ReqwestClient;

#[test]
fn map_test() {
    let map = vec![("a", "a"), ("b", "b"), ("c", "c"), ("d", "d"), ("a", "e")];
    let map: HashMap<&str, &str> = map.into_iter().collect();
    println!("{:#?}", map)
}

#[cfg(not(feature = "blocking"))]
#[tokio::test]
async fn usage_test() {
    // prepare authorization info

    let secrets = Secrets::new(CONSUMER_KEY, CONSUMER_SECRET);

    // sample: request access token to twitter

    // step 1: acquire request token & token secret
    let endpoint_reqtoken = "https://api.twitter.com/oauth/request_token";

    let client = ReqwestClient::new();
    let resp = client
        .oauth1(secrets)
        .post(endpoint_reqtoken)
        .query(&[("oauth_callback", "oob")])
        .send()
        .parse_oauth_token()
        .await
        .unwrap();

    // step 2. acquire user pin
    let endpoint_authorize = "https://api.twitter.com/oauth/authorize?oauth_token=";
    println!(
        "please access to: {}{}",
        endpoint_authorize, resp.oauth_token
    );

    println!("input pin: ");
    let mut user_input = String::new();
    io::stdin().read_line(&mut user_input).unwrap();
    let pin = user_input.trim();

    // step 3. acquire access token
    let secrets = Secrets::new(CONSUMER_KEY, CONSUMER_SECRET)
        .token(resp.oauth_token, resp.oauth_token_secret);
    let endpoint_acctoken = "https://api.twitter.com/oauth/access_token";

    let client = ReqwestClient::new();
    let resp = client
        .oauth1(secrets)
        .post(endpoint_acctoken)
        .query(&[("oauth_verifier", pin)])
        .send()
        .parse_oauth_token()
        .await
        .unwrap();
    println!(
        "your token and secret is: \n token: {}\n secret: {}",
        resp.oauth_token, resp.oauth_token_secret
    );
    println!("other attributes: {:#?}", resp.remain)
}

#[cfg(feature = "blocking")]
#[test]
fn usage_test() {
    // prepare authorization info

    let secrets = Secrets::new(CONSUMER_KEY, CONSUMER_SECRET);

    // sample: request access token to twitter

    // step 1: acquire request token & token secret
    let endpoint_reqtoken = "https://api.twitter.com/oauth/request_token";

    let client = ReqwestClient::new();
    let resp = client
        .oauth1(secrets)
        .post(endpoint_reqtoken)
        .query(&[("oauth_callback", "oob")])
        .send()
        .parse_oauth_token()
        .unwrap();

    // step 2. acquire user pin
    let endpoint_authorize = "https://api.twitter.com/oauth/authorize?oauth_token=";
    println!(
        "please access to: {}{}",
        endpoint_authorize, resp.oauth_token
    );

    println!("input pin: ");
    let mut user_input = String::new();
    io::stdin().read_line(&mut user_input).unwrap();
    let pin = user_input.trim();

    // step 3. acquire access token
    let secrets = Secrets::new(CONSUMER_KEY, CONSUMER_SECRET)
        .token(resp.oauth_token, resp.oauth_token_secret);
    let endpoint_acctoken = "https://api.twitter.com/oauth/access_token";

    let client = ReqwestClient::new();
    let resp = client
        .oauth1(secrets)
        .post(endpoint_acctoken)
        .query(&[("oauth_verifier", pin)])
        .send()
        .parse_oauth_token()
        .unwrap();
    println!(
        "your token and secret is: \n token: {}\n secret: {}",
        resp.oauth_token, resp.oauth_token_secret
    );
    println!("other attributes: {:#?}", resp.remain)
}
