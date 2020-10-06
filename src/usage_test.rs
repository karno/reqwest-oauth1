// use reqwest_oauth1;
use reqwest;
use std::{collections::HashMap, io};
use tokio;

use crate::{OAuthClientProvider, Secrets, TokenReaderFuture};

#[test]
fn map_test() {
    let map = vec![("a", "a"), ("b", "b"), ("c", "c"), ("d", "d"), ("a", "e")];
    let map: HashMap<&str, &str> = map.into_iter().collect();
    println!("{:#?}", map)
}

#[tokio::test]
async fn usage_test() {
    // prepare authorization info
    let consumer_key = "[CONSUMER_KEY]";
    let consumer_secret = "[CONSUMER_SECRET]";

    let secrets = Secrets::new(consumer_key, consumer_secret);

    // sample: request access token to twitter

    // step 1: acquire request token & token secret
    let endpoint_reqtoken = "https://api.twitter.com/oauth/request_token";

    let client = reqwest::Client::new();
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
    let secrets = Secrets::new(consumer_key, consumer_secret)
        .token(resp.oauth_token, resp.oauth_token_secret);
    let endpoint_acctoken = "https://api.twitter.com/oauth/access_token";

    let client = reqwest::Client::new();
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
