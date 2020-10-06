use std::borrow::Cow;

/// Interface of OAuth secrets provider
pub trait SecretsProvider {
    fn get_consumer_key_pair<'a>(&'a self) -> (&'a str, &'a str);

    fn get_token_pair_option<'a>(&'a self) -> Option<(&'a str, &'a str)>;

    fn get_token_option_pair<'a>(&'a self) -> (Option<&'a str>, Option<&'a str>) {
        self.get_token_pair_option()
            .map(|s| (Some(s.0), Some(s.1)))
            .unwrap_or_else(|| (None, None))
    }
}

/**
Represents OAuth secrets including consumer_key, consumer_secret, token, and token_secret.
The token and token_secret are optional.

# Basic usage

```rust
use reqwest_oauth1::OAuthClientProvider;

let consumer_key = "[CONSUMER_KEY]";
let consumer_secret = "[CONSUMER_SECRET]";

// if you don't have the token and token secret:
let secrets = reqwest_oauth1::Secrets::new(consumer_key, consumer_secret);

// when you have the access token and secret:
let access_token = "[ACCESS_TOKEN]";
let token_secret = "[TOKEN_SECRET]";
let secrets_with_token = secrets.token(access_token, token_secret);

// use the secret
let req = reqwest::Client::new()
    .oauth1(secrets_with_token)
    .post("http://example.com/");
```

*/
#[derive(Debug, Clone)]
pub struct Secrets<'a> {
    consumer_key_secret: (Cow<'a, str>, Cow<'a, str>),
    token_key_secret: Option<(Cow<'a, str>, Cow<'a, str>)>,
}

impl<'a> Secrets<'a> {
    pub fn new<TKey, TSecret>(consumer_key: TKey, consumer_secret: TSecret) -> Self
    where
        TKey: Into<Cow<'a, str>>,
        TSecret: Into<Cow<'a, str>>,
    {
        Secrets {
            consumer_key_secret: (consumer_key.into(), consumer_secret.into()),
            token_key_secret: None,
        }
    }

    pub fn new_with_token<TKey, TSecret, TToken, TTokenSecret>(
        consumer_key: TKey,
        consumer_secret: TSecret,
        token: TToken,
        token_secret: TTokenSecret,
    ) -> Self
    where
        TKey: Into<Cow<'a, str>>,
        TSecret: Into<Cow<'a, str>>,
        TToken: Into<Cow<'a, str>>,
        TTokenSecret: Into<Cow<'a, str>>,
    {
        Secrets {
            consumer_key_secret: (consumer_key.into(), consumer_secret.into()),
            token_key_secret: Some((token.into(), token_secret.into())),
        }
    }

    pub fn token<TKey, TSecret>(self, token: TKey, token_secret: TSecret) -> Secrets<'a>
    where
        TKey: Into<Cow<'a, str>>,
        TSecret: Into<Cow<'a, str>>,
    {
        Secrets {
            token_key_secret: Some((token.into(), token_secret.into())),
            ..self
        }
    }
}

impl SecretsProvider for Secrets<'_> {
    fn get_consumer_key_pair<'a>(&'a self) -> (&'a str, &'a str) {
        (&self.consumer_key_secret.0, &self.consumer_key_secret.1)
    }

    fn get_token_pair_option<'a>(&'a self) -> Option<(&'a str, &'a str)> {
        match &self.token_key_secret {
            Some((k, s)) => Some((&k, &s)),
            None => None,
        }
    }
}
