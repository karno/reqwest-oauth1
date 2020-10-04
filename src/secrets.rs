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
let consumer_key = "[CONSUMER_KEY]";
let consumer_secret = "[CONSUMER_SECRET]";

// if you don't have the token and token secret:
let secrets = reqwest-oauth1::Secret::new(consumer_key, consumer_secret);

// when you have the access token and secret:
let access_token = "[ACCESS_TOKEN]";
let token_secret = "[TOKEN_SECRET]";
let secrets_with_token = secrets.token(access_token, token_secret);

// use the secret
let req = reqwest::Client::new()
    .oauth1(secrets_with_token)
    .post(endpoint)
```

*/
#[derive(Debug, Clone)]
pub struct Secrets<'a, T> {
    token: T,
    token_secret: T,
    consumer_key: Cow<'a, str>,
    consumer_secret: Cow<'a, str>,
}

impl<'a> Secrets<'a, ()> {
    pub fn new<TKey, TSecret>(consumer_key: TKey, consumer_secret: TSecret) -> Self
    where
        TKey: Into<Cow<'a, str>>,
        TSecret: Into<Cow<'a, str>>,
    {
        Secrets {
            token: (),
            token_secret: (),
            consumer_key: consumer_key.into(),
            consumer_secret: consumer_secret.into(),
        }
    }

    pub fn token<TKey, TSecret>(
        self,
        token: TKey,
        token_secret: TSecret,
    ) -> Secrets<'a, Cow<'a, str>>
    where
        TKey: Into<Cow<'a, str>>,
        TSecret: Into<Cow<'a, str>>,
    {
        Secrets {
            token: token.into(),
            token_secret: token_secret.into(),
            consumer_key: self.consumer_key,
            consumer_secret: self.consumer_secret,
        }
    }
}

impl SecretsProvider for Secrets<'_, ()> {
    fn get_consumer_key_pair<'a>(&'a self) -> (&'a str, &'a str) {
        (&self.consumer_key, &self.consumer_secret)
    }

    fn get_token_pair_option<'a>(&'a self) -> Option<(&'a str, &'a str)> {
        None
    }
}

impl SecretsProvider for Secrets<'_, Cow<'_, str>> {
    fn get_consumer_key_pair<'a>(&'a self) -> (&'a str, &'a str) {
        (&self.consumer_key, &self.consumer_secret)
    }

    fn get_token_pair_option<'a>(&'a self) -> Option<(&'a str, &'a str)> {
        Some((&self.token, &self.token_secret))
    }
}
