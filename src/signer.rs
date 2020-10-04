use std::{borrow::Cow, collections::HashMap};

use crate::{SecretsProvider, SignError, SignResult};
use crate::{
    OAUTH_CALLBACK_KEY, OAUTH_CONSUMER_KEY, OAUTH_KEY_PREFIX, OAUTH_NONCE_KEY,
    OAUTH_SIGNATURE_METHOD_KEY, OAUTH_TIMESTAMP_KEY, OAUTH_TOKEN_KEY, OAUTH_VERIFIER_KEY,
    OAUTH_VERSION_KEY, REALM_KEY,
};
use http::Method;
use oauth1_request::signature_method::SignatureMethod;
use oauth1_request::signer::Signer as OAuthSigner;
use oauth1_request::{HmacSha1, Options};
use url::Url;

/**
Provides OAuth signature with [oauth1-request](https://crates.io/crates/oauth1-request).

# Note

This struct is intended for internal use.

You may consider use the struct provided from oauth1-request crate directly
instead of this struct.

*/
#[derive(Debug, Clone)]
pub struct Signer<'a, TSecrets, TSM>
where
    TSecrets: SecretsProvider + Clone,
    TSM: SignatureMethod + Clone,
{
    secrets: TSecrets,
    parameters: Result<OAuthParameters<'a, TSM>, SignError>,
}

impl<'a, TSecretsProvider, TSM> Signer<'a, TSecretsProvider, TSM>
where
    TSecretsProvider: SecretsProvider + Clone,
    TSM: SignatureMethod + Clone,
{
    pub fn new(secrets: TSecretsProvider, parameters: OAuthParameters<'a, TSM>) -> Self {
        Signer {
            secrets,
            parameters: Ok(parameters),
        }
    }

    pub fn override_oauth_parameter(mut self, parameters: HashMap<String, String>) -> Self {
        for (key, value) in parameters {
            self.parameters = match self.parameters {
                Ok(p) => match key.as_str() {
                    // always success
                    OAUTH_CALLBACK_KEY => Ok(p.callback(value)),
                    OAUTH_NONCE_KEY => Ok(p.nonce(value)),
                    OAUTH_VERIFIER_KEY => Ok(p.verifier(value)),
                    REALM_KEY => Ok(p.realm(value)),
                    // potential to fail
                    OAUTH_TIMESTAMP_KEY => match value.parse::<u64>() {
                        Ok(v) => Ok(p.timestamp(v)),
                        Err(_) => Err(SignError::InvalidTimestamp(value)),
                    },
                    OAUTH_VERSION_KEY => match value.as_str() {
                        "1.0" => Ok(p.version(true)),
                        "" => Ok(p.version(false)),
                        _ => Err(SignError::InvalidVersion(value)),
                    },
                    // always fail
                    OAUTH_SIGNATURE_METHOD_KEY | OAUTH_CONSUMER_KEY | OAUTH_TOKEN_KEY => {
                        Err(SignError::UnconfigurableParameter(key))
                    }
                    _ => Err(SignError::UnknownParameter(key)),
                },
                Err(e) => Err(e),
            };
        }

        self
    }

    /// Generate OAuth signature with specified parameters.
    pub(crate) fn generate_signature(
        self,
        method: Method,
        url: Url,
        payload: &str,
        is_url_query: bool,
    ) -> SignResult<String> {
        let (consumer_key, consumer_secret) = self.secrets.get_consumer_key_pair();
        let (token, token_secret) = self.secrets.get_token_option_pair();
        // build oauth option
        let params = self.parameters?;
        let options = params.build_options(token);

        // destructure query and sort by alphabetical order
        let parsed_payload: Vec<(Cow<str>, Cow<str>)> =
            url::form_urlencoded::parse(payload.as_bytes())
                .into_iter()
                .collect();
        // add `oauth_` key to identify where to divide
        let oauth_identifier = vec![(Cow::from(OAUTH_KEY_PREFIX), Cow::from(""))];
        let mut sorted_query = [parsed_payload, oauth_identifier].concat();

        // then, sort by alphabetical order (that is required by OAuth specification)
        sorted_query.sort();

        // divide key-value items by the element has "oauth_" key
        let mut divided = sorted_query
            .splitn(2, |(k, _)| k == &OAUTH_KEY_PREFIX)
            .into_iter();
        let query_before_oauth = divided.next().unwrap();
        let query_after_oauth = divided.next().unwrap_or_default();

        // generate signature
        // Step 0. instantiate sign generator
        let sig_method = params.signature_method.clone();
        println!("signing url: {:#?}", url);
        let mut signer = generate_signer(
            sig_method,
            method.as_str(),
            url,
            consumer_secret,
            token_secret,
            is_url_query,
        );

        // Step 1. key [a ~ oauth_)
        for (key, value) in query_before_oauth {
            if !key.starts_with(OAUTH_KEY_PREFIX) {
                // not an oauth_* parameter
                signer.parameter(key, value);
            }
        }
        // Step 2. add oauth_* parameters
        let mut signer = signer.oauth_parameters(consumer_key, &options);
        // Step 3. key (oauth_ ~ z]
        for (key, value) in query_after_oauth {
            if !key.starts_with(OAUTH_KEY_PREFIX) {
                // not an oauth_* parameter
                signer.parameter(key, value);
            }
        }

        // signature is generated.
        let sign = signer.finish().authorization;

        if let Some(realm) = params.realm {
            // OAuth oauth_...,realm="realm"
            Ok(format!("{},{}=\"{}\"", sign, REALM_KEY, realm.as_ref()))
        } else {
            // OAuth oauth_...
            Ok(sign)
        }
    }
}

fn generate_signer<TSM>(
    signature_method: TSM,
    method: &str,
    url: Url,
    consumer_secret: &str,
    token_secret: Option<&str>,
    is_url_query: bool,
) -> OAuthSigner<TSM>
where
    TSM: SignatureMethod,
{
    if is_url_query {
        OAuthSigner::with_signature_method(
            signature_method,
            method,
            url,
            consumer_secret,
            token_secret,
        )
    } else {
        OAuthSigner::form_with_signature_method(
            signature_method,
            method,
            url,
            consumer_secret,
            token_secret,
        )
    }
}

/**
Represents OAuth parameters including oauth_nonce, oauth_timestamp, realm, and others.

# Basic usage

```rust
let consumer_key = "[CONSUMER_KEY]";
let consumer_secret = "[CONSUMER_SECRET]";
let secrets = reqwest-oauth1::Secret::new(consumer_key, consumer_secret);

let nonce = "[NONCE]";
let timestamp = 100_000_001u64;
let callback = "http://example.com/ready";

let params = OAuthParameters::new()
    .nonce(nonce)
    .timestamp(timestamp)
    .callback(callback);

let req = reqwest::Client::new()
    .oauth1_with_params(&secrets, params)
    .post(endpoint)
    ...
```

# Note

If you want to add `realm` parameter in your request, you must pass it
by OAuthParameter. Otherwise, you will get the wrong signature.

```rust
let realm = "Realm";
let params = OAuthParameters::new()
    .realm(realm);

let req = reqwest::Client::new()
    .oauth1_with_params(&secrets, params)
    .post(endpoint)
    // YOU CAN'T DO THIS!
    // .form(&[("realm", realm)])
    ...
```

*/
#[derive(Debug, Clone)]
pub struct OAuthParameters<'a, TSM>
where
    TSM: SignatureMethod + Clone,
{
    callback: Option<Cow<'a, str>>,
    nonce: Option<Cow<'a, str>>,
    realm: Option<Cow<'a, str>>,
    signature_method: TSM,
    timestamp: Option<u64>,
    verifier: Option<Cow<'a, str>>,
    version: bool,
}

impl Default for OAuthParameters<'static, HmacSha1> {
    fn default() -> Self {
        OAuthParameters {
            callback: None,
            nonce: None,
            realm: None,
            signature_method: HmacSha1,
            timestamp: None,
            verifier: None,
            version: false,
        }
    }
}

impl OAuthParameters<'_, HmacSha1> {
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, TSM> OAuthParameters<'a, TSM>
where
    TSM: SignatureMethod + Clone,
{
    /// set the oauth_callback value
    pub fn callback<T>(self, callback: T) -> Self
    where
        T: Into<Cow<'a, str>>,
    {
        OAuthParameters {
            callback: Some(callback.into()),
            ..self
        }
    }

    /// set the oauth_nonce value
    pub fn nonce<T>(self, nonce: T) -> Self
    where
        T: Into<Cow<'a, str>>,
    {
        OAuthParameters {
            nonce: Some(nonce.into()),
            ..self
        }
    }

    /// set the realm value
    ///
    /// # Note
    /// this parameter will not be included in the signature-base string.
    /// cf. https://tools.ietf.org/html/rfc5849#section-3.4.1.3.1
    pub fn realm<T>(self, realm: T) -> Self
    where
        T: Into<Cow<'a, str>>,
    {
        OAuthParameters {
            realm: Some(realm.into()),
            ..self
        }
    }

    /// set the oauth_timestamp value
    pub fn timestamp<T>(self, timestamp: T) -> Self
    where
        T: Into<u64>,
    {
        OAuthParameters {
            timestamp: Some(timestamp.into()),
            ..self
        }
    }

    /// set the oauth_verifier value
    pub fn verifier<T>(self, verifier: T) -> Self
    where
        T: Into<Cow<'a, str>>,
    {
        OAuthParameters {
            verifier: Some(verifier.into()),
            ..self
        }
    }

    /// set the oauth_version value (boolean)
    ///
    /// # Note
    /// When the version has value `true`, oauth_version will be set with "1.0".
    /// Otherwise, oauth_version will not be included in your request.
    /// In oauth1, oauth_version value must be "1.0" or not specified.
    pub fn version<T>(self, version: T) -> Self
    where
        T: Into<bool>,
    {
        OAuthParameters {
            version: version.into(),
            ..self
        }
    }
    pub fn signature_method<T>(self, signature_method: T) -> OAuthParameters<'a, T>
    where
        T: SignatureMethod + Clone,
    {
        OAuthParameters {
            signature_method,
            callback: None,
            nonce: None,
            realm: None,
            timestamp: None,
            verifier: None,
            version: false,
        }
    }
}

impl<T> OAuthParameters<'_, T>
where
    T: SignatureMethod + Clone,
{
    fn build_options<'a>(&'a self, token: Option<&'a str>) -> Options<'a> {
        let mut opt = Options::new();

        // NOTE: items must be added by alphabetical order

        if let Some(ref callback) = self.callback {
            opt.callback(callback.as_ref());
        }
        if let Some(ref nonce) = self.nonce {
            opt.nonce(nonce.as_ref());
        }
        if let Some(timestamp) = self.timestamp {
            opt.timestamp(timestamp);
        }
        if let Some(token) = token {
            opt.token(token);
        }
        if let Some(ref verifier) = self.verifier {
            opt.verifier(verifier.as_ref());
        }
        opt.version(self.version);
        if self.version {}

        opt
    }
}
