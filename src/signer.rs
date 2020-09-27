use std::borrow::Cow;

use crate::SecretsProvider;
use http::Method;
use oauth1_request::signature_method::SignatureMethod;
use oauth1_request::signer::Signer as OAuthSigner;
use oauth1_request::{HmacSha1, Options};
use url::Url;

const OAUTH_IDENTIFIER: &str = "oauth_";
const REALM_IDENTIFIER: &str = "realm";

#[derive(Debug, Clone)]
pub struct Signer<'a, TSecretsProvider, TSignatureMethod>
where
    TSecretsProvider: SecretsProvider,
    TSignatureMethod: SignatureMethod + Clone,
{
    secrets: &'a TSecretsProvider,
    parameters: OAuthParameters<'a, TSignatureMethod>,
}

impl<'a, TSecretsProvider, TSignatureMethod> Signer<'a, TSecretsProvider, TSignatureMethod>
where
    TSecretsProvider: SecretsProvider,
    TSignatureMethod: SignatureMethod + Clone,
{
    pub fn new(
        secrets: &'a TSecretsProvider,
        parameters: OAuthParameters<'a, TSignatureMethod>,
    ) -> Self {
        Signer {
            secrets,
            parameters,
        }
    }

    pub fn generate_signature(
        self,
        method: Method,
        url: Url,
        payload: &str,
        is_url_query: bool,
    ) -> String {
        let (consumer_key, consumer_secret) = self.secrets.get_consumer_key_pair();
        let (token, token_secret) = self.secrets.get_token_option_pair();
        // build oauth option
        let options = self.parameters.build_options(token);

        // destructure query and sort by alphabetical order
        let parsed_payload: Vec<(Cow<str>, Cow<str>)> =
            url::form_urlencoded::parse(payload.as_bytes())
                .into_iter()
                .collect();
        let oauth_identifier = vec![(Cow::from(OAUTH_IDENTIFIER), Cow::from(""))];
        let mut sorted_query = [parsed_payload, oauth_identifier].concat();
        sorted_query.sort();

        // divide key-value items by the element has "oauth_" key
        let mut divided = sorted_query
            .splitn(2, |(k, _)| k == &OAUTH_IDENTIFIER)
            .into_iter();
        let query_before_oauth = divided.next().unwrap();
        let query_after_oauth = divided.next().unwrap_or_default();

        // generate signature
        // Step 0. instantiate sign generator
        let sig_method = self.parameters.signature_method.clone();
        let mut signer = if is_url_query {
            OAuthSigner::with_signature_method(
                sig_method,
                method.as_str(),
                url,
                consumer_secret,
                token_secret,
            )
        } else {
            OAuthSigner::form_with_signature_method(
                sig_method,
                method.as_str(),
                url,
                consumer_secret,
                token_secret,
            )
        };

        // Step 1. key [a ~ oauth_)
        for (key, value) in query_before_oauth {
            if !key.starts_with(OAUTH_IDENTIFIER) {
                // not an oauth_* parameter
                signer.parameter(key, value);
            }
        }
        // Step 2. add oauth_* parameters
        let mut signer = signer.oauth_parameters(consumer_key, &options);
        // Step 3. key (oauth_ ~ z]
        for (key, value) in query_after_oauth {
            if !key.starts_with(OAUTH_IDENTIFIER) {
                // not an oauth_* parameter
                signer.parameter(key, value);
            }
        }

        // signature is generated.
        let sign = signer.finish().authorization;

        if let Some(realm) = self.parameters.realm {
            // OAuth oauth_...,realm="realm"
            format!("{},{}=\"{}\"", sign, REALM_IDENTIFIER, realm.as_ref())
        } else {
            // OAuth oauth_...
            sign
        }
    }
}

#[derive(Debug, Clone)]
pub struct OAuthParameters<'a, TSignatureMethod>
where
    TSignatureMethod: SignatureMethod + Clone,
{
    callback: Option<Cow<'a, str>>,
    nonce: Option<Cow<'a, str>>,
    realm: Option<Cow<'a, str>>,
    signature_method: TSignatureMethod,
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

impl<'a> OAuthParameters<'a, HmacSha1> {
    pub fn new() -> Self {
        Default::default()
    }

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

    /// set the oauth_realm value
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
}

impl<'a, T> OAuthParameters<'a, T>
where
    T: SignatureMethod + Clone,
{
    pub fn signature_method<TSignatureMethod>(
        self,
        signature_method: TSignatureMethod,
    ) -> OAuthParameters<'a, TSignatureMethod>
    where
        TSignatureMethod: SignatureMethod + Clone,
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

impl<'a, T> OAuthParameters<'a, T>
where
    T: SignatureMethod + Clone,
{
    fn build_options(&'a self, token: Option<&'a str>) -> Options<'a> {
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
