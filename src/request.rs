// ----------------------------------------------------------------------------
// This source code contains derived artifacts from seanmonstar's `reqwest`.
// for further information(including license information),
// please visit their repository: https://github.com/seanmonstar/reqwest .
// ----------------------------------------------------------------------------
use std::{collections::HashMap, convert::TryFrom, fmt, time::Duration};

use http::{header::AUTHORIZATION, Method};
use oauth1_request::signature_method::HmacSha1 as DefaultSM;
use oauth1_request::signature_method::SignatureMethod;
use reqwest::{
    header::HeaderMap, header::HeaderName, header::HeaderValue, multipart, Body,
    Client as RequwestClient, IntoUrl, RequestBuilder as ReqwestRequestBuilder, Response,
};
use serde::Serialize;
use url::Url;

use crate::{
    Error, OAuthParameters, SecretsProvider, SignResult, Signer, OAUTH_KEY_PREFIX, REALM_KEY,
};

/// Compatible interface with reqwest's [`RequestBuilder`](https://docs.rs/reqwest/0.10.8/reqwest/struct.RequestBuilder.html).
pub struct RequestBuilder<TSigner>
where
    TSigner: Clone,
{
    method: Method,
    inner: ReqwestRequestBuilder,
    signer: TSigner,
    url: Option<Url>,
    body: String,
    query_oauth_parameters: HashMap<String, String>,
    form_oauth_parameters: HashMap<String, String>,
}

impl RequestBuilder<()> {
    // ------------------------------------------------------------------------
    // Set signing information

    /// Add the signing information.
    pub fn sign<'a, TSecrets>(
        self,
        secrets: TSecrets,
    ) -> RequestBuilder<Signer<'a, TSecrets, DefaultSM>>
    where
        TSecrets: SecretsProvider + Clone,
    {
        self.sign_with_params(secrets, OAuthParameters::new())
    }

    /// Add the signing information with OAuth parameters.
    pub fn sign_with_params<'a, TSecrets, TSM>(
        self,
        secrets: TSecrets,
        params: OAuthParameters<'a, TSM>,
    ) -> RequestBuilder<Signer<'a, TSecrets, TSM>>
    where
        TSecrets: SecretsProvider + Clone,
        TSM: SignatureMethod + Clone,
    {
        RequestBuilder {
            inner: self.inner,
            method: self.method,
            url: self.url,
            body: self.body,
            signer: Signer::new(secrets.into(), params),
            query_oauth_parameters: self.query_oauth_parameters,
            form_oauth_parameters: self.form_oauth_parameters,
        }
    }
}

impl<TSecrets, TSM> RequestBuilder<Signer<'_, TSecrets, TSM>>
where
    TSecrets: SecretsProvider + Clone,
    TSM: SignatureMethod + Clone,
{
    // ------------------------------------------------------------------------
    // Finish building the request and send it to server with OAuth signature

    /// Constructs the Request and sends it to the target URL, returning a
    /// future Response.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending request,
    /// redirect loop was detected or redirect limit was exhausted.
    pub async fn send(self) -> Result<Response, Error> {
        Ok(self.generate_signature()?.send().await?)
    }

    /// Generate an OAuth signature and return the reqwest's `RequestBuilder`.
    pub fn generate_signature(self) -> SignResult<ReqwestRequestBuilder> {
        if let Some(url) = self.url {
            let (is_q, url, payload) = match url.query() {
                None | Some("") => {
                    // POST
                    (false, url, self.body.as_ref())
                }
                Some(q) => {
                    // GET
                    let mut pure_url = url.clone();
                    pure_url.set_query(None);
                    (true, pure_url, q)
                }
            };
            let oauth_params: HashMap<String, String> = self
                .form_oauth_parameters
                .into_iter()
                .chain(self.query_oauth_parameters.into_iter())
                .collect();

            let signature = self
                .signer
                .override_oauth_parameter(oauth_params)
                .generate_signature(self.method, url, payload, is_q)?;
            // println!("generated signature: {}", signature);
            // set AUTHORIZATION header to inner RequestBuilder and return it
            Ok(self.inner.header(AUTHORIZATION, signature))
        } else {
            // just return inner RequestBuilder
            Ok(self.inner)
        }
    }
}

impl<TSigner> RequestBuilder<TSigner>
where
    TSigner: Clone,
{
    pub(crate) fn new<T: IntoUrl + Clone>(
        client: &RequwestClient,
        method: Method,
        url: T,
        signer: TSigner,
    ) -> Self {
        match url.clone().into_url() {
            Ok(url) => {
                let mut query_oauth_params: HashMap<String, String> = HashMap::new();
                let stealed_url = steal_oauth_params_from_url(url, &mut query_oauth_params);
                RequestBuilder {
                    inner: client.request(method.clone(), stealed_url.clone()),
                    method,
                    url: Some(stealed_url),
                    body: String::new(),
                    signer: signer,
                    query_oauth_parameters: query_oauth_params,
                    form_oauth_parameters: HashMap::new(),
                }
            }
            Err(_) => RequestBuilder {
                inner: client.request(method.clone(), url),
                method,
                url: None,
                body: String::new(),
                signer: signer,
                query_oauth_parameters: HashMap::new(),
                form_oauth_parameters: HashMap::new(),
            },
        }
    }

    // ------------------------------------------------------------------------
    // Trapped with the wrapper

    /// Modify the query string of the URL.
    ///
    /// Modifies the URL of this request, adding the parameters provided.
    /// This method appends and does not overwrite. This means that it can
    /// be called multiple times and that existing query parameters are not
    /// overwritten if the same key is used. The key will simply show up
    /// twice in the query string.
    /// Calling `.query([("foo", "a"), ("foo", "b")])` gives `"foo=a&foo=b"`.
    ///
    /// # Note
    /// This method does not support serializing a single key-value
    /// pair. Instead of using `.query(("key", "val"))`, use a sequence, such
    /// as `.query(&[("key", "val")])`. It's also possible to serialize structs
    /// and maps into a key-value pair.
    ///
    /// # Errors
    /// This method will fail if the object you provide cannot be serialized
    /// into a query string.
    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> Self {
        // stealing oauth_* parameters
        let query = steal_oauth_params(query, &mut self.query_oauth_parameters);

        // update local-captured url
        if let Some(ref mut url) = self.url {
            let mut pairs = url.query_pairs_mut();
            let serializer = serde_urlencoded::Serializer::new(&mut pairs);

            let _ = query.serialize(serializer);
        }
        // cleanup
        if let Some(ref mut url) = self.url {
            if let Some("") = url.query() {
                url.set_query(None);
            }
        }
        // passing argument into original request builder
        self.inner = self.inner.query(&query);
        self
    }

    /// Send a form body.
    pub fn form<T: Serialize + ?Sized + Clone>(mut self, form: &T) -> Self {
        // before stealing oauth_* parameters, clear old result
        self.form_oauth_parameters.clear();
        // stealing oauth_* parameters
        let form = steal_oauth_params(form, &mut self.query_oauth_parameters);

        match serde_urlencoded::to_string(form.clone()) {
            Ok(body) => {
                self.inner = self.inner.form(&form);
                self.body = body;
                self
            }
            Err(_) => self.pass_through(|b| b.form(&form)),
        }
    }

    // ------------------------------------------------------------------------
    // Bypass methods

    /// Modify the query string of the URL, without capturing OAuth parameters.
    ///
    /// # Note
    /// Generated OAuth signature will may be invalid when you call this method
    /// with the parameters including the `oauth_*` parameters or the `realm` parameter.
    pub fn query_without_capture<T: Serialize>(self, query: &T) -> Self {
        self.pass_through(|b| b.query(query))
    }

    ///
    /// # Note
    /// Generated OAuth signature will may be invalid when you call this method
    /// with the parameters including the `oauth_*` parameters or the `realm` parameter.
    pub fn form_without_capture<T: Serialize + ?Sized>(self, form: &T) -> Self {
        self.pass_through(|b| b.form(form))
    }

    // ------------------------------------------------------------------------
    // Pass-through to inner builder

    fn pass_through<F>(self, f: F) -> Self
    where
        F: FnOnce(ReqwestRequestBuilder) -> ReqwestRequestBuilder,
    {
        RequestBuilder {
            inner: f(self.inner),
            ..self
        }
    }

    /// Add a `Header` to this Request.
    pub fn header<K, V>(self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.pass_through(|b| b.header(key, value))
    }

    /// Add a set of Headers to the existing ones on this Request.
    ///
    /// The headers will be merged in to any already set.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.inner = self.inner.headers(headers);
        self
    }

    /// Enable HTTP basic authentication.
    pub fn basic_auth<U, P>(self, username: U, password: Option<P>) -> Self
    where
        U: fmt::Display,
        P: fmt::Display,
    {
        self.pass_through(|b| b.basic_auth(username, password))
    }

    /// Enable HTTP bearer authentication.
    pub fn bearer_auth<T>(self, token: T) -> Self
    where
        T: fmt::Display,
    {
        self.pass_through(|b| b.bearer_auth(token))
    }

    /// Set the request body.
    pub fn body<T: Into<Body>>(mut self, body: T) -> Self {
        self.inner = self.inner.body(body);
        self
    }

    /// Enables a request timeout.
    ///
    /// The timeout is applied from the when the request starts connecting
    /// until the response body has finished. It affects only this request
    /// and overrides the timeout configured using `ClientBuilder::timeout()`.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    /// Sends a multipart/form-data body.
    ///
    /// ```
    /// # use reqwest::Error;
    ///
    /// # async fn run() -> Result<(), Error> {
    /// let client = reqwest::Client::new();
    /// let form = reqwest::multipart::Form::new()
    ///     .text("key3", "value3")
    ///     .text("key4", "value4");
    ///
    ///
    /// let response = client.post("your url")
    ///     .multipart(form)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Note: multipart/form-data is not handled by the OAuth signer.
    pub fn multipart(self, multipart: multipart::Form) -> Self {
        self.pass_through(|b| b.multipart(multipart))
    }

    /// Disable CORS on fetching the request.
    ///
    /// # WASM
    ///
    /// This option is only effective with WebAssembly target.
    ///
    /// The [request mode][mdn] will be set to 'no-cors'.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/API/Request/mode
    pub fn fetch_mode_no_cors(self) -> Self {
        self
    }

    /// Attempt to clone the RequestBuilder.
    ///
    /// `None` is returned if the RequestBuilder can not be cloned,
    /// i.e. if the request body is a stream.
    pub fn try_clone(&self) -> Option<Self> {
        match self.inner.try_clone() {
            Some(inner) => Some(RequestBuilder {
                inner,
                method: self.method.clone(),
                url: self.url.clone(),
                body: self.body.clone(),
                signer: self.signer.clone(),
                query_oauth_parameters: self.query_oauth_parameters.clone(),
                form_oauth_parameters: self.form_oauth_parameters.clone(),
            }),
            None => None,
        }
    }
}

fn steal_oauth_params<T>(
    query: &T,
    oauth_map: &mut HashMap<String, String>,
) -> Vec<(String, String)>
where
    T: Serialize + ?Sized,
{
    let mut empty_url = Url::parse("http://example.com/")
        // this is valid url and always success
        .expect("failed to parse the http://example.com/, that is unexpected behavior.");
    {
        let mut pairs = empty_url.query_pairs_mut();
        let serializer = serde_urlencoded::Serializer::new(&mut pairs);
        let _ = query.serialize(serializer);
    }

    // capture oauth_* item and construct remainder vector, then return
    steal_oauth_params_core(&empty_url, oauth_map)
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn steal_oauth_params_from_url(mut url: Url, oauth_map: &mut HashMap<String, String>) -> Url {
    let remainder = steal_oauth_params_core(&url, oauth_map);
    // clear query
    url.set_query(None);
    if remainder.len() > 0 {
        // add non oauth_* parameters
        let mut serializer = url.query_pairs_mut();
        for (k, v) in remainder {
            serializer.append_pair(&k, &v);
        }
    }

    url
}

fn steal_oauth_params_core(
    url: &Url,
    oauth_map: &mut HashMap<String, String>,
) -> Vec<(String, String)> {
    // steal oauth_* items
    url.query_pairs()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .filter_map(|(k, v)| {
            if k.starts_with(OAUTH_KEY_PREFIX) || k == REALM_KEY {
                // capture oauth_* item
                oauth_map.insert(k, v);
                None
            } else {
                Some((k, v))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use http::header::AUTHORIZATION;

    use crate::{
        OAuthClientProvider, OAuthParameters, Secrets, OAUTH_NONCE_KEY, OAUTH_TIMESTAMP_KEY,
    };

    fn extract_signature(auth_header: &str) -> String {
        let content = auth_header.strip_prefix("OAuth ").unwrap();
        let mapped_header = content
            .split(',')
            .map(|item| item.splitn(2, '=').collect::<Vec<&str>>())
            .filter(|v| v.len() == 2)
            .map(|v| (v[0], v[1]))
            .collect::<Vec<(&str, &str)>>();
        let sig_content = mapped_header.iter().find(|(k, _)| k == &"oauth_signature");
        percent_encoding::percent_decode_str(sig_content.unwrap().1)
            .decode_utf8_lossy()
            .trim_matches('"')
            .to_string()
    }

    #[test]
    fn call_multiple_queries() {
        let req = reqwest::Client::new()
            .get("https://example.com")
            .query(&[("a", "b")])
            .query(&[("c", "d")])
            .build()
            .unwrap();
        // println!("{:#?}", req.url());
        assert_eq!(req.url().to_string(), "https://example.com/?a=b&c=d");
    }

    #[test]
    fn call_multiple_forms() {
        let req = reqwest::Client::new()
            .post("https://example.com")
            .query(&[("this is", "query")])
            .form(&[("a", "b")]) // this will be ignored
            .form(&[("c", "d")])
            .build()
            .unwrap();
        // println!("{:#?}", req.url());
        let decoded_body = String::from_utf8_lossy(req.body().unwrap().as_bytes().unwrap());
        // println!("{:#?}", decoded_body);
        assert_eq!(req.url().to_string(), "https://example.com/?this+is=query");
        assert_eq!(decoded_body, "c=d");
    }

    #[test]
    fn capture_post_query() {
        let endpoint = "https://photos.example.net/initiate";
        let c_key = "dpf43f3p2l4k3l03";
        let c_secret = "kd94hf93k423kf44";
        let nonce = "wIjqoS";
        let timestamp = 137_131_200u64;

        let secrets = Secrets::new(c_key, c_secret);
        let params = OAuthParameters::new()
            .nonce(nonce)
            .timestamp(timestamp)
            .callback("http://printer.example.com/ready")
            .realm("photos");

        let req = reqwest::Client::new()
            .oauth1_with_params(secrets, params)
            .post(endpoint)
            .form(&[("少女", "終末旅行"), ("oauth_should_be_ignored", "true")]);
        let url = req.body;
        // println!("{:?}", url);
        assert_eq!(
            url,
            "%E5%B0%91%E5%A5%B3=%E7%B5%82%E6%9C%AB%E6%97%85%E8%A1%8C"
        );
    }

    #[test]
    fn sign_post_query() {
        // https://tools.ietf.org/html/rfc5849
        let endpoint = "https://photos.example.net/initiate";
        let c_key = "dpf43f3p2l4k3l03";
        let c_secret = "kd94hf93k423kf44";
        let nonce = "wIjqoS";
        let timestamp = 137_131_200u64;

        let secrets = Secrets::new(c_key, c_secret);
        let params = OAuthParameters::new()
            .nonce(nonce)
            .timestamp(timestamp)
            .callback("http://printer.example.com/ready")
            .realm("photos");

        let req = reqwest::Client::new()
            .oauth1_with_params(secrets, params)
            .post(endpoint)
            .generate_signature()
            .unwrap()
            .build()
            .unwrap();

        let sign = req.headers().get(AUTHORIZATION);
        // println!("{:#?}", sign);
        assert_eq!(
            extract_signature(sign.unwrap().to_str().unwrap()),
            "74KNZJeDHnMBp0EMJ9ZHt/XKycU="
        );
    }

    #[test]
    fn capture_get_query() {
        // https://tools.ietf.org/html/rfc5849
        let endpoint = "https://photos.example.net/photos?file=vacation.jpg&size=original&oauth_should_be_ignored=true";
        let c_key = "dpf43f3p2l4k3l03";
        let c_secret = "kd94hf93k423kf44";
        let token = "nnch734d00sl2jdk";
        let token_secret = "pfkkdhi9sl3r4s00";
        let nonce = "wIjqoS";
        let timestamp = 137_131_200u64;

        let secrets = Secrets::new(c_key, c_secret).token(token, token_secret);
        let params = OAuthParameters::new().nonce(nonce).timestamp(timestamp);

        let req = reqwest::Client::new()
            .oauth1_with_params(secrets, params)
            .get(endpoint);
        let query = req.url.unwrap().query().unwrap().to_string();
        // println!("{:?}", query);
        assert_eq!(query, "file=vacation.jpg&size=original")
    }

    #[test]
    fn sign_get_query() {
        // https://tools.ietf.org/html/rfc5849
        let endpoint = "http://photos.example.net/photos?file=vacation.jpg&size=original";
        let c_key = "dpf43f3p2l4k3l03";
        let c_secret = "kd94hf93k423kf44";
        let token = "nnch734d00sl2jdk";
        let token_secret = "pfkkdhi9sl3r4s00";
        let nonce = "chapoH";
        let timestamp = 137_131_202u64;

        let secrets = Secrets::new(c_key, c_secret).token(token, token_secret);
        let params = OAuthParameters::new()
            .nonce(nonce)
            .timestamp(timestamp)
            .realm("Photos");
        // .version(true);

        let req = reqwest::Client::new()
            .oauth1_with_params(secrets, params)
            .get(endpoint)
            .generate_signature()
            .unwrap()
            .build()
            .unwrap();

        let sign = req.headers().get(AUTHORIZATION);
        // println!("{:#?}", sign);
        assert_eq!(
            extract_signature(sign.unwrap().to_str().unwrap()),
            "MdpQcU8iPSUjWoN/UDMsK2sui9I="
        );

        // println!("{:#?}", sign);
        // assert_eq!(sign, "MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D");
    }

    #[test]
    fn sign_get_query_with_query_oauth_params() {
        // https://tools.ietf.org/html/rfc5849
        let endpoint =
            "http://photos.example.net/photos?file=vacation.jpg&size=original&realm=Photos";
        let c_key = "dpf43f3p2l4k3l03";
        let c_secret = "kd94hf93k423kf44";
        let token = "nnch734d00sl2jdk";
        let token_secret = "pfkkdhi9sl3r4s00";
        let nonce = "chapoH";
        let timestamp = 137_131_202u64;

        let secrets = Secrets::new(c_key, c_secret).token(token, token_secret);
        // .version(true);

        let req = reqwest::Client::new()
            .oauth1(secrets)
            .get(endpoint)
            .query(&[
                (OAUTH_NONCE_KEY, nonce),
                (OAUTH_TIMESTAMP_KEY, &format!("{}", timestamp)),
            ])
            .generate_signature()
            .unwrap()
            .build()
            .unwrap();

        let sign = req.headers().get(AUTHORIZATION);
        // println!("{:#?}", sign);
        assert_eq!(
            extract_signature(sign.unwrap().to_str().unwrap()),
            "MdpQcU8iPSUjWoN/UDMsK2sui9I="
        );

        // println!("{:#?}", sign);
        // assert_eq!(sign, "MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D");
    }

    #[test]
    fn capture_body() {
        // https://developer.twitter.com/ja/docs/basics/authentication/guides/creating-a-signature
        let endpoint = url::Url::parse("https://api.twitter.com/1.1/statuses/update.json").unwrap();
        let c_key = "xvz1evFS4wEEPTGEFPHBog";
        let c_secret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
        let nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
        let timestamp = 1_318_622_958u64;
        let token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb";
        let token_secret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";

        let secrets = Secrets::new(c_key, c_secret).token(token, token_secret);
        let params = OAuthParameters::new().nonce(nonce).timestamp(timestamp);

        let req = reqwest::Client::new()
            .oauth1_with_params(secrets, params)
            .post(endpoint)
            .form(&[
                ("include_entities", "true"),
                (
                    "status",
                    "Hello Ladies + Gentlemen, a signed OAuth request!",
                ),
            ]);

        let body = req.body;
        // println!("{:#?}", body);
        assert_eq!(
            body,
            "include_entities=true&status=Hello+Ladies+%2B+Gentlemen%2C+a+signed+OAuth+request%21"
        )
    }

    #[test]
    fn sign_post_body() {
        // https://developer.twitter.com/ja/docs/basics/authentication/guides/creating-a-signature
        let endpoint = url::Url::parse("https://api.twitter.com/1.1/statuses/update.json").unwrap();
        let c_key = "xvz1evFS4wEEPTGEFPHBog";
        let c_secret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
        let nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
        let timestamp = 1_318_622_958u64;
        let token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb";
        let token_secret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";

        let secrets = Secrets::new(c_key, c_secret).token(token, token_secret);
        let params = OAuthParameters::new()
            .nonce(nonce)
            .timestamp(timestamp)
            .version(true);

        let req = reqwest::Client::new()
            .oauth1_with_params(secrets, params)
            .post(endpoint)
            .form(&[
                ("include_entities", "true"),
                (
                    "status",
                    "Hello Ladies + Gentlemen, a signed OAuth request!",
                ),
            ])
            .generate_signature()
            .unwrap()
            .build()
            .unwrap();

        let sign = req.headers().get(AUTHORIZATION);
        // println!("{:#?}", sign);
        assert_eq!(
            extract_signature(sign.unwrap().to_str().unwrap()),
            "hCtSmYh+iHYCEqBWrE7C7hYmtUk="
        );
    }
}
