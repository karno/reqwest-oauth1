// ----------------------------------------------------------------------------
// This source code contains derived artifacts from seanmonstar's `reqwest`.
// for further information(including license information),
// please visit their repository: https://github.com/seanmonstar/reqwest .
// ----------------------------------------------------------------------------

pub use oauth1_request::signature_method::HmacSha1 as DefaultSM;
use oauth1_request::signature_method::SignatureMethod;
use reqwest::{IntoUrl, Method};

#[cfg(feature = "blocking")]
use reqwest::blocking::Client as ReqwestClient;

#[cfg(not(feature = "blocking"))]
use reqwest::Client as ReqwestClient;

use crate::{OAuthParameters, RequestBuilder, SecretsProvider, Signer};

/// Bridge trait from reqwest's `Client` from our `Client`.
pub trait OAuthClientProvider {
    fn oauth1<'a, T>(self, secrets: T) -> Client<Signer<'a, T, DefaultSM>>
    where
        Self: Sized,
        T: SecretsProvider + Clone,
    {
        self.oauth1_with_params(secrets, OAuthParameters::new())
    }

    fn oauth1_with_params<'a, TSecrets, TSM>(
        self,
        secrets: TSecrets,
        params: OAuthParameters<'a, TSM>,
    ) -> Client<Signer<'a, TSecrets, TSM>>
    where
        Self: Sized,
        TSecrets: SecretsProvider + Clone,
        TSM: SignatureMethod + Clone;
}

/// Compatible interface with reqwest's [`Client`](https://docs.rs/reqwest/0.10.8/reqwest/struct.Client.html).
#[derive(Debug)]
pub struct Client<TSigner> {
    inner: ReqwestClient,
    signer: TSigner,
}

impl OAuthClientProvider for ReqwestClient {
    fn oauth1_with_params<'a, TSecrets, TSM>(
        self,
        secrets: TSecrets,
        parameters: OAuthParameters<'a, TSM>,
    ) -> Client<Signer<'a, TSecrets, TSM>>
    where
        Self: Sized,
        TSecrets: SecretsProvider + Clone,
        TSM: SignatureMethod + Clone,
    {
        Client {
            inner: self,
            signer: Signer::new(secrets, parameters),
        }
    }
}

impl From<ReqwestClient> for Client<()> {
    fn from(client: ReqwestClient) -> Self {
        Client::new_with_client(client)
    }
}

impl Client<()> {
    /// Constructs a new `Client`.
    ///
    /// This method calls reqwest::Client::new() internally.
    pub fn new() -> Self {
        Client {
            inner: ReqwestClient::new(),
            signer: (),
        }
    }

    /// Constructs a new `Client` with specifying inner `reqwest::Client`.
    pub fn new_with_client(client: ReqwestClient) -> Self {
        Client {
            inner: client,
            signer: (),
        }
    }
}

impl<T> Client<T>
where
    T: Clone,
{
    /// Convenience method to make a `GET` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever supplied `Url` cannot be parsed.
    pub fn get<U: IntoUrl + Clone>(&self, url: U) -> RequestBuilder<T> {
        self.request(Method::GET, url)
    }

    /// Convenience method to make a `POST` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever supplied `Url` cannot be parsed.
    pub fn post<U: IntoUrl + Clone>(&self, url: U) -> RequestBuilder<T> {
        self.request(Method::POST, url)
    }

    /// Convenience method to make a `PUT` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever supplied `Url` cannot be parsed.
    pub fn put<U: IntoUrl + Clone>(&self, url: U) -> RequestBuilder<T> {
        self.request(Method::PUT, url)
    }

    /// Convenience method to make a `PATCH` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever supplied `Url` cannot be parsed.
    pub fn patch<U: IntoUrl + Clone>(&self, url: U) -> RequestBuilder<T> {
        self.request(Method::PATCH, url)
    }

    /// Convenience method to make a `DELETE` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever supplied `Url` cannot be parsed.
    pub fn delete<U: IntoUrl + Clone>(&self, url: U) -> RequestBuilder<T> {
        self.request(Method::DELETE, url)
    }

    /// Convenience method to make a `HEAD` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever supplied `Url` cannot be parsed.
    pub fn head<U: IntoUrl + Clone>(&self, url: U) -> RequestBuilder<T> {
        self.request(Method::HEAD, url)
    }

    /// Start building a `Request` with the `Method` and `Url`.
    ///
    /// Returns a `RequestBuilder<T>`, which will allow setting headers and
    /// request body before sending.
    ///
    /// # Errors
    ///
    /// This method fails whenever supplied `Url` cannot be parsed.
    pub fn request<U: IntoUrl + Clone>(&self, method: Method, url: U) -> RequestBuilder<T> {
        RequestBuilder::new(&self.inner, method, url, self.signer.clone())
    }
}
