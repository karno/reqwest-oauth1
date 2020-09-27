// ----------------------------------------------------------------------------
// This source code contains derived artifacts from seanmonstar's `reqwest`.
// for further information(including license information),
// please visit their repository: https://github.com/seanmonstar/reqwest .
// ----------------------------------------------------------------------------
use oauth1_request::signature_method::HmacSha1 as DefaultSignatureMethod;
use oauth1_request::signature_method::SignatureMethod;
use reqwest::{Client as ReqwestClient, IntoUrl, Method};

use crate::{OAuthParameters, SecretsProvider, Signer};

use super::request::RequestBuilder;

pub trait OAuthClientProvider {
    fn oauth1<'a, T>(self, secrets: &'a T) -> Client<Signer<'a, T, DefaultSignatureMethod>>
    where
        Self: Sized,
        T: SecretsProvider,
    {
        self.oauth1_with_params(secrets, OAuthParameters::new())
    }

    fn oauth1_with_params<'a, TSecrets, TSignatureMethod>(
        self,
        secrets: &'a TSecrets,
        params: OAuthParameters<'a, TSignatureMethod>,
    ) -> Client<Signer<'a, TSecrets, TSignatureMethod>>
    where
        Self: Sized,
        TSecrets: SecretsProvider,
        TSignatureMethod: SignatureMethod + Clone;
}

#[derive(Debug)]
pub struct Client<TSigner> {
    inner: ReqwestClient,
    signer: TSigner,
}

impl OAuthClientProvider for ReqwestClient {
    fn oauth1_with_params<'a, TSecrets, TSignatureMethod>(
        self,
        secrets: &'a TSecrets,
        parameters: OAuthParameters<'a, TSignatureMethod>,
    ) -> Client<Signer<'a, TSecrets, TSignatureMethod>>
    where
        Self: Sized,
        TSecrets: SecretsProvider,
        TSignatureMethod: SignatureMethod + Clone,
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

impl<'a, T> Client<T>
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
        let cloned_url = match url.clone().into_url() {
            Ok(url) => Some(url),
            Err(_) => None,
        };
        let cloned_method = method.clone();
        RequestBuilder::new(
            self.inner.request(method, url),
            cloned_method,
            cloned_url,
            self.signer.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn empty() {}
}
