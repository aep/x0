use ::verifier;
use ::Identity;
use tokio_openssl;
use url;
use std;
use tokio;
use openssl;
use futures;
use hyper;

use futures::Future;
use openssl::ssl::{SslConnector, SslMethod};
use std::net::ToSocketAddrs;
use tokio::net::TcpStream;
use tokio_openssl::SslConnectorExt;

use hyper::Client;
use hyper::{Body};
use hyper::client::connect::{Connect, Destination};
use std::sync::Mutex;


#[derive(Default)]
pub struct ClientBuilder {
    verifier:   Option<verifier::Verifier>,
    url:        String,
    identity:   Option<Identity>,
}

pub fn builder() -> ClientBuilder {
    ClientBuilder::new()
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn verifier(mut self, verifier: verifier::Verifier) -> Self {
        self.verifier = Some(verifier);
        self
    }

    pub fn url(mut self, url: String) -> Self {
        self.url = url;
        self
    }

    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn build(self) -> impl Future<
        Item = (
        Identity,
        tokio_openssl::SslStream<TcpStream>
        ),
        Error = std::io::Error,
        > {

        let (cert, pkey) = self.identity.unwrap().to_x509().unwrap();

        let url = url::Url::parse(&self.url).unwrap();
        let addr = url.to_socket_addrs().unwrap().next().unwrap();

        let verifier = self.verifier.unwrap();

        let hello = TcpStream::connect(&addr)
            .and_then(move |socket| {
                let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
                builder.set_verify_callback(openssl::ssl::SslVerifyMode::PEER, move |ok, store| {
                    verifier.verify(ok, store)
                });
                builder.set_private_key(&pkey).unwrap();
                builder.set_certificate(&cert).unwrap();
                builder.check_private_key().unwrap();
                let connector = builder.build();
                connector
                    .connect_async(url.host_str().unwrap(), socket)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            })
            .and_then(move |socket| {
                let pkey = socket
                    .get_ref()
                    .ssl()
                    .peer_certificate()
                    .unwrap()
                    .public_key()
                    .unwrap();
                let pkey = pkey.public_key_to_der().unwrap();
                let identity = Identity::from_public_der(&pkey).unwrap();

                Ok((identity, socket))
            });

        hello


    }
}



pub struct IoConnector<T> {
    inner: Mutex<Option<T>>,
}

impl<T: 'static> Connect for IoConnector<T>
where
    T: tokio::io::AsyncWrite + tokio::io::AsyncRead + Send + Sync,
{
    type Transport = T;
    type Error = std::io::Error;
    type Future = futures::future::FutureResult<
        (Self::Transport, hyper::client::connect::Connected),
        Self::Error,
    >;
    fn connect(&self, _dst: Destination) -> Self::Future {
        let mut inner = self.inner.lock().unwrap();
        let inner = std::mem::replace(&mut *inner, None).unwrap();
        futures::future::ok((inner, hyper::client::connect::Connected::new()))
    }
}


