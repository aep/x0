use ::verifier;
use ::Identity;
use tokio_openssl;
use url;
use std;
use tokio;
use openssl;
use futures;
use hyper;

use futures::{Future, Stream, future};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_openssl::SslAcceptorExt;
use openssl::ssl::{SslAcceptor, SslMethod};
use hyper::{Body, Chunk, Client, Method, Request, Response, Server, StatusCode};
use std::io;
use tokio::net::TcpStream;

#[derive(Default)]
pub struct Builder {
    verifier:   Option<verifier::Verifier>,
    identity:   Option<Identity>,
}

pub fn builder() -> Builder {
    Builder::new()
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn verifier(mut self, verifier: verifier::Verifier) -> Self {
        self.verifier = Some(verifier);
        self
    }

    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn bind(self, addr: SocketAddr) -> Result<impl Stream<
        Item = Result<(Identity, tokio_openssl::SslStream<TcpStream>), io::Error>,
        Error = io::Error,
        >, io::Error> {

            let verifier = self.verifier.unwrap();
            let (cert, pkey) = self.identity.unwrap().to_x509()?;

            let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
            acceptor.set_private_key(&pkey).unwrap();
            acceptor.set_certificate(&cert).unwrap();
            acceptor.check_private_key().unwrap();
            acceptor.set_verify_callback(
                openssl::ssl::SslVerifyMode::PEER | openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                move |ok, store| verifier.verify(ok, store),
            );
            let acceptor = acceptor.build();
            let tcp = TcpListener::bind(&addr)?;
            let server = tcp.incoming()
                .and_then(move |conn|{
                    acceptor.accept_async(conn)
                        .map_err(|e|io::Error::new(io::ErrorKind::Other, e))
                        .and_then(|conn|{
                            let pkey = conn.get_ref()
                                .ssl()
                                .peer_certificate()
                                .unwrap()
                                .public_key()?;
                            let pkey = pkey.public_key_to_der()?;
                            let identity = match Identity::from_public_der(&pkey) {
                                None => return Err(io::Error::new(io::ErrorKind::Other, "missing peer id")),
                                Some(i) => i,
                            };
                            Ok((identity, conn))
                        })
                        .then(|v|future::ok(v))
                });
            Ok(server)
    }
}
