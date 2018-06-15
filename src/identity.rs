use openssl;
use std;
use bs58;
use crc8;
use sha2;
use der_parser::{parse_der, DerObjectContent};
use nom::IResult;

#[derive(Clone)]
pub enum Algo {
    Ed25519 = 0x9,
}

pub struct Identity {
    algo:    Algo,
    secret:  Vec<u8>,
    public:  Vec<u8>,
}


impl Identity {

    pub fn into_parts(self) -> (Algo,Vec<u8>,Vec<u8>) {
        (self.algo, self.secret, self.public)
    }

    pub fn public_id(&self) -> String {
        let mut v = Vec::new();
        v.push(8 as u8);
        v.push(self.algo.clone() as u8);
        v.extend_from_slice(&self.public);

        let mut crc8 = crc8::Crc8::create_lsb(130);
        let crc = crc8.calc(&v.as_ref(), v.len() as i32, 0);
        v.push(crc);

        bs58::encode(v)
            .with_alphabet(bs58::alphabet::BITCOIN)
            .into_string()
    }

    pub fn from_private(secret: Vec<u8>) -> Self {
        use ed25519_dalek::{PublicKey, SecretKey};
        let secret_key: SecretKey = SecretKey::from_bytes(&secret).unwrap();
        let pk: PublicKey = PublicKey::from_secret::<sha2::Sha512>(&secret_key);

        Self {
            algo:   Algo::Ed25519,
            secret: secret,
            public: pk.as_bytes().to_vec(),
        }
    }

    pub fn from_public(public: Vec<u8>) -> Self {
        Self {
            algo:   Algo::Ed25519,
            secret: Vec::new(),
            public: public,
        }
    }

    pub fn from_public_der(der: &[u8]) -> Option<Self>  {
        let res = parse_der(der);
        if let IResult::Done(_rem, d) = res {
            if d.class != 0 || d.structured != 1 || d.tag != 16 {
                warn!("DER parsing failed: unexpected class, struct or tag");
                return None;
            }
            let vec = match d.content {
                DerObjectContent::Sequence(vec) => vec,
                _ => {
                    warn!("DER parsing failed: expected sequence");
                    return None;
                }
            };

            if vec.len() < 2 {
                warn!("DER parsing failed: expected sequence len 2");
                return None;
            };

            let oidvec = match &vec[0].content {
                DerObjectContent::Sequence(vec) => vec,
                _ => {
                    warn!("DER parsing failed: expected sequence");
                    return None;
                }
            };

            if oidvec.len() < 1 {
                warn!("DER parsing failed: expected sequence len 1");
                return None;
            };

            let oid = match &oidvec[0].content {
                DerObjectContent::OID(oid) => oid,
                any => {
                    warn!("DER parsing failed: expected oid, got {:?}", any);
                    return None;
                }
            };

            let key = match &vec[1].content {
                DerObjectContent::BitString(_, o) => o.data.to_vec(),
                _ => {
                    warn!("DER parsing failed: expected bitstring");
                    return None;
                }
            };

            let _algo = match oid.to_string().as_str() {
                "1.3.101.112" => Algo::Ed25519,
                _ => {
                    warn!("DER parsing failed: unknown signature algo: {}", oid);
                    return None;
                }
            };


            Some(Self::from_public(key))

        } else {
            warn!("DER parsing failed: {:?}", res);
            None
        }
    }

    pub fn to_x509(&self) -> Result<
        (
            openssl::x509::X509,
            openssl::pkey::PKey<openssl::pkey::Private>,
            ),
            openssl::error::ErrorStack,
            > {
                use openssl::{asn1::Asn1Time,
                bn::{BigNum, MsbOption},
                hash::MessageDigest,
                pkey::PKey,
                x509::extension::{BasicConstraints, SubjectKeyIdentifier},
                x509::{X509, X509NameBuilder}};

                // header copied from 'openssl genpkey -algorithm ed25519'
                // there's actually no working API to generate an ed25519 into PKey from existing material directly
                let mut der = vec![
                    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
                    0x20,
                ];

                der.extend_from_slice(&self.secret);
                let privkey = PKey::private_key_from_der(&der)?;

                // this is the "Subject" as well as "Issuer" since we self sign
                let mut x509_name = X509NameBuilder::new()?;
                x509_name.append_entry_by_text("C", "US")?;
                x509_name.append_entry_by_text("ST", "TX")?;
                x509_name.append_entry_by_text("O", "organization")?;
                x509_name.append_entry_by_text("CN", "localhost")?;
                let x509_name = x509_name.build();

                let mut cert_builder = X509::builder()?;
                cert_builder.set_version(2)?;

                // make up a serial number
                let serial_number = {
                    let mut serial = BigNum::new()?;
                    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
                    serial.to_asn1_integer()?
                };
                cert_builder.set_serial_number(&serial_number)?;
                cert_builder.set_subject_name(&x509_name)?;
                cert_builder.set_issuer_name(&x509_name)?;
                cert_builder.set_pubkey(&privkey)?;
                let not_before = Asn1Time::days_from_now(0)?;
                cert_builder.set_not_before(&not_before)?;
                let not_after = Asn1Time::days_from_now(1)?;
                cert_builder.set_not_after(&not_after)?;

                cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
                // this is probably junk?
                let subject_key_identifier =
                    SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
                cert_builder.append_extension(subject_key_identifier)?;

                // self sign with the ed25519
                cert_builder.sign(&privkey, unsafe {
                    MessageDigest::from_ptr(std::ptr::null_mut())
                })?;
                let cert = cert_builder.build();

                Ok((cert, privkey))
            }
}
