//! Shared outbound ClientHello construction for explicit and auto-sense clients.

use arrayvec::ArrayVec;

use crate::Config;
use crate::buffer::Buf;
use crate::dtls12::message::ECPointFormatsExtension;
use crate::dtls12::message::SignatureAlgorithmsExtension as SignatureAlgorithms12;
use crate::dtls12::message::SupportedGroupsExtension as SupportedGroups12;
use crate::dtls12::message::UseSrtpExtension as UseSrtp12;
use crate::dtls13::message::{
    ExtensionType, KeyShareClientHello, KeyShareEntry, SupportedVersionsClientHello,
};
use crate::dtls13::message::{
    SignatureAlgorithmsExtension, SupportedGroupsExtension, UseSrtpExtension,
};
use crate::types::{NamedGroup, ProtocolVersion, Random};

/// Builds an offer from configuration and live handshake state, including retries.
pub struct ClientHelloBuilder<'a> {
    config: &'a Config,
    random: Random,
    offer: Offer,
    cipher_suites: ArrayVec<u16, 16>,
    session_id: &'a [u8],
    legacy_cookie: &'a [u8],
    key_share: Option<(NamedGroup, &'a [u8])>,
    retry_cookie: Option<&'a [u8]>,
}

/// The original offer remains fixed when auto-sense selects a protocol version.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    Dtls12,
    Dtls13,
    Hybrid,
}

impl<'a> ClientHelloBuilder<'a> {
    pub fn new(config: &'a Config, random: Random, offer: Offer) -> Self {
        let mut cipher_suites = ArrayVec::new();
        if offer != Offer::Dtls12 {
            cipher_suites.extend(config.dtls13_cipher_suites().map(|cs| cs.suite().as_u16()));
        }
        if offer != Offer::Dtls13 {
            // Auto fallback is certificate-only and cannot negotiate PSK suites.
            cipher_suites.extend(
                config
                    .dtls12_cipher_suites()
                    .filter(|cs| offer != Offer::Hybrid || !cs.suite().is_psk())
                    .map(|cs| cs.suite().as_u16()),
            );
        }
        Self {
            config,
            random,
            offer,
            cipher_suites,
            session_id: &[],
            legacy_cookie: &[],
            key_share: None,
            retry_cookie: None,
        }
    }

    pub fn cipher_suites(mut self, suites: impl Iterator<Item = u16>) -> Self {
        self.cipher_suites.clear();
        self.cipher_suites.extend(suites);
        self
    }

    pub fn session_id(mut self, session_id: &'a [u8]) -> Self {
        self.session_id = session_id;
        self
    }

    pub fn legacy_cookie(mut self, cookie: &'a [u8]) -> Self {
        self.legacy_cookie = cookie;
        self
    }

    pub fn key_share(mut self, group: NamedGroup, public_key: &'a [u8]) -> Self {
        self.key_share = Some((group, public_key));
        self
    }

    /// The saved HRR cookie includes its two-byte length prefix.
    pub fn retry_cookie(mut self, cookie: Option<&'a [u8]>) -> Self {
        self.retry_cookie = cookie;
        self
    }

    pub fn serialize(self, body: &mut Buf) {
        debug!(
            "Sending ClientHello: cookie_len={}, offering {} cipher suites",
            self.legacy_cookie.len(),
            self.cipher_suites.len()
        );
        let start = body.len();
        body.extend_from_slice(&0xFEFDu16.to_be_bytes());
        self.random.serialize(body);
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(self.session_id);
        body.push(self.legacy_cookie.len() as u8);
        body.extend_from_slice(self.legacy_cookie);
        body.extend_from_slice(&((self.cipher_suites.len() * 2) as u16).to_be_bytes());
        for suite in &self.cipher_suites {
            body.extend_from_slice(&suite.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]); // one compression method: null

        let extensions_len = body.len();
        body.extend_from_slice(&[0, 0]);
        // A key share identifies the 1.3-capable flight. After HVR we retain the
        // hybrid cipher suites but omit 1.3 extensions and send a legacy cookie.
        let dtls13 = self.key_share.is_some();
        if dtls13 {
            assert!(self.legacy_cookie.is_empty());
            extension(body, ExtensionType::SupportedVersions, |out| {
                let mut versions = ArrayVec::new();
                versions.push(ProtocolVersion::DTLS1_3);
                if self.offer == Offer::Hybrid {
                    versions.push(ProtocolVersion::DTLS1_2);
                }
                SupportedVersionsClientHello { versions }.serialize(out);
            });
        }
        if self.config.crypto_provider().has_ecdh() {
            extension(body, ExtensionType::SupportedGroups, |out| {
                let groups = self.config.kx_groups().map(|group| group.name()).collect();
                if self.offer == Offer::Dtls12 {
                    SupportedGroups12 { groups }.serialize(out);
                } else {
                    SupportedGroupsExtension { groups }.serialize(out);
                }
            });
            if !dtls13 {
                extension(body, ExtensionType::EcPointFormats, |out| {
                    ECPointFormatsExtension::default().serialize(out)
                });
            }
        }
        if let Some((group, public_key)) = self.key_share {
            extension(body, ExtensionType::KeyShare, |out| {
                let mut entries = ArrayVec::new();
                entries.push(KeyShareEntry {
                    group,
                    key_exchange_range: 0..public_key.len(),
                });
                KeyShareClientHello { entries }.serialize(public_key, out);
            });
        }
        extension(body, ExtensionType::SignatureAlgorithms, |out| {
            if self.offer == Offer::Dtls12 {
                SignatureAlgorithms12::default().serialize(out);
            } else {
                SignatureAlgorithmsExtension::default().serialize(out);
            }
        });
        extension(body, ExtensionType::UseSrtp, |out| {
            if self.offer == Offer::Dtls12 {
                UseSrtp12::default().serialize(out);
            } else {
                UseSrtpExtension::default().serialize(out);
            }
        });
        if self.offer != Offer::Dtls13 {
            if dtls13 {
                extension(body, ExtensionType::EcPointFormats, |out| {
                    ECPointFormatsExtension::default().serialize(out)
                });
            }
            extension(body, ExtensionType::ExtendedMasterSecret, |_| {}); // extended_master_secret
            if self.offer == Offer::Hybrid {
                extension(body, ExtensionType::RenegotiationInfo, |out| out.push(0)); // renegotiation_info
            }
        }
        if let Some(cookie) = self.retry_cookie {
            assert!(dtls13);
            extension(body, ExtensionType::Cookie, |out| {
                out.extend_from_slice(cookie)
            });
        }
        if dtls13 {
            // Pad to the MTU, accounting for record and handshake headers.
            let deficit = self.config.mtu().saturating_sub(25 + body.len() - start);
            if deficit >= 4 {
                extension(body, ExtensionType::Padding, |out| {
                    out.resize(out.len() + deficit - 4, 0)
                });
            }
        }
        let len = (body.len() - extensions_len - 2) as u16;
        body[extensions_len..extensions_len + 2].copy_from_slice(&len.to_be_bytes());
    }
}

fn extension(body: &mut Buf, kind: ExtensionType, write: impl FnOnce(&mut Buf)) {
    body.extend_from_slice(&kind.as_u16().to_be_bytes());
    let length_pos = body.len();
    body.extend_from_slice(&[0, 0]);
    write(body);
    let len = (body.len() - length_pos - 2) as u16;
    body[length_pos..length_pos + 2].copy_from_slice(&len.to_be_bytes());
}
