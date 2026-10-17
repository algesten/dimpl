#![cfg(feature = "rcgen")]

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dimpl::certificate::generate_self_signed_certificate;
use dimpl::{Config, Dtls};

#[path = "dtls13/common.rs"]
mod common;
use common::drain_outputs;

#[test]
fn corrected_client_hello_completes_after_malformed_extension() {
    let constructors = [Dtls::new_12, Dtls::new_13, Dtls::new_auto];
    let certificate = generate_self_signed_certificate().expect("certificate");
    let config = Arc::new(
        Config::builder()
            .use_server_cookie(false)
            .build()
            .expect("config"),
    );
    for (client_version, server_version) in [(0, 0), (1, 1), (0, 2), (1, 2), (2, 0), (2, 1), (2, 2)]
    {
        for kind in [10u16, 13, 14] {
            for fragmented in [false, true] {
                let now = Instant::now();
                let mut client =
                    constructors[client_version](config.clone(), certificate.clone(), now);
                let mut server =
                    constructors[server_version](config.clone(), certificate.clone(), now);
                client.set_active(true);
                client.handle_timeout(now).expect("client clock");
                let hello = drain_outputs(&mut client).packets;
                assert_eq!(hello.len(), 1);
                server.handle_timeout(now).expect("server clock");
                drain_outputs(&mut server);
                let mut malformed = hello[0].clone();
                // Record (13), handshake (12), version (2), random (32).
                let mut cursor = 59;
                cursor += 1 + malformed[cursor] as usize; // session id
                cursor += 1 + malformed[cursor] as usize; // cookie
                cursor +=
                    2 + u16::from_be_bytes([malformed[cursor], malformed[cursor + 1]]) as usize;
                cursor += 1 + malformed[cursor] as usize; // compression
                cursor += 2; // extensions length
                loop {
                    let extension = u16::from_be_bytes([malformed[cursor], malformed[cursor + 1]]);
                    let len =
                        u16::from_be_bytes([malformed[cursor + 2], malformed[cursor + 3]]) as usize;
                    if extension == kind {
                        malformed[cursor + 4] = 0xff;
                        break;
                    }
                    cursor += 4 + len;
                }
                let chunk = if fragmented {
                    (malformed.len() - 25).div_ceil(2)
                } else {
                    malformed.len() - 25
                };
                for (index, body) in malformed[25..].chunks(chunk).enumerate() {
                    let mut fragment = malformed[..25].to_vec();
                    fragment.extend_from_slice(body);
                    fragment[5..11].copy_from_slice(&(index as u64).to_be_bytes()[2..]);
                    fragment[11..13].copy_from_slice(&((12 + body.len()) as u16).to_be_bytes());
                    fragment[19..22].copy_from_slice(&((index * chunk) as u32).to_be_bytes()[1..]);
                    fragment[22..25].copy_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
                    server
                        .handle_packet(&fragment)
                        .expect("discard malformed hello");
                    assert!(drain_outputs(&mut server).packets.is_empty());
                }
                server.handle_packet(&hello[0]).expect("corrected hello");
                let mut connected = [false; 2];
                let mut pending = VecDeque::new();
                let output = drain_outputs(&mut server);
                connected[1] |= output.connected;
                pending.extend(output.packets.into_iter().map(|packet| (0, packet)));
                for _ in 0..100 {
                    let Some((recipient, packet)) = pending.pop_front() else {
                        break;
                    };
                    let target = if recipient == 0 {
                        &mut client
                    } else {
                        &mut server
                    };
                    target.handle_packet(&packet).expect("handshake packet");
                    let output = drain_outputs(target);
                    connected[recipient] |= output.connected;
                    pending.extend(
                        output
                            .packets
                            .into_iter()
                            .map(|packet| (1 - recipient, packet)),
                    );
                }
                assert_eq!(
                    connected,
                    [true, true],
                    "{client_version}->{server_version}, extension {kind}, fragmented={fragmented}"
                );
            }
        }
    }
}
