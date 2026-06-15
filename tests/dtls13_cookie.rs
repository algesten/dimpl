#![cfg(feature = "rcgen")]

#[path = "dtls13/common.rs"]
mod common;

use std::sync::Arc;
use std::time::Instant;

use dimpl::certificate::generate_self_signed_certificate;
use dimpl::{Dtls, NamedGroup};

use crate::common::{drain_outputs, dtls13_config};

fn cookie_extensions_start(body: &[u8], msg_type: u8) -> Option<usize> {
    let mut pos = 0;
    match msg_type {
        0x01 => {
            pos += 2 + 32;
            let sid_len = *body.get(pos)? as usize;
            pos += 1 + sid_len;
            let cookie_len = *body.get(pos)? as usize;
            pos += 1 + cookie_len;
            let suites_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
            pos += 2 + suites_len;
            let compression_len = *body.get(pos)? as usize;
            pos += 1 + compression_len;
        }
        0x02 => {
            pos += 2 + 32;
            let sid_len = *body.get(pos)? as usize;
            pos += 1 + sid_len + 2 + 1;
        }
        _ => return None,
    }

    Some(pos)
}

fn shrink_dtls13_cookie_extension_inner_len(packet: &mut [u8]) -> bool {
    const RECORD_HEADER_LEN: usize = 13;
    const HANDSHAKE_HEADER_LEN: usize = 12;
    const COOKIE_EXTENSION: u16 = 0x002C;

    if packet.len() < RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN || packet[0] != 22 {
        return false;
    }

    let handshake = &mut packet[RECORD_HEADER_LEN..];
    let msg_type = handshake[0];
    let body_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
    if handshake.len() < HANDSHAKE_HEADER_LEN + body_len {
        return false;
    }

    let body = &mut handshake[HANDSHAKE_HEADER_LEN..HANDSHAKE_HEADER_LEN + body_len];
    let mut pos = match cookie_extensions_start(body, msg_type) {
        Some(pos) => pos,
        None => return false,
    };
    if body.len() < pos + 2 {
        return false;
    }

    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;
    if body.len() < extensions_end {
        return false;
    }

    while pos + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let extension_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let extension_body = pos + 4;
        let next = extension_body + extension_len;
        if next > extensions_end {
            return false;
        }

        if extension_type == COOKIE_EXTENSION && extension_len > 2 {
            let cookie_len = u16::from_be_bytes([body[extension_body], body[extension_body + 1]]);
            if cookie_len == 0 {
                return false;
            }
            body[extension_body..extension_body + 2]
                .copy_from_slice(&(cookie_len - 1).to_be_bytes());
            return true;
        }

        pos = next;
    }

    false
}

fn dtls13_hrr_extension_types(packet: &[u8]) -> Option<Vec<u16>> {
    const RECORD_HEADER_LEN: usize = 13;
    const HANDSHAKE_HEADER_LEN: usize = 12;

    if packet.len() < RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN || packet[0] != 22 {
        return None;
    }

    let handshake = &packet[RECORD_HEADER_LEN..];
    let msg_type = handshake[0];
    let body_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
    if handshake.len() < HANDSHAKE_HEADER_LEN + body_len {
        return None;
    }

    let body = &handshake[HANDSHAKE_HEADER_LEN..HANDSHAKE_HEADER_LEN + body_len];
    let mut pos = cookie_extensions_start(body, msg_type)?;
    if body.len() < pos + 2 {
        return None;
    }

    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;
    if body.len() < extensions_end {
        return None;
    }

    let mut extensions = Vec::new();
    while pos + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let extension_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4 + extension_len;
        if pos > extensions_end {
            return None;
        }
        extensions.push(extension_type);
    }

    Some(extensions)
}

fn insert_dtls13_hrr_key_share_before_cookie(packet: &mut Vec<u8>, selected_group: u16) -> bool {
    const RECORD_HEADER_LEN: usize = 13;
    const HANDSHAKE_HEADER_LEN: usize = 12;
    const KEY_SHARE_EXTENSION: u16 = 0x0033;
    const COOKIE_EXTENSION: u16 = 0x002C;

    if packet.len() < RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN || packet[0] != 22 {
        return false;
    }

    let handshake_start = RECORD_HEADER_LEN;
    let body_start = handshake_start + HANDSHAKE_HEADER_LEN;
    let body_len = ((packet[handshake_start + 1] as usize) << 16)
        | ((packet[handshake_start + 2] as usize) << 8)
        | packet[handshake_start + 3] as usize;
    if packet.len() < body_start + body_len {
        return false;
    }

    let body = &packet[body_start..body_start + body_len];
    let mut pos = match cookie_extensions_start(body, packet[handshake_start]) {
        Some(pos) => body_start + pos,
        None => return false,
    };
    if packet.len() < pos + 2 {
        return false;
    }

    let extensions_len = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
    let extensions_len_pos = pos;
    pos += 2;
    let extensions_end = pos + extensions_len;
    if packet.len() < extensions_end {
        return false;
    }

    while pos + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let extension_len = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]) as usize;
        let next = pos + 4 + extension_len;
        if next > extensions_end {
            return false;
        }

        if extension_type == KEY_SHARE_EXTENSION {
            return true;
        }

        if extension_type == COOKIE_EXTENSION {
            let key_share = [
                (KEY_SHARE_EXTENSION >> 8) as u8,
                KEY_SHARE_EXTENSION as u8,
                0,
                2,
                (selected_group >> 8) as u8,
                selected_group as u8,
            ];
            packet.splice(pos..pos, key_share);

            let new_extensions_len = extensions_len + key_share.len();
            packet[extensions_len_pos..extensions_len_pos + 2]
                .copy_from_slice(&(new_extensions_len as u16).to_be_bytes());

            let new_body_len = body_len + key_share.len();
            packet[handshake_start + 1] = ((new_body_len >> 16) & 0xff) as u8;
            packet[handshake_start + 2] = ((new_body_len >> 8) & 0xff) as u8;
            packet[handshake_start + 3] = (new_body_len & 0xff) as u8;
            packet[handshake_start + 9] = ((new_body_len >> 16) & 0xff) as u8;
            packet[handshake_start + 10] = ((new_body_len >> 8) & 0xff) as u8;
            packet[handshake_start + 11] = (new_body_len & 0xff) as u8;

            let new_record_len = HANDSHAKE_HEADER_LEN + new_body_len;
            packet[11..13].copy_from_slice(&(new_record_len as u16).to_be_bytes());
            return true;
        }

        pos = next;
    }

    false
}

#[test]
fn dtls13_client_rejects_hrr_cookie_extension_trailing_bytes() {
    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let config = dtls13_config();
    let now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    assert!(!client_out.packets.is_empty(), "client should send CH1");
    for packet in &client_out.packets {
        server.handle_packet(packet).expect("server receives CH1");
    }

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    let mut hrr = server_out
        .packets
        .into_iter()
        .next()
        .expect("server should emit HRR");
    assert!(
        insert_dtls13_hrr_key_share_before_cookie(&mut hrr, NamedGroup::X25519.as_u16()),
        "fixture should insert HRR KeyShare before Cookie"
    );
    let mut malformed_hrr = hrr.clone();
    let hrr_extensions = dtls13_hrr_extension_types(&hrr).expect("parse HRR extensions");
    let key_share_index = hrr_extensions
        .iter()
        .position(|ext| *ext == 0x0033)
        .expect("HRR should contain KeyShare");
    let cookie_index = hrr_extensions
        .iter()
        .position(|ext| *ext == 0x002C)
        .expect("HRR should contain Cookie");
    assert!(
        key_share_index < cookie_index,
        "fixture must parse KeyShare before rejecting malformed Cookie"
    );
    assert!(
        shrink_dtls13_cookie_extension_inner_len(&mut malformed_hrr),
        "fixture should contain a Cookie extension"
    );

    client
        .handle_packet(&malformed_hrr)
        .expect("malformed HRR Cookie extension should be discarded");

    client
        .handle_timeout(now)
        .expect("client timeout after error");
    let client_out = drain_outputs(&mut client);
    assert!(
        client_out.packets.is_empty(),
        "client must not send CH2 after malformed HRR Cookie"
    );

    client
        .handle_packet(&hrr)
        .expect("clean HRR retransmission should be accepted");
    client
        .handle_timeout(now)
        .expect("client timeout after clean HRR");
    let client_out = drain_outputs(&mut client);
    assert!(
        !client_out.packets.is_empty(),
        "client should send CH2 after clean HRR retransmission"
    );
}

#[test]
fn dtls13_server_rejects_clienthello_cookie_extension_trailing_bytes() {
    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let config = dtls13_config();
    let now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    for packet in &client_out.packets {
        server.handle_packet(packet).expect("server receives CH1");
    }

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    let hrr = server_out
        .packets
        .first()
        .expect("server should emit HRR")
        .clone();
    client
        .handle_packet(&hrr)
        .expect("client receives valid HRR");

    client
        .handle_timeout(now)
        .expect("client timeout after HRR");
    let client_out = drain_outputs(&mut client);
    let mut ch2 = client_out
        .packets
        .into_iter()
        .next()
        .expect("client should emit CH2 with cookie");
    assert!(
        shrink_dtls13_cookie_extension_inner_len(&mut ch2),
        "fixture should contain a Cookie extension"
    );

    server
        .handle_packet(&ch2)
        .expect("malformed ClientHello Cookie extension should be discarded");
}
