//! Shared handshake driver for SRTP configuration tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::certificate::generate_self_signed_certificate;
use dimpl::{Config, Dtls, DtlsCertificate, SrtpProfile};

use crate::common::{DrainedOutputs, drain_outputs};

pub type Constructor = fn(Arc<Config>, DtlsCertificate, Instant) -> Dtls;

pub const SRTP_PROFILE_CASES: [([SrtpProfile; 3], [SrtpProfile; 2], SrtpProfile); 3] = {
    use SrtpProfile::{AEAD_AES_128_GCM, AEAD_AES_256_GCM, AES128_CM_SHA1_80};

    [
        (
            [AEAD_AES_128_GCM, AEAD_AES_256_GCM, AES128_CM_SHA1_80],
            [AES128_CM_SHA1_80, AEAD_AES_256_GCM],
            AEAD_AES_256_GCM,
        ),
        (
            [AEAD_AES_128_GCM, AES128_CM_SHA1_80, AEAD_AES_256_GCM],
            [AEAD_AES_256_GCM, AES128_CM_SHA1_80],
            AES128_CM_SHA1_80,
        ),
        (
            [AEAD_AES_256_GCM, AES128_CM_SHA1_80, AEAD_AES_128_GCM],
            [AEAD_AES_128_GCM, AES128_CM_SHA1_80],
            AES128_CM_SHA1_80,
        ),
    ]
};

pub fn handshake_with_srtp(
    client_new: Constructor,
    server_new: Constructor,
    client_profiles: Option<&[SrtpProfile]>,
    server_profiles: Option<&[SrtpProfile]>,
    cookie: bool,
) -> (DrainedOutputs, DrainedOutputs) {
    let mut now = Instant::now();
    let client_cert = generate_self_signed_certificate().expect("client certificate");
    let server_cert = generate_self_signed_certificate().expect("server certificate");
    let mut client = client_new(config(client_profiles, cookie), client_cert, now);
    let mut server = server_new(config(server_profiles, cookie), server_cert, now);
    client.set_active(true);
    server.set_active(false);
    let mut client_state = DrainedOutputs::default();
    let mut server_state = DrainedOutputs::default();
    let mut client_packets = Vec::new();
    let mut server_packets = Vec::new();

    for _ in 0..100 {
        client.handle_timeout(now).expect("client timeout");
        client_packets.extend(collect(&mut client, &mut client_state));
        server.handle_timeout(now).expect("server timeout");
        server_packets.extend(collect(&mut server, &mut server_state));
        for packet in client_packets.drain(..) {
            server
                .handle_packet(&packet)
                .expect("server receives packet");
            server_packets.extend(collect(&mut server, &mut server_state));
        }
        for packet in server_packets.drain(..) {
            client
                .handle_packet(&packet)
                .expect("client receives packet");
            client_packets.extend(collect(&mut client, &mut client_state));
        }
        if client_state.connected && server_state.connected {
            return (client_state, server_state);
        }
        now += Duration::from_millis(10);
    }
    panic!("SRTP-configured handshake did not complete");
}

fn config(profiles: Option<&[SrtpProfile]>, cookie: bool) -> Arc<Config> {
    let mut builder = Config::builder().use_server_cookie(cookie);
    if let Some(profiles) = profiles {
        builder = builder.srtp_profiles(profiles);
    }
    Arc::new(builder.build().expect("SRTP config"))
}

fn collect(endpoint: &mut Dtls, state: &mut DrainedOutputs) -> Vec<Vec<u8>> {
    let output = drain_outputs(endpoint);
    state.connected |= output.connected;
    if let Some(keying_material) = output.keying_material {
        state.keying_material = Some(keying_material);
    }
    output.packets
}
