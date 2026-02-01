#![allow(unused)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls, Output};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecHdr {
    ctype: u8,
    epoch: u16,
    seq: u64,
}

fn parse_records(datagram: &[u8]) -> Vec<RecHdr> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 13 <= datagram.len() {
        let ctype = datagram[i];
        let epoch = u16::from_be_bytes([datagram[i + 3], datagram[i + 4]]);
        let seq_bytes = [
            0u8,
            0u8,
            datagram[i + 5],
            datagram[i + 6],
            datagram[i + 7],
            datagram[i + 8],
            datagram[i + 9],
            datagram[i + 10],
        ];
        let seq = u64::from_be_bytes(seq_bytes);
        let len = u16::from_be_bytes([datagram[i + 11], datagram[i + 12]]) as usize;
        out.push(RecHdr { ctype, epoch, seq });
        i += 13 + len;
    }
    out
}

fn collect_flight_packets(endpoint: &mut Dtls) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 2048];
    loop {
        match endpoint.poll_output(&mut buf) {
            Output::Packet(p) => out.push(p.to_vec()),
            Output::Timeout(_) => break,
            _ => {}
        }
    }
    out
}

fn collect_headers(datagrams: &[Vec<u8>]) -> Vec<RecHdr> {
    datagrams.iter().flat_map(|d| parse_records(d)).collect()
}

fn assert_epochs_and_seq_increased(init: &[RecHdr], resend: &[RecHdr]) {
    assert_eq!(
        init.len(),
        resend.len(),
        "record count must match between initial and resend"
    );
    for (a, b) in init.iter().zip(resend.iter()) {
        assert_eq!(
            a.epoch, b.epoch,
            "epoch must match for the same record on resend"
        );
        assert!(
            b.seq > a.seq,
            "sequence must increase on resend: {:?} -> {:?}",
            a,
            b
        );
    }
}

fn trigger_resend(ep: &mut Dtls, now: &mut Instant) {
    *now += Duration::from_secs(2);
    ep.handle_timeout(*now).expect("handle_timeout");
}

#[test]
#[cfg(feature = "rcgen")]
fn duplicate_triggers_server_resend_of_final_flight() {
    // Use a small MTU to make record packing simple and deterministic.
    let now0 = Instant::now();
    let mut now = now0;

    use dimpl::certificate::generate_self_signed_certificate;

    // Certificates for client and server
    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config_client = Arc::new(
        Config::builder()
            .mtu(115) // modestly small but enough to keep flights split
            .build()
            .expect("Failed to build config"),
    );
    let config_server = Arc::new(
        Config::builder()
            .mtu(115) // modestly small but enough to keep flights split
            .build()
            .expect("Failed to build config"),
    );

    // Client
    let mut client = Dtls::new(config_client, client_cert.clone(), now);
    client.set_active(true);

    // Server
    let mut server = Dtls::new(config_server, server_cert.clone(), now);
    server.set_active(false);

    // FLIGHT 1 (ClientHello)
    client.handle_timeout(now).expect("client timeout start");
    client.handle_timeout(now).expect("client arm flight 1");
    let f1 = collect_flight_packets(&mut client);
    for p in f1 {
        server.handle_packet(&p).expect("server recv f1");
    }

    // FLIGHT 2 (HelloVerifyRequest)
    server.handle_timeout(now).expect("server arm flight 2");
    let f2 = collect_flight_packets(&mut server);
    assert!(!f2.is_empty(), "server should emit flight 2 after CH");
    for p in f2 {
        client.handle_packet(&p).expect("client recv f2");
    }

    // FLIGHT 3 (ClientHello with cookie)
    client.handle_timeout(now).expect("client arm flight 3");
    let f3 = collect_flight_packets(&mut client);
    assert!(!f3.is_empty(), "client should emit flight 3 after HVR");
    for p in f3 {
        server.handle_packet(&p).expect("server recv f3");
    }

    // FLIGHT 4 (ServerHello, Certificate, ... , ServerHelloDone)
    server.handle_timeout(now).expect("server arm flight 4");
    let f4 = collect_flight_packets(&mut server);
    assert!(
        !f4.is_empty(),
        "server should emit flight 4 after CH+cookie"
    );
    for p in f4 {
        client.handle_packet(&p).expect("client recv f4");
    }

    // FLIGHT 5 (Client cert?, CKX, CV?, CCS, Finished)
    client.handle_timeout(now).expect("client arm flight 5");
    let f5_init = collect_flight_packets(&mut client);
    assert!(
        !f5_init.is_empty(),
        "client should emit flight 5 after server flight"
    );
    for p in &f5_init {
        server.handle_packet(p).expect("server recv f5");
    }

    // Server should send FLIGHT 6 (CCS, Finished) exactly once initially.
    server.handle_timeout(now).expect("server arm flight 6");
    let f6_init = collect_flight_packets(&mut server);
    assert!(!f6_init.is_empty(), "server should emit initial flight 6");
    let f6_init_hdrs = collect_headers(&f6_init);
    assert!(
        f6_init_hdrs.iter().any(|h| h.ctype == 22 && h.epoch == 1),
        "server flight 6 should include epoch 1 Finished"
    );

    // IMPORTANT PART: Trigger a client resend of flight 5 (duplicate Finished)
    // and deliver to the server. The server has its timer stopped after flight 6,
    // so this resend must be caused by duplicate-handshake processing.
    trigger_resend(&mut client, &mut now);
    let f5_resend = collect_flight_packets(&mut client);
    assert!(
        !f5_resend.is_empty(),
        "client should resend flight 5 on its timer"
    );
    for p in &f5_resend {
        server.handle_packet(p).expect("server recv f5 resend");
    }

    // The server should resend its final flight in response to the duplicate.
    let f6_resend = collect_flight_packets(&mut server);
    assert!(
        !f6_resend.is_empty(),
        "server should resend flight 6 upon receiving duplicate Finished"
    );
    let f6_resend_hdrs = collect_headers(&f6_resend);
    assert!(
        f6_resend_hdrs.iter().any(|h| h.ctype == 22 && h.epoch == 1),
        "resend flight 6 should include epoch 1 Finished"
    );

    // Epochs must match and sequence numbers must increase on resend.
    assert_epochs_and_seq_increased(&f6_init_hdrs, &f6_resend_hdrs);
}
