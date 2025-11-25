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
fn resends_each_flight_epoch_and_sequence_increase() {
    let now0 = Instant::now();
    let mut now = now0;

    use dimpl::certificate::generate_self_signed_certificate;

    // Certificates for client and server
    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config_client = Arc::new(Config::default());
    let config_server = Arc::new(Config::default());

    // Client
    let mut client = Dtls::new(
        config_client,
        client_cert.certificate.clone(),
        client_cert.private_key.clone(),
    );
    client.set_active(true);

    // Server
    let mut server = Dtls::new(
        config_server,
        server_cert.certificate.clone(),
        server_cert.private_key.clone(),
    );
    server.set_active(false);

    // FLIGHT 1 (ClientHello): block initial, deliver resend
    client.handle_timeout(now).expect("client timeout start");
    // flight_begin reset the flight timer; arm it again so poll_output yields packets
    client.handle_timeout(now).expect("client arm flight 1");
    let init1_pkts = collect_flight_packets(&mut client);
    let init1_hdrs = collect_headers(&init1_pkts);
    trigger_resend(&mut client, &mut now);
    let resend1_pkts = collect_flight_packets(&mut client);
    let resend1_hdrs = collect_headers(&resend1_pkts);
    assert_epochs_and_seq_increased(&init1_hdrs, &resend1_hdrs);
    for p in resend1_pkts {
        server.handle_packet(&p).expect("server recv f1");
    }

    // FLIGHT 2 (HelloVerifyRequest): capture initial from server, block, deliver resend
    server.handle_timeout(now).expect("server arm flight 2");
    let init2_pkts = collect_flight_packets(&mut server);
    assert!(
        !init2_pkts.is_empty(),
        "server should emit flight 2 after CH"
    );
    let init2_hdrs = collect_headers(&init2_pkts);
    trigger_resend(&mut server, &mut now);
    let resend2_pkts = collect_flight_packets(&mut server);
    let resend2_hdrs = collect_headers(&resend2_pkts);
    assert_epochs_and_seq_increased(&init2_hdrs, &resend2_hdrs);
    for p in resend2_pkts {
        client.handle_packet(&p).expect("client recv f2");
    }

    // FLIGHT 3 (ClientHello with cookie): block initial, deliver resend
    client.handle_timeout(now).expect("client arm flight 3");
    let init3_pkts = collect_flight_packets(&mut client);
    assert!(
        !init3_pkts.is_empty(),
        "client should emit flight 3 after HVR"
    );
    let init3_hdrs = collect_headers(&init3_pkts);
    trigger_resend(&mut client, &mut now);
    let resend3_pkts = collect_flight_packets(&mut client);
    let resend3_hdrs = collect_headers(&resend3_pkts);
    assert_epochs_and_seq_increased(&init3_hdrs, &resend3_hdrs);
    for p in resend3_pkts {
        server.handle_packet(&p).expect("server recv f3");
    }

    // FLIGHT 4 (ServerHello, Certificate, SKE, CR, SHD): block initial, deliver resend
    server.handle_timeout(now).expect("server arm flight 4");
    let init4_pkts = collect_flight_packets(&mut server);
    assert!(
        !init4_pkts.is_empty(),
        "server should emit flight 4 after CH+cookie"
    );
    let init4_hdrs = collect_headers(&init4_pkts);
    trigger_resend(&mut server, &mut now);
    let resend4_pkts = collect_flight_packets(&mut server);
    let resend4_hdrs = collect_headers(&resend4_pkts);
    assert_epochs_and_seq_increased(&init4_hdrs, &resend4_hdrs);
    for p in resend4_pkts {
        client.handle_packet(&p).expect("client recv f4");
    }

    // FLIGHT 5 (Client cert?, CKX, CV?, CCS, Finished): block initial, deliver resend
    client.handle_timeout(now).expect("client arm flight 5");
    let init5_pkts = collect_flight_packets(&mut client);
    assert!(
        !init5_pkts.is_empty(),
        "client should emit flight 5 after server flight"
    );
    let init5_hdrs = collect_headers(&init5_pkts);
    trigger_resend(&mut client, &mut now);
    let resend5_pkts = collect_flight_packets(&mut client);
    let resend5_hdrs = collect_headers(&resend5_pkts);
    assert_epochs_and_seq_increased(&init5_hdrs, &resend5_hdrs);
    // Additionally, ensure Finished is epoch 1 is present in the set
    assert!(
        resend5_hdrs.iter().any(|h| h.ctype == 22 && h.epoch == 1),
        "client flight 5 should include epoch 1 Finished"
    );
    for p in resend5_pkts {
        server.handle_packet(&p).expect("server recv f5");
    }

    // FLIGHT 6 (Server CCS, Finished): no resend timer after final flight
    server.handle_timeout(now).expect("server arm flight 6");
    let init6_pkts = collect_flight_packets(&mut server);
    assert!(
        !init6_pkts.is_empty(),
        "server should emit flight 6 after client flight 5"
    );
    let init6_hdrs = collect_headers(&init6_pkts);
    // Final flight should include epoch 1 Finished in the initial transmission
    assert!(
        init6_hdrs.iter().any(|h| h.ctype == 22 && h.epoch == 1),
        "server flight 6 should include epoch 1 Finished"
    );
    // Ensure no timer-driven resend occurs after final flight
    trigger_resend(&mut server, &mut now);
    let resend6_pkts = collect_flight_packets(&mut server);
    assert!(resend6_pkts.is_empty(), "no resend after final flight");
}
