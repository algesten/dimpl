#![cfg(feature = "rcgen")]

use std::mem;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::certificate::generate_self_signed_certificate;
use dimpl::{Config, Dtls, DtlsCertificate, Error, Output, ProtocolVersion, TimeoutError};

#[path = "dtls13/common.rs"]
mod common;

use common::{DrainedOutputs, drain_outputs};

const VERSIONS: &[Version] = &[Version::Dtls12, Version::Dtls13, Version::Auto];
const BUDGET: Duration = Duration::from_millis(100);
const PAIRS: &[(Version, Version)] = &[
    (Version::Dtls12, Version::Dtls12),
    (Version::Dtls13, Version::Dtls13),
    (Version::Auto, Version::Dtls12),
    (Version::Auto, Version::Dtls13),
    (Version::Dtls12, Version::Auto),
    (Version::Dtls13, Version::Auto),
    (Version::Auto, Version::Auto),
];

#[derive(Clone, Copy, Debug)]
enum Version {
    Dtls12,
    Dtls13,
    Auto,
}

impl Version {
    fn endpoint(self, config: Arc<Config>, certificate: DtlsCertificate, now: Instant) -> Dtls {
        match self {
            Self::Dtls12 => Dtls::new_12(config, certificate, now),
            Self::Dtls13 => Dtls::new_13(config, certificate, now),
            Self::Auto => Dtls::new_auto(config, certificate, now),
        }
    }
}

/// Short overall budget, with retries far enough out not to interfere.
fn config() -> Arc<Config> {
    Arc::new(
        Config::builder()
            .dangerously_set_rng_seed(42)
            .handshake_timeout(BUDGET)
            .flight_start_rto(Duration::from_secs(1))
            .flight_retries(0)
            .build()
            .expect("valid timing config"),
    )
}

fn retry_config(retries: usize, use_cookie: bool) -> Arc<Config> {
    Arc::new(
        Config::builder()
            .dangerously_set_rng_seed(42)
            .use_server_cookie(use_cookie)
            .handshake_timeout(Duration::from_secs(3600))
            .flight_start_rto(Duration::from_millis(20))
            .flight_retries(retries)
            .build()
            .expect("valid retry config"),
    )
}

/// Behave like an event loop at a single instant: tick while a due timeout is advertised.
fn settle(endpoint: &mut Dtls, now: Instant) -> (Vec<Vec<u8>>, Instant) {
    let mut packets = Vec::new();
    for _ in 0..10 {
        let output = drain_outputs(endpoint);
        packets.extend(output.packets);
        let deadline = output.timeout.expect("polled timeout");
        if deadline > now {
            return (packets, deadline);
        }
        endpoint.handle_timeout(now).expect("tick");
    }
    panic!("timers did not settle");
}

fn client_hello(version: Version, config: Arc<Config>, now: Instant) -> Vec<Vec<u8>> {
    let certificate = generate_self_signed_certificate().expect("certificate");
    let mut client = version.endpoint(config, certificate, now);
    client.set_active(true);
    settle(&mut client, now).0
}

fn merge_output(received: &mut DrainedOutputs, output: DrainedOutputs) {
    received.connected |= output.connected;
    received.app_data.extend(output.app_data);
    received.packets.extend(output.packets);
    received.timeout = output.timeout;
}

fn deliver_queued(source: &mut DrainedOutputs, target: &mut Dtls, received: &mut DrainedOutputs) {
    for packet in mem::take(&mut source.packets) {
        target.handle_packet(&packet).expect("deliver packet");
        merge_output(received, drain_outputs(target));
    }
}

fn exchange(
    client: &mut Dtls,
    server: &mut Dtls,
    now: Instant,
) -> (DrainedOutputs, DrainedOutputs) {
    let mut client_output = drain_outputs(client);
    let mut server_output = drain_outputs(server);
    for _ in 0..100 {
        deliver_queued(&mut client_output, server, &mut server_output);
        deliver_queued(&mut server_output, client, &mut client_output);
        client.handle_timeout(now).expect("client pending progress");
        merge_output(&mut client_output, drain_outputs(client));
        server.handle_timeout(now).expect("server pending progress");
        merge_output(&mut server_output, drain_outputs(server));
        if client_output.packets.is_empty() && server_output.packets.is_empty() {
            return (client_output, server_output);
        }
    }
    panic!("packet exchange did not settle");
}

#[test]
fn clients_start_deadline_at_first_emission() {
    let base = Instant::now();
    let certificate = generate_self_signed_certificate().expect("certificate");
    for &version in VERSIONS {
        let mut client = version.endpoint(config(), certificate.clone(), base);
        let late = base + Duration::from_secs(60);
        client.set_active(true);
        let (packets, deadline) = settle(&mut client, late);
        assert!(!packets.is_empty(), "{version:?}");
        assert_eq!(deadline, late + BUDGET, "{version:?}");
        assert_eq!(
            client.handle_timeout(deadline),
            Err(Error::Timeout(TimeoutError::Connect))
        );
    }
}

/// An idle server advertises no timeout, so a caller may hand it a packet
/// without refreshing the clock. Its deadline must start from the next tick.
#[test]
fn idle_server_starts_deadline_from_fresh_clock() {
    let base = Instant::now();
    let certificate = generate_self_signed_certificate().expect("certificate");
    for &version in VERSIONS {
        let mut server = version.endpoint(config(), certificate.clone(), base);
        server.handle_timeout(base).expect("server clock");
        let arrival = base + Duration::from_secs(3600);
        assert!(
            drain_outputs(&mut server).timeout.expect("idle deadline") > arrival,
            "idle server must not wake"
        );

        for packet in client_hello(version, config(), arrival) {
            server.handle_packet(&packet).expect("ClientHello");
        }
        let (response, deadline) = settle(&mut server, arrival);
        assert!(!response.is_empty(), "{version:?}");
        assert_eq!(deadline, arrival + BUDGET, "{version:?}");
        assert_eq!(
            server.handle_timeout(deadline),
            Err(Error::Timeout(TimeoutError::Connect))
        );
    }
}

#[test]
fn flights_retry_exactly_with_backoff() {
    let base = Instant::now();
    let certificate = generate_self_signed_certificate().expect("certificate");
    let rto = Duration::from_millis(20);
    for &version in VERSIONS {
        for retries in [0, 2] {
            for active in [false, true] {
                let config = retry_config(retries, true);
                let mut endpoint = version.endpoint(config.clone(), certificate.clone(), base);
                endpoint.set_active(active);
                endpoint.handle_timeout(base).expect("initialize clock");
                if !active {
                    for packet in client_hello(version, config, base) {
                        endpoint.handle_packet(&packet).expect("accept ClientHello");
                    }
                }
                let (original, mut deadline) = settle(&mut endpoint, base);
                assert!(!original.is_empty(), "{version:?}, active={active}");
                let mut now = base;
                for attempt in 0..=retries {
                    let nominal = rto * (1 << attempt);
                    let interval = deadline - now;
                    assert!(interval >= nominal.mul_f64(0.75), "{version:?} {active}");
                    assert!(interval <= nominal.mul_f64(1.25), "{version:?} {active}");
                    now = deadline;
                    if attempt == retries {
                        break;
                    }
                    endpoint.handle_timeout(now).expect("retry");
                    let (retried, next) = settle(&mut endpoint, now);
                    assert_eq!(retried.len(), original.len(), "{version:?} {active}");
                    deadline = next;
                }
                let reason = if active && matches!(version, Version::Auto) {
                    TimeoutError::HybridClientHello
                } else {
                    TimeoutError::Handshake
                };
                assert_eq!(endpoint.handle_timeout(now), Err(Error::Timeout(reason)));
            }
        }
    }
}

#[test]
fn duplicate_client_hellos_share_the_retry_budget() {
    let base = Instant::now();
    let certificate = generate_self_signed_certificate().expect("certificate");
    for &version in VERSIONS {
        let config = retry_config(1, false);
        let mut server = version.endpoint(config.clone(), certificate.clone(), base);
        server.handle_timeout(base).expect("server clock");
        let hello = client_hello(version, config, base);
        for packet in &hello {
            server.handle_packet(packet).expect("ClientHello");
        }
        let (original, _) = settle(&mut server, base);

        let now = base + Duration::from_millis(1);
        server.handle_timeout(now).expect("before retry timer");
        for packet in &hello {
            server.handle_packet(packet).expect("duplicate ClientHello");
        }
        let (resent, deadline) = settle(&mut server, now);
        assert_eq!(resent.len(), original.len(), "{version:?}");
        assert_eq!(
            server.handle_timeout(deadline),
            Err(Error::Timeout(TimeoutError::Handshake)),
            "{version:?}"
        );
    }
}

#[test]
fn auto_client_keeps_its_deadline_across_version_selection() {
    let base = Instant::now();
    let certificate = generate_self_signed_certificate().expect("certificate");
    for (peer, expected) in [
        (Version::Dtls12, ProtocolVersion::DTLS1_2),
        (Version::Dtls13, ProtocolVersion::DTLS1_3),
    ] {
        let mut client = Version::Auto.endpoint(config(), certificate.clone(), base);
        client.set_active(true);
        let (hello, deadline) = settle(&mut client, base);
        assert_eq!(deadline, base + BUDGET);

        let selection = base + Duration::from_millis(70);
        let mut server = peer.endpoint(config(), certificate.clone(), selection);
        server.handle_timeout(selection).expect("server clock");
        for packet in hello {
            server.handle_packet(&packet).expect("hybrid ClientHello");
        }
        let (responses, _) = settle(&mut server, selection);
        client.handle_timeout(selection).expect("client clock");
        for packet in responses {
            client.handle_packet(&packet).expect("version selection");
        }
        let (second_hello, after) = settle(&mut client, selection);
        assert!(!second_hello.is_empty(), "{peer:?}");
        assert_eq!(client.protocol_version(), Some(expected));
        assert_eq!(after, deadline, "{peer:?}");
        assert_eq!(
            client.handle_timeout(deadline),
            Err(Error::Timeout(TimeoutError::Connect))
        );
    }
}

#[test]
fn completed_handshakes_ignore_the_deadline() {
    let base = Instant::now();
    let certificate = generate_self_signed_certificate().expect("certificate");
    let config = Arc::new(
        Config::builder()
            .dangerously_set_rng_seed(42)
            .handshake_timeout(BUDGET)
            .flight_start_rto(Duration::from_millis(20))
            .aead_encryption_limit(3)
            .build()
            .expect("small key-update threshold"),
    );
    for &versions in PAIRS {
        let mut client = versions
            .0
            .endpoint(config.clone(), certificate.clone(), base);
        let mut server = versions
            .1
            .endpoint(config.clone(), certificate.clone(), base);
        client.set_active(true);
        let output = exchange(&mut client, &mut server, base);
        assert!(output.0.connected && output.1.connected, "{versions:?}");

        for round in 0..6 {
            let now = base + Duration::from_secs(60 + round);
            client.send_application_data(b"ping").expect("client send");
            let received = exchange(&mut client, &mut server, now);
            assert_eq!(received.1.app_data, [b"ping".to_vec()], "{versions:?}");
            server.send_application_data(b"pong").expect("server send");
            let received = exchange(&mut client, &mut server, now);
            assert_eq!(received.0.app_data, [b"pong".to_vec()], "{versions:?}");
            assert!(received.0.timeout.expect("client timeout") > now);
            assert!(received.1.timeout.expect("server timeout") > now);
        }
    }
}

/// Same budget as [`config`], with the minimum MTU so the ClientHello fragments.
fn fragmenting_config() -> Arc<Config> {
    Arc::new(
        Config::builder()
            .dangerously_set_rng_seed(42)
            .mtu(64)
            .handshake_timeout(BUDGET)
            .flight_start_rto(Duration::from_secs(1))
            .flight_retries(0)
            .build()
            .expect("valid fragmenting config"),
    )
}

/// Make a ClientHello unparseable by overstating an extension's inner length.
fn corrupt_supported_groups(hello: &mut [u8]) {
    // Record header (13) + handshake header (12) + version (2) + random (32).
    let mut cursor = 59;
    cursor += 1 + hello[cursor] as usize; // session id
    cursor += 1 + hello[cursor] as usize; // cookie
    cursor += 2 + u16::from_be_bytes([hello[cursor], hello[cursor + 1]]) as usize;
    cursor += 1 + hello[cursor] as usize; // compression methods
    cursor += 2; // extensions length
    while cursor + 4 <= hello.len() {
        let kind = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
        let length = u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]) as usize;
        if kind == 0x000A {
            hello[cursor + 4..cursor + 6].copy_from_slice(&u16::MAX.to_be_bytes());
            return;
        }
        cursor += 4 + length;
    }
    panic!("ClientHello has no supported_groups extension");
}

#[test]
fn undersized_output_does_not_start_client_timers() {
    let base = Instant::now();
    let certificate = generate_self_signed_certificate().expect("certificate");
    for &version in VERSIONS {
        let mut client = version.endpoint(config(), certificate.clone(), base);
        client.set_active(true);
        client.handle_timeout(base).expect("build ClientHello");
        assert!(matches!(
            client.poll_output(&mut []),
            Output::BufferTooSmall { .. }
        ));
        let late = base + Duration::from_secs(60);
        client
            .handle_timeout(late)
            .expect("nothing sent, nothing started");
        let (packets, deadline) = settle(&mut client, late);
        assert!(!packets.is_empty(), "{version:?}");
        assert_eq!(deadline, late + BUDGET, "{version:?}");
    }
}

#[test]
fn servers_start_at_first_accepted_client_hello_fragment() {
    let base = Instant::now();
    let certificate = generate_self_signed_certificate().expect("certificate");
    for &version in VERSIONS {
        let mut server = version.endpoint(config(), certificate.clone(), base);
        server.handle_timeout(base).expect("server clock");
        server
            .handle_packet(&[0, 1, 2])
            .expect("malformed input is discarded");
        assert!(settle(&mut server, base).1 > base + BUDGET, "{version:?}");

        let arrival = base + Duration::from_secs(60);
        // The hybrid Auto ClientHello is never fragmented.
        let client = match version {
            Version::Auto => Version::Dtls13,
            other => other,
        };
        let hello = client_hello(client, fragmenting_config(), arrival);
        assert!(hello.len() > 1, "{version:?}: ClientHello not fragmented");
        server.handle_packet(&hello[0]).expect("first fragment");
        let (_, deadline) = settle(&mut server, arrival);
        assert_eq!(deadline, arrival + BUDGET, "{version:?}");
        assert_eq!(
            server.handle_timeout(deadline),
            Err(Error::Timeout(TimeoutError::Connect))
        );
    }
}

#[test]
fn rejected_client_hello_does_not_start_server_clock() {
    let base = Instant::now();
    let certificate = generate_self_signed_certificate().expect("certificate");
    // Without cookies the server parses, and so rejects, the first ClientHello.
    let config = Arc::new(
        Config::builder()
            .dangerously_set_rng_seed(42)
            .use_server_cookie(false)
            .handshake_timeout(BUDGET)
            .build()
            .expect("valid config"),
    );
    for version in [Version::Dtls12, Version::Dtls13] {
        let mut server = version.endpoint(config.clone(), certificate.clone(), base);
        server.handle_timeout(base).expect("server clock");
        let mut hello = client_hello(version, config.clone(), base);
        assert_eq!(hello.len(), 1);
        corrupt_supported_groups(&mut hello[0]);
        let _ = server.handle_packet(&hello[0]);
        let (response, wake) = settle(&mut server, base);
        assert!(response.is_empty(), "{version:?}");
        assert!(wake > base + BUDGET, "{version:?}");
    }
}

#[test]
fn auto_server_keeps_its_deadline_across_dtls12_fallback() {
    let base = Instant::now();
    let certificate = generate_self_signed_certificate().expect("certificate");
    let mut server = Version::Auto.endpoint(config(), certificate.clone(), base);
    server.handle_timeout(base).expect("server clock");
    let hello = client_hello(Version::Dtls12, fragmenting_config(), base);
    assert!(hello.len() > 1, "ClientHello not fragmented");
    server.handle_packet(&hello[0]).expect("first fragment");
    let (_, deadline) = settle(&mut server, base);
    assert_eq!(deadline, base + BUDGET);

    let selection = base + Duration::from_millis(70);
    server.handle_timeout(selection).expect("server clock");
    for packet in &hello[1..] {
        server.handle_packet(packet).expect("remaining fragments");
    }
    let (response, after) = settle(&mut server, selection);
    assert!(!response.is_empty());
    assert_eq!(server.protocol_version(), Some(ProtocolVersion::DTLS1_2));
    assert_eq!(after, deadline);
    assert_eq!(
        server.handle_timeout(deadline),
        Err(Error::Timeout(TimeoutError::Connect))
    );
}
