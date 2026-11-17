//! Publishing to the lab relay over plain `ws://`.
//!
//! In this version the relay must be `ws://<host>:7777` with `<host>` one of
//! the regtest lab's own service names. No TLS, no redirects (a non-101 answer
//! is an error), messages capped at 64 KiB, 5 seconds to connect and 10 in all.

use crate::NotifyError;
use crate::event::Event;
use gd_core::Untrusted;
use serde_json::Value;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Error as WsError, Message};

/// The only hosts a relay may have in this version: the lab's service names.
pub const ALLOWED_HOSTS: [&str; 5] = ["bitcoind", "lnd", "cln", "strfry", "nutshell"];
/// The only relay port.
pub const RELAY_PORT: u16 = 7777;
/// Largest WebSocket message, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Frames that are not an answer to us (notices, pings) we will skip, at most.
const MAX_SKIPPED_MESSAGES: usize = 200;

/// A relay address that passed the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayUrl {
    host: String,
    port: u16,
    #[cfg(test)]
    loopback: bool,
}

impl RelayUrl {
    /// Accepts exactly `ws://<host>:7777` for a lab host; refuses everything
    /// else (other schemes, hosts, ports, paths, queries, credentials, IP
    /// addresses, case changes, spaces).
    pub fn parse(text: &str) -> Result<RelayUrl, NotifyError> {
        let refused = NotifyError::Refused(
            "relay must be ws://<host>:7777 with host one of strfry, bitcoind, lnd, cln, nutshell (lab only)",
        );
        let rest = text.strip_prefix("ws://").ok_or(refused)?;
        let (host, port) = rest.split_once(':').ok_or(refused)?;
        if port != "7777" || !ALLOWED_HOSTS.contains(&host) {
            return Err(refused);
        }
        Ok(RelayUrl {
            host: host.to_owned(),
            port: RELAY_PORT,
            #[cfg(test)]
            loopback: false,
        })
    }

    /// The host name.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Test only: a relay on this machine's loopback address, for the fake
    /// relay in this crate's tests. Not compiled into any other build.
    #[cfg(test)]
    pub(crate) fn loopback_for_test(port: u16) -> RelayUrl {
        RelayUrl {
            host: "strfry".to_owned(),
            port,
            loopback: true,
        }
    }

    fn allow_loopback(&self) -> bool {
        #[cfg(test)]
        {
            self.loopback
        }
        #[cfg(not(test))]
        {
            false
        }
    }
}

/// True for the private ranges a lab or home network uses: 10.0.0.0/8,
/// 172.16.0.0/12, 192.168.0.0/16 and IPv6 unique-local fc00::/7 (the lab is
/// 172.29.208.0/24). An IPv4 address written as IPv6 is judged as IPv4.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_private(),
            None => v6.segments().first().is_some_and(|s| s & 0xfe00 == 0xfc00),
        },
    }
}

/// Picks the address to connect to from what the name resolved to. Every
/// address must be private (loopback too, but only when `allow_loopback`, which
/// only tests can set); one public address refuses the name, so a lookup that
/// has been tampered with cannot send a message out to the internet.
fn addresses_ok(addrs: &[SocketAddr], allow_loopback: bool) -> Result<SocketAddr, NotifyError> {
    let all_private = addrs
        .iter()
        .all(|a| is_private(a.ip()) || (allow_loopback && a.ip().is_loopback()));
    match addrs.first() {
        Some(first) if all_private => Ok(*first),
        _ => Err(NotifyError::Refused(
            "the relay name does not resolve to a private address",
        )),
    }
}

fn system_resolver(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

#[cfg(test)]
fn loopback_resolver(_host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
}

/// The relay's answer to one event. The relay's own message is outside text.
#[derive(Debug, Clone)]
pub struct PublishOutcome {
    /// The event this answers.
    pub event_id: String,
    /// True if the relay stored it.
    pub accepted: bool,
    /// What the relay said, untrusted.
    pub message: Untrusted<String>,
}

fn ws_error(e: &WsError) -> NotifyError {
    match e {
        WsError::Http(_) => {
            NotifyError::Relay("the relay answered with an HTTP status, not a websocket")
        }
        WsError::Io(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            NotifyError::Relay("timed out waiting for the relay")
        }
        WsError::Capacity(_) => NotifyError::Relay("the relay sent a message that is too large"),
        _ => NotifyError::Relay("the websocket connection failed"),
    }
}

/// Sends `["EVENT", <event>]` for each event and waits (at most 10 seconds in
/// all) for the relay's `["OK", id, true|false, message]` for each. Returns
/// one outcome per event, in order.
pub fn publish(relay: &RelayUrl, events: &[Event]) -> Result<Vec<PublishOutcome>, NotifyError> {
    #[cfg(test)]
    if relay.loopback {
        return publish_with(relay, events, TOTAL_TIMEOUT, &loopback_resolver);
    }
    publish_with(relay, events, TOTAL_TIMEOUT, &system_resolver)
}

/// [`publish`] with the name lookup and the total time as parameters (tests
/// use a fake lookup and a short deadline). The lookup runs in its own thread
/// and counts against `total`; the address it returns is checked, and that
/// checked address is the one connected to.
fn publish_with<R>(
    relay: &RelayUrl,
    events: &[Event],
    total: Duration,
    resolver: &R,
) -> Result<Vec<PublishOutcome>, NotifyError>
where
    R: Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>> + Clone + Send + 'static,
{
    let start = Instant::now();
    let remaining = |start: Instant| -> Result<Duration, NotifyError> {
        total
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or(NotifyError::Relay("timed out waiting for the relay"))
    };
    let (tx, rx) = mpsc::channel();
    let lookup = resolver.clone();
    let (host, port) = (relay.host.clone(), relay.port);
    std::thread::spawn(move || {
        let _ = tx.send(lookup(&host, port));
    });
    let found = rx
        .recv_timeout(remaining(start)?)
        .map_err(|_| NotifyError::Relay("timed out looking up the relay"))?
        .map_err(|_| NotifyError::Relay("cannot find the relay"))?;
    let addr = addresses_ok(&found, relay.allow_loopback())?;
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT.min(remaining(start)?))
        .map_err(|_| NotifyError::Relay("cannot connect to the relay"))?;
    let _ = stream.set_nodelay(true);
    let set_timeouts = |stream: &TcpStream| -> Result<(), NotifyError> {
        let left = remaining(start)?;
        stream
            .set_read_timeout(Some(left))
            .and_then(|()| stream.set_write_timeout(Some(left)))
            .map_err(|_| NotifyError::Relay("cannot set timeouts"))
    };
    set_timeouts(&stream)?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    let url = format!("ws://{}:{}", relay.host, relay.port);
    let (mut socket, _response) =
        tungstenite::client::client_with_config(url, stream, Some(config)).map_err(
            |e| match e {
                tungstenite::HandshakeError::Failure(err) => ws_error(&err),
                tungstenite::HandshakeError::Interrupted(_) => {
                    NotifyError::Relay("timed out waiting for the relay")
                }
            },
        )?;

    for event in events {
        let text = format!("[\"EVENT\",{}]", event.to_json());
        if text.len() > MAX_MESSAGE_BYTES {
            return Err(NotifyError::Refused(
                "event is larger than the 64 KiB message limit",
            ));
        }
        set_timeouts(socket.get_ref())?;
        socket.send(Message::text(text)).map_err(|e| ws_error(&e))?;
    }

    let mut outcomes: Vec<Option<PublishOutcome>> = vec![None; events.len()];
    let mut skipped = 0usize;
    while outcomes.iter().any(Option::is_none) {
        set_timeouts(socket.get_ref())?;
        let message = socket.read().map_err(|e| ws_error(&e))?;
        let Message::Text(text) = message else {
            if matches!(message, Message::Close(_)) {
                return Err(NotifyError::Relay("the relay closed the connection early"));
            }
            continue;
        };
        let parsed = serde_json::from_str::<Value>(text.as_str()).ok();
        let answer = parsed.as_ref().and_then(Value::as_array).and_then(|a| {
            if a.first()?.as_str()? != "OK" {
                return None;
            }
            Some((
                a.get(1)?.as_str()?,
                a.get(2)?.as_bool()?,
                a.get(3).and_then(Value::as_str).unwrap_or(""),
            ))
        });
        match answer {
            Some((id, accepted, note)) => {
                if let Some(index) = events.iter().position(|e| e.id == id)
                    && let Some(slot) = outcomes.get_mut(index)
                {
                    *slot = Some(PublishOutcome {
                        event_id: id.to_owned(),
                        accepted,
                        message: Untrusted::new(note.chars().take(500).collect()),
                    });
                }
            }
            None => {
                skipped += 1;
                if skipped > MAX_SKIPPED_MESSAGES {
                    return Err(NotifyError::Relay(
                        "the relay sent too many unrelated messages",
                    ));
                }
            }
        }
    }
    // Politeness only: the answers are already in hand.
    let _ = socket.close(None);
    Ok(outcomes.into_iter().flatten().collect())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::*;
    use crate::event::{gift_wrap_dm, unwrap_dm};
    use crate::{Clock, Entropy, Keys, NotifyError};
    use sha2::{Digest, Sha256};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    struct Seq(u64);
    impl Entropy for Seq {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), NotifyError> {
            let mut done = 0;
            while done < buf.len() {
                self.0 += 1;
                let block = Sha256::digest(self.0.to_be_bytes());
                let n = (buf.len() - done).min(32);
                buf[done..done + n].copy_from_slice(&block[..n]);
                done += n;
            }
            Ok(())
        }
    }
    struct Fixed(u64);
    impl Clock for Fixed {
        fn now_unix(&self) -> u64 {
            self.0
        }
    }

    /// What the fake relay does with each EVENT it receives.
    #[derive(Clone, Copy)]
    enum Mode {
        Accept,
        Reject,
        Silent,
        NoiseThenAccept,
        Redirect,
        Huge,
    }

    /// An in-process relay on 127.0.0.1: records every message it gets.
    fn fake_relay(mode: Mode) -> (u16, Arc<Mutex<Vec<String>>>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            if matches!(mode, Mode::Redirect) {
                use std::io::{Read, Write};
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 301 Moved Permanently\r\nLocation: ws://elsewhere.example:7777/\r\nContent-Length: 0\r\n\r\n",
                );
                return;
            }
            let mut ws = tungstenite::accept(stream).unwrap();
            loop {
                let Ok(msg) = ws.read() else { return };
                let Message::Text(text) = msg else { continue };
                log.lock().unwrap().push(text.as_str().to_owned());
                let v: Value = serde_json::from_str(text.as_str()).unwrap();
                let id = v[1]["id"].as_str().unwrap().to_owned();
                let reply = match mode {
                    Mode::Accept | Mode::NoiseThenAccept => serde_json::json!(["OK", id, true, ""]),
                    Mode::Reject => serde_json::json!(["OK", id, false, "blocked: \u{1b}[31mnope"]),
                    Mode::Huge => serde_json::json!(["NOTICE", "x".repeat(100_000)]),
                    Mode::Silent | Mode::Redirect => continue,
                };
                if matches!(mode, Mode::NoiseThenAccept) {
                    let _ = ws.send(Message::text(r#"["NOTICE","hello"]"#));
                    let _ = ws.send(Message::text(r#"["OK","not-ours",true,""]"#));
                }
                let _ = ws.send(Message::text(reply.to_string()));
                if matches!(mode, Mode::Huge) {
                    return;
                }
            }
        });
        (port, seen, handle)
    }

    fn wraps(n: usize) -> (Keys, Vec<Event>) {
        let sender = Keys::generate(&mut Seq(1)).unwrap();
        let recipient = Keys::generate(&mut Seq(2)).unwrap();
        let mut entropy = Seq(100);
        let events = (0..n)
            .map(|i| {
                gift_wrap_dm(
                    &sender,
                    &recipient.public_x(),
                    &format!("message {i}"),
                    &Fixed(1_795_000_000),
                    &mut entropy,
                )
                .unwrap()
            })
            .collect();
        (recipient, events)
    }

    #[test]
    fn fake_relay_receives_exactly_the_wraps_and_answers_ok() {
        let (recipient, events) = wraps(3);
        let (port, seen, handle) = fake_relay(Mode::Accept);
        let out = publish(&RelayUrl::loopback_for_test(port), &events).unwrap();
        assert_eq!(out.len(), 3);
        for (o, e) in out.iter().zip(&events) {
            assert!(o.accepted);
            assert_eq!(o.event_id, e.id);
        }
        handle.join().unwrap();
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 3);
        for (i, text) in got.iter().enumerate() {
            let v: Value = serde_json::from_str(text).unwrap();
            assert_eq!(v[0], "EVENT");
            assert_eq!(v.as_array().unwrap().len(), 2);
            let event = Event::from_json(&v[1].to_string()).unwrap();
            assert_eq!(event, events[i]);
            event.verify().unwrap();
            let opened = unwrap_dm(&recipient, &event).unwrap();
            assert_eq!(opened.rumor.content, format!("message {i}"));
        }
    }

    #[test]
    fn a_rejection_is_reported_and_its_text_is_untrusted() {
        let (_, events) = wraps(1);
        let (port, _seen, handle) = fake_relay(Mode::Reject);
        let out = publish(&RelayUrl::loopback_for_test(port), &events).unwrap();
        assert!(!out[0].accepted);
        let shown = format!("{:?}", out[0]);
        assert!(!shown.contains("blocked"), "{shown}");
        assert!(
            out[0]
                .message
                .escape_for_terminal()
                .starts_with("blocked: \\u{1b}")
        );
        handle.join().unwrap();
    }

    #[test]
    fn notices_and_other_answers_are_skipped() {
        let (_, events) = wraps(1);
        let (port, _seen, handle) = fake_relay(Mode::NoiseThenAccept);
        let out = publish(&RelayUrl::loopback_for_test(port), &events).unwrap();
        assert!(out[0].accepted);
        handle.join().unwrap();
    }

    #[test]
    fn a_silent_relay_times_out_inside_ten_seconds() {
        let (_, events) = wraps(1);
        let (port, _seen, handle) = fake_relay(Mode::Silent);
        let start = Instant::now();
        let err = publish(&RelayUrl::loopback_for_test(port), &events).unwrap_err();
        assert!(matches!(err, NotifyError::Relay(_)), "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(12),
            "{:?}",
            start.elapsed()
        );
        drop(handle);
    }

    #[test]
    fn a_redirect_is_not_followed() {
        let (_, events) = wraps(1);
        let (port, _seen, handle) = fake_relay(Mode::Redirect);
        let err = publish(&RelayUrl::loopback_for_test(port), &events).unwrap_err();
        assert!(matches!(err, NotifyError::Relay(_)), "{err}");
        handle.join().unwrap();
    }

    #[test]
    fn a_message_over_64_kib_is_refused() {
        let (_, events) = wraps(1);
        let (port, _seen, handle) = fake_relay(Mode::Huge);
        let err = publish(&RelayUrl::loopback_for_test(port), &events).unwrap_err();
        assert!(matches!(err, NotifyError::Relay(_)), "{err}");
        handle.join().unwrap();
    }

    #[test]
    fn loopback_is_not_reachable_through_parse() {
        for text in ["ws://127.0.0.1:7777", "ws://localhost:7777"] {
            assert!(RelayUrl::parse(text).is_err());
        }
    }

    #[test]
    fn send_alerts_refuses_mainnet_before_any_connection() {
        use crate::alert::Chain;
        let sender = Keys::generate(&mut Seq(1)).unwrap();
        // Nothing listens on this port; the refusal must come first.
        let relay = RelayUrl::loopback_for_test(1);
        let err = crate::send_alerts(
            &relay,
            &sender,
            &[7u8; 32],
            &[],
            &[Chain::Mainnet],
            &Fixed(1),
            &mut Seq(3),
        )
        .unwrap_err();
        assert!(matches!(err, NotifyError::Refused(_)));
    }

    #[test]
    fn send_alerts_publishes_the_planned_messages_end_to_end() {
        use crate::alert::{Alert, AlertParts, Chain, MatchResult, Severity};
        let (recipient, _) = wraps(0);
        let sender = Keys::generate(&mut Seq(1)).unwrap();
        let alert = |id: &str, severity| {
            Alert::new(AlertParts {
                product: "LND",
                version: "0.18.4-beta".to_owned(),
                chain: Chain::Regtest,
                advisory_id: id.to_owned(),
                result: MatchResult::Affected,
                severity,
                fixed_in: None,
                summary: Untrusted::new("s".to_owned()),
                playbook: Untrusted::new("p".to_owned()),
                question: None,
                checked_at: 1_795_000_000,
                blind_spots: vec![],
            })
            .unwrap()
        };
        let alerts = [
            alert("held-back", Severity::Low),
            alert("sent-one", Severity::High),
        ];
        let (port, seen, handle) = fake_relay(Mode::Accept);
        let out = crate::send_alerts(
            &RelayUrl::loopback_for_test(port),
            &sender,
            &recipient.public_x(),
            &alerts,
            &[Chain::Regtest, Chain::Signet],
            &Fixed(1_795_000_000),
            &mut Seq(9),
        )
        .unwrap();
        assert_eq!(out.len(), 1);
        handle.join().unwrap();
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        let v: Value = serde_json::from_str(&got[0]).unwrap();
        let event = Event::from_json(&v[1].to_string()).unwrap();
        let text = unwrap_dm(&recipient, &event).unwrap().rumor.content;
        assert!(text.contains("sent-one") && !text.contains("held-back"));
    }

    fn sock(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 7777)
    }

    #[test]
    fn only_private_addresses_are_accepted() {
        for ok in [
            "10.1.2.3",
            "172.16.0.1",
            "172.29.208.5",
            "172.31.255.255",
            "192.168.1.1",
            "fd12:3456::1",
            "fc00::1",
        ] {
            assert!(addresses_ok(&[sock(ok)], false).is_ok(), "{ok}");
        }
        for bad in [
            "8.8.8.8",
            "172.15.0.1",
            "172.32.0.1",
            "192.169.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:8.8.8.8",
            "::",
            "fe00::1",
        ] {
            assert!(addresses_ok(&[sock(bad)], false).is_err(), "{bad}");
        }
        // One public address among private ones is enough to refuse the name.
        assert!(addresses_ok(&[sock("10.0.0.1"), sock("8.8.8.8")], false).is_err());
        assert!(addresses_ok(&[], false).is_err());
        // Loopback only when the test hook says so.
        assert!(addresses_ok(&[sock("127.0.0.1")], true).is_ok());
        assert_eq!(
            addresses_ok(&[sock("10.0.0.1"), sock("10.0.0.2")], false).unwrap(),
            sock("10.0.0.1")
        );
    }

    #[test]
    fn a_name_that_resolves_to_a_public_address_is_refused_before_connecting() {
        let (_, events) = wraps(1);
        let relay = RelayUrl::loopback_for_test(1);
        let resolver = |_: &str, _: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![sock("93.184.216.34")])
        };
        // The loopback test relay may use loopback, but never a public address.
        let err = publish_with(&relay, &events, TOTAL_TIMEOUT, &resolver).unwrap_err();
        assert!(matches!(err, NotifyError::Refused(_)), "{err}");
    }

    #[test]
    fn a_slow_lookup_counts_against_the_deadline() {
        let (_, events) = wraps(1);
        let relay = RelayUrl::loopback_for_test(1);
        let resolver = |_: &str, _: u16| -> std::io::Result<Vec<SocketAddr>> {
            thread::sleep(Duration::from_secs(5));
            Ok(vec![sock("127.0.0.1")])
        };
        let start = Instant::now();
        let err = publish_with(&relay, &events, Duration::from_secs(1), &resolver).unwrap_err();
        assert!(matches!(err, NotifyError::Relay(_)), "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn the_checked_address_is_the_one_connected_to() {
        let (_, events) = wraps(1);
        let (port, _seen, handle) = fake_relay(Mode::Accept);
        let relay = RelayUrl::loopback_for_test(port);
        let resolver = move |host: &str, p: u16| -> std::io::Result<Vec<SocketAddr>> {
            assert_eq!(host, "strfry");
            assert_eq!(p, port);
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
        };
        let out = publish_with(&relay, &events, TOTAL_TIMEOUT, &resolver).unwrap();
        assert!(out[0].accepted);
        handle.join().unwrap();
    }

    #[test]
    fn an_alert_on_a_chain_that_is_not_allowed_is_refused() {
        use crate::alert::{Alert, AlertParts, Chain, MatchResult, Severity};
        let make = |chain| {
            Alert::new(AlertParts {
                product: "LND",
                version: "0.18.4-beta".to_owned(),
                chain,
                advisory_id: "a-1".to_owned(),
                result: MatchResult::Affected,
                severity: Severity::High,
                fixed_in: None,
                summary: Untrusted::new("s".to_owned()),
                playbook: Untrusted::new("p".to_owned()),
                question: None,
                checked_at: 1,
                blind_spots: vec![],
            })
            .unwrap()
        };
        let sender = Keys::generate(&mut Seq(1)).unwrap();
        let relay = RelayUrl::loopback_for_test(1);
        for chain in [Chain::Mainnet, Chain::Testnet, Chain::Unknown] {
            // The node set is fine, but this one alert is on another chain.
            let err = crate::send_alerts(
                &relay,
                &sender,
                &[7u8; 32],
                &[make(Chain::Regtest), make(chain)],
                &[Chain::Regtest],
                &Fixed(1),
                &mut Seq(3),
            )
            .unwrap_err();
            assert!(matches!(err, NotifyError::Refused(_)), "{chain:?}: {err}");
        }
    }
}
