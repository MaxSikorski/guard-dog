//! Publishing to the lab relay over plain `ws://`.
//!
//! In this version the relay must be `ws://<host>:7777` with `<host>` one of
//! the regtest lab's own service names. No TLS, no redirects (a non-101 answer
//! is an error), messages capped at 64 KiB, 5 seconds to connect and 10 in all (a relay that
//! sends a byte at a time still runs out the same 10 seconds). The name must
//! resolve only to the lab's own subnet, 172.29.208.0/24.

use crate::NotifyError;
use crate::event::Event;
use gd_core::Untrusted;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
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

/// True only for the regtest lab's own subnet, 172.29.208.0/24. An IPv4
/// address written as IPv6 is judged as IPv4.
fn is_lab_address(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return false,
        },
    };
    let lab = Ipv4Addr::new(172, 29, 208, 0);
    v4.octets().get(..3) == lab.octets().get(..3)
}

/// Picks the address to connect to from what the name resolved to. Every
/// address must be in the lab subnet (loopback too, but only when
/// `allow_loopback`, which only tests can set); one other address refuses the
/// name, so a tampered lookup, a search domain or mDNS cannot send a message
/// anywhere but the lab.
fn addresses_ok(addrs: &[SocketAddr], allow_loopback: bool) -> Result<SocketAddr, NotifyError> {
    let all_lab = addrs
        .iter()
        .all(|a| is_lab_address(a.ip()) || (allow_loopback && a.ip().is_loopback()));
    match addrs.first() {
        Some(first) if all_lab => Ok(*first),
        _ => Err(NotifyError::Refused(
            "the relay name does not resolve to the lab subnet (172.29.208.0/24)",
        )),
    }
}

/// A TCP stream that stops at a fixed deadline: before every read and write
/// it sets the socket timeout to the time left, and past the deadline it
/// fails with `TimedOut`. So the 10 seconds cover the whole conversation,
/// however slowly the relay sends.
struct DeadlineStream {
    inner: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn left(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.set_read_timeout(Some(self.left()?))?;
        self.inner.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.set_write_timeout(Some(self.left()?))?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
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
pub(crate) fn publish(
    relay: &RelayUrl,
    events: &[Event],
) -> Result<Vec<PublishOutcome>, NotifyError> {
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
    let stream = DeadlineStream {
        inner: stream,
        deadline: start + total,
    };
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
        socket.send(Message::text(text)).map_err(|e| ws_error(&e))?;
    }

    let mut outcomes: Vec<Option<PublishOutcome>> = vec![None; events.len()];
    let mut ignored = 0usize;
    while outcomes.iter().any(Option::is_none) {
        let message = socket.read().map_err(|e| ws_error(&e))?;
        if matches!(message, Message::Close(_)) {
            return Err(NotifyError::Relay("the relay closed the connection early"));
        }
        let used = match &message {
            Message::Text(text) => fill_slot(text.as_str(), events, &mut outcomes),
            _ => false,
        };
        // Every message that did not fill an empty slot counts toward the
        // limit: notices, pings, odd shapes, unknown ids and repeated answers.
        if !used {
            ignored += 1;
            if ignored > MAX_SKIPPED_MESSAGES {
                return Err(NotifyError::Relay(
                    "the relay sent too many unrelated messages",
                ));
            }
        }
    }
    // Politeness only: the answers are already in hand.
    let _ = socket.close(None);
    Ok(outcomes.into_iter().flatten().collect())
}

/// Reads one relay message. Only the shape `["OK", <id>, <bool>, <text>]`
/// (or with a fifth field that is text) for one of our events whose slot is still empty is used; it fills that slot
/// once, so a later conflicting answer never overwrites the first. Returns
/// whether a slot was filled.
fn fill_slot(text: &str, events: &[Event], outcomes: &mut [Option<PublishOutcome>]) -> bool {
    let Ok(Value::Array(fields)) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let [kind, id, accepted, note, rest @ ..] = fields.as_slice() else {
        return false;
    };
    // Four fields, or five where the fifth is text (some relays add one).
    if !matches!(rest, [] | [Value::String(_)]) {
        return false;
    }
    let (Some("OK"), Some(id), Some(accepted), Some(note)) = (
        kind.as_str(),
        id.as_str(),
        accepted.as_bool(),
        note.as_str(),
    ) else {
        return false;
    };
    let Some(index) = events.iter().position(|e| e.id == id) else {
        return false;
    };
    match outcomes.get_mut(index) {
        Some(slot @ None) => {
            *slot = Some(PublishOutcome {
                event_id: id.to_owned(),
                accepted,
                message: Untrusted::new(note.chars().take(500).collect()),
            });
            true
        }
        _ => false,
    }
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
        fn now_unix(&self) -> Result<u64, NotifyError> {
            Ok(self.0)
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
        /// Answers a two-event batch with a short, a conflicting and a good ack.
        Conflicting,
        /// Floods pings before it answers.
        Pings,
        /// Answers with a valid five-field rejection.
        FiveFields,
        /// Floods five-field acks whose fifth field is not text.
        BadFifth,
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
            let mut ids: Vec<String> = Vec::new();
            loop {
                let Ok(msg) = ws.read() else { return };
                let Message::Text(text) = msg else { continue };
                log.lock().unwrap().push(text.as_str().to_owned());
                let v: Value = serde_json::from_str(text.as_str()).unwrap();
                let id = v[1]["id"].as_str().unwrap().to_owned();
                ids.push(id.clone());
                if matches!(mode, Mode::FiveFields) {
                    let ack = serde_json::json!(["OK", id, false, "blocked: spam", "extra"]);
                    let _ = ws.send(Message::text(ack.to_string()));
                    continue;
                }
                if matches!(mode, Mode::BadFifth) {
                    for _ in 0..250 {
                        let ack = serde_json::json!(["OK", id, true, "", 5]);
                        let _ = ws.send(Message::text(ack.to_string()));
                    }
                    continue;
                }
                if matches!(mode, Mode::Conflicting) {
                    if ids.len() == 2 {
                        for ack in [
                            // Too short, and it says "false" for the event that is accepted.
                            serde_json::json!(["OK", ids[1], false]),
                            serde_json::json!(["OK", ids[0], true, ""]),
                            serde_json::json!(["OK", ids[0], false, "conflict"]),
                            serde_json::json!(["OK", "0".repeat(64), false, "x"]),
                            serde_json::json!(["OK", ids[1], true, ""]),
                        ] {
                            let _ = ws.send(Message::text(ack.to_string()));
                        }
                    }
                    continue;
                }
                if matches!(mode, Mode::Pings) {
                    for _ in 0..250 {
                        let _ = ws.send(Message::Ping(vec![].into()));
                    }
                    continue;
                }
                let reply = match mode {
                    Mode::Accept | Mode::NoiseThenAccept => serde_json::json!(["OK", id, true, ""]),
                    Mode::Reject => serde_json::json!(["OK", id, false, "blocked: \u{1b}[31mnope"]),
                    Mode::Huge => serde_json::json!(["NOTICE", "x".repeat(100_000)]),
                    Mode::Silent
                    | Mode::Redirect
                    | Mode::Conflicting
                    | Mode::Pings
                    | Mode::FiveFields
                    | Mode::BadFifth => continue,
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
                    &recipient.public_x().unwrap(),
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
            &recipient.public_x().unwrap(),
            &alerts,
            &[Chain::Regtest, Chain::Signet],
            &Fixed(1_795_000_000),
            &mut Seq(9),
        )
        .unwrap();
        // The high one, then one summary for the low one that was held back.
        assert_eq!(out.len(), 2);
        handle.join().unwrap();
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 2);
        let open = |raw: &str| {
            let v: Value = serde_json::from_str(raw).unwrap();
            let event = Event::from_json(&v[1].to_string()).unwrap();
            unwrap_dm(&recipient, &event).unwrap().rumor.content
        };
        let first = open(&got[0]);
        assert!(first.contains("sent-one") && !first.contains("held-back"));
        let summary = open(&got[1]);
        assert!(summary.contains("1 medium or low finding not sent as direct messages"));
        assert!(!summary.contains("held-back"));
    }

    fn sock(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 7777)
    }

    #[test]
    fn only_lab_subnet_addresses_are_accepted() {
        for ok in [
            "172.29.208.0",
            "172.29.208.5",
            "172.29.208.254",
            "::ffff:172.29.208.9",
        ] {
            assert!(addresses_ok(&[sock(ok)], false).is_ok(), "{ok}");
        }
        for bad in [
            // Other private ranges are not the lab.
            "10.1.2.3",
            "172.16.0.1",
            "172.29.207.255",
            "172.29.209.1",
            "172.28.208.5",
            "192.168.1.1",
            "fd12:3456::1",
            "fc00::1",
            "8.8.8.8",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:8.8.8.8",
            "::ffff:10.0.0.1",
            "::",
        ] {
            assert!(addresses_ok(&[sock(bad)], false).is_err(), "{bad}");
        }
        // One address outside the lab among lab ones refuses the name.
        assert!(addresses_ok(&[sock("172.29.208.1"), sock("10.0.0.1")], false).is_err());
        assert!(addresses_ok(&[sock("172.29.208.1"), sock("8.8.8.8")], false).is_err());
        assert!(addresses_ok(&[], false).is_err());
        // Loopback only when the test hook says so.
        assert!(addresses_ok(&[sock("127.0.0.1")], true).is_ok());
        assert!(addresses_ok(&[sock("10.0.0.1")], true).is_err());
        assert_eq!(
            addresses_ok(&[sock("172.29.208.1"), sock("172.29.208.2")], false).unwrap(),
            sock("172.29.208.1")
        );
    }

    #[test]
    fn a_name_that_resolves_to_another_private_address_is_refused_before_connecting() {
        let (_, events) = wraps(1);
        // Not the loopback test relay: a real relay value is judged by the subnet.
        let relay = RelayUrl::parse("ws://strfry:7777").unwrap();
        let resolver = |_: &str, _: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![sock("192.168.1.20")])
        };
        let err = publish_with(&relay, &events, TOTAL_TIMEOUT, &resolver).unwrap_err();
        assert!(matches!(err, NotifyError::Refused(_)), "{err}");
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
    fn an_alert_on_a_chain_that_is_not_allowed_is_dropped_and_counted() {
        use crate::alert::{Alert, AlertParts, Chain, MatchResult, Severity};
        let make = |chain, id: &str| {
            Alert::new(AlertParts {
                product: "LND",
                version: "0.18.4-beta".to_owned(),
                chain,
                advisory_id: id.to_owned(),
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
        let (recipient, _) = wraps(0);
        let sender = Keys::generate(&mut Seq(1)).unwrap();
        for chain in [Chain::Mainnet, Chain::Testnet, Chain::Unknown] {
            let (port, seen, handle) = fake_relay(Mode::Accept);
            // The node set is fine, but this one alert is on another chain: it is
            // never sent, the good one still is, and the summary counts it.
            let out = crate::send_alerts(
                &RelayUrl::loopback_for_test(port),
                &sender,
                &recipient.public_x().unwrap(),
                &[make(Chain::Regtest, "good-one"), make(chain, "bad-chain")],
                &[Chain::Regtest],
                &Fixed(1),
                &mut Seq(3),
            )
            .unwrap();
            assert_eq!(out.len(), 2, "{chain:?}");
            handle.join().unwrap();
            let got = seen.lock().unwrap().clone();
            let texts: Vec<String> = got
                .iter()
                .map(|raw| {
                    let v: Value = serde_json::from_str(raw).unwrap();
                    let event = Event::from_json(&v[1].to_string()).unwrap();
                    unwrap_dm(&recipient, &event).unwrap().rumor.content
                })
                .collect();
            assert!(texts[0].contains("good-one"), "{chain:?}");
            assert!(!texts.iter().any(|t| t.contains("bad-chain")), "{chain:?}");
            assert!(
                texts[1].contains("1 finding not sent because they are about a chain other than"),
                "{chain:?}"
            );
        }
    }

    #[test]
    fn a_node_that_is_not_on_regtest_or_signet_still_refuses_the_whole_run() {
        use crate::alert::Chain;
        let sender = Keys::generate(&mut Seq(1)).unwrap();
        let relay = RelayUrl::loopback_for_test(1);
        for chains in [vec![Chain::Mainnet], vec![Chain::Unknown], vec![]] {
            let err = crate::send_alerts(
                &relay,
                &sender,
                &[7u8; 32],
                &[],
                &chains,
                &Fixed(1),
                &mut Seq(3),
            )
            .unwrap_err();
            assert!(matches!(err, NotifyError::Refused(_)), "{chains:?}");
        }
    }

    #[test]
    fn a_short_ack_a_conflicting_repeat_and_an_unknown_id_do_not_change_the_outcome() {
        let (_, events) = wraps(2);
        let (port, _seen, handle) = fake_relay(Mode::Conflicting);
        let out = publish(&RelayUrl::loopback_for_test(port), &events).unwrap();
        assert_eq!(out.len(), 2);
        // The first answer for the first event stands; the later "false" is ignored.
        assert!(out[0].accepted && out[1].accepted);
        assert_eq!(out[0].event_id, events[0].id);
        assert_eq!(out[1].event_id, events[1].id);
        assert!(out[0].message.escape_for_terminal().is_empty());
        handle.join().unwrap();
    }

    #[test]
    fn a_valid_five_field_rejection_is_reported_as_that_rejection() {
        let (_, events) = wraps(1);
        let (port, _seen, handle) = fake_relay(Mode::FiveFields);
        let out = publish(&RelayUrl::loopback_for_test(port), &events).unwrap();
        assert!(!out[0].accepted);
        assert!(
            out[0]
                .message
                .escape_for_terminal()
                .starts_with("blocked: spam")
        );
        drop(handle);
    }

    #[test]
    fn a_five_field_ack_with_a_fifth_field_that_is_not_text_counts_as_ignored() {
        let (_, events) = wraps(1);
        let (port, _seen, handle) = fake_relay(Mode::BadFifth);
        let err = publish(&RelayUrl::loopback_for_test(port), &events).unwrap_err();
        assert!(
            matches!(err, NotifyError::Relay(m) if m.contains("too many")),
            "{err}"
        );
        drop(handle);
    }

    #[test]
    fn pings_count_toward_the_limit_on_unrelated_messages() {
        let (_, events) = wraps(1);
        let (port, _seen, handle) = fake_relay(Mode::Pings);
        let err = publish(&RelayUrl::loopback_for_test(port), &events).unwrap_err();
        assert!(
            matches!(err, NotifyError::Relay(m) if m.contains("too many")),
            "{err}"
        );
        drop(handle);
    }

    #[test]
    fn a_send_with_nothing_eligible_sends_nothing_and_never_wraps() {
        use crate::alert::{Alert, AlertParts, Chain, MatchResult, Severity};
        struct NeverClock;
        impl Clock for NeverClock {
            fn now_unix(&self) -> Result<u64, NotifyError> {
                Err(NotifyError::Refused("the clock must not be read"))
            }
        }
        struct NeverEntropy;
        impl Entropy for NeverEntropy {
            fn fill(&mut self, _: &mut [u8]) -> Result<(), NotifyError> {
                Err(NotifyError::Entropy)
            }
        }
        let alert = Alert::new(AlertParts {
            product: "LND",
            version: "0.18.4-beta".to_owned(),
            chain: Chain::Unknown,
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
        .unwrap();
        let sender = Keys::generate(&mut Seq(1)).unwrap();
        // Nothing listens on this port either: a connection would be an error.
        let out = crate::send_alerts(
            &RelayUrl::loopback_for_test(1),
            &sender,
            &[7u8; 32],
            &[alert],
            &[Chain::Regtest],
            &NeverClock,
            &mut NeverEntropy,
        )
        .unwrap();
        assert!(out.is_empty());
    }

    /// A relay that never finishes a sentence: it sends one byte every 300 ms.
    /// `after_handshake` makes it a proper websocket first, then drip its OK.
    fn drip_relay(after_handshake: bool) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().unwrap();
            let bytes: Vec<u8> = if after_handshake {
                let mut ws = tungstenite::accept(stream.try_clone().unwrap()).unwrap();
                let Ok(Message::Text(text)) = ws.read() else {
                    return;
                };
                let v: Value = serde_json::from_str(text.as_str()).unwrap();
                let reply = serde_json::json!(["OK", v[1]["id"], true, ""]).to_string();
                let mut frame = vec![0x81, u8::try_from(reply.len()).unwrap()];
                frame.extend_from_slice(reply.as_bytes());
                frame
            } else {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n".to_vec()
            };
            for byte in bytes {
                if stream.write_all(&[byte]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(300));
            }
        });
        port
    }

    #[test]
    fn a_relay_that_drips_one_byte_at_a_time_cannot_outlast_the_deadline() {
        for after_handshake in [false, true] {
            let (_, events) = wraps(1);
            let port = drip_relay(after_handshake);
            let total = Duration::from_millis(1500);
            let start = Instant::now();
            let err = publish_with(
                &RelayUrl::loopback_for_test(port),
                &events,
                total,
                &loopback_resolver,
            )
            .unwrap_err();
            let took = start.elapsed();
            assert!(
                matches!(err, NotifyError::Relay(m) if m.contains("timed out")),
                "{after_handshake}: {err}"
            );
            assert!(
                took < total + Duration::from_secs(1),
                "{after_handshake}: {took:?}"
            );
        }
    }
}
