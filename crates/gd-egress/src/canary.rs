//! The eleven canary classes: fake secrets that must never leave the box.
//!
//! They are made from one seeded stream, so a run can be repeated. Several
//! carry a valid checksum (BIP39, bech32, base58check, onion v3), so a future
//! Guard Dog parser that validates them still treats them as real.

use crate::bip39;
use crate::encode::{
    base32_lower, base58check, base64, bech32, hex, hex_decode, ipv6_text, onion_label,
};
use crate::prng::SplitMix64;
use serde_json::{Value, json};

/// Which kind of secret a canary imitates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// 24 BIP39 words.
    SeedPhrase,
    /// A Nostr private key, `nsec1...`.
    Nsec,
    /// A BIP32 extended public key.
    Xpub,
    /// An LND macaroon (binary, with a hex text form).
    Macaroon,
    /// A v3 onion address.
    Onion,
    /// A public IPv4 address (documentation range).
    Ipv4,
    /// A public IPv6 address (documentation range).
    Ipv6,
    /// A node RPC password in the lab's `gdlabcanary-` shape.
    RpcPassword,
    /// A Core Lightning rune.
    ClnRune,
    /// A Lightning node public key.
    NodePubkey,
    /// The machine's hostname.
    Hostname,
}

impl Class {
    /// Every class, in generation order.
    pub const ALL: [Class; 11] = [
        Class::SeedPhrase,
        Class::Nsec,
        Class::Xpub,
        Class::Macaroon,
        Class::Onion,
        Class::Ipv4,
        Class::Ipv6,
        Class::RpcPassword,
        Class::ClnRune,
        Class::NodePubkey,
        Class::Hostname,
    ];

    /// The name used in `canaries.json` and in reports.
    pub fn name(self) -> &'static str {
        match self {
            Class::SeedPhrase => "seed-phrase",
            Class::Nsec => "nsec",
            Class::Xpub => "xpub",
            Class::Macaroon => "macaroon",
            Class::Onion => "onion",
            Class::Ipv4 => "ipv4",
            Class::Ipv6 => "ipv6",
            Class::RpcPassword => "rpc-password",
            Class::ClnRune => "cln-rune",
            Class::NodePubkey => "node-pubkey",
            Class::Hostname => "hostname",
        }
    }

    /// Looks a class up by its name.
    pub fn from_name(name: &str) -> Option<Class> {
        Class::ALL.into_iter().find(|c| c.name() == name)
    }
}

/// One planted secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canary {
    /// Its class.
    pub class: Class,
    /// The text form.
    pub text: String,
    /// The raw bytes, for the macaroon only (its text is their hex).
    pub bytes: Option<Vec<u8>>,
}

/// All canaries of one run, plus the control token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanarySet {
    /// The seed they were made from.
    pub seed: u64,
    /// One per class, in generation order.
    pub canaries: Vec<Canary>,
    /// Tags the control flows. Not a canary.
    pub control_token: String,
}

fn xpub_text(rng: &mut SplitMix64) -> String {
    let fingerprint = rng.fill_bytes(4);
    let child = rng.fill_bytes(4);
    let chain_code = rng.fill_bytes(32);
    let prefix = rng.fill_bytes(1);
    let x = rng.fill_bytes(32);
    let mut payload = vec![0x04, 0x88, 0xB2, 0x1E, 0x03];
    payload.extend(fingerprint);
    payload.extend(child);
    payload.extend(chain_code);
    payload.push(if prefix.first().is_some_and(|b| b & 1 == 1) {
        3
    } else {
        2
    });
    payload.extend(x);
    base58check(&payload)
}

/// Makes every canary from `seed`. The draw order is fixed: a golden file pins it.
pub fn generate(seed: u64) -> CanarySet {
    let mut rng = SplitMix64::new(seed);
    let mut canaries = Vec::new();
    let mut push = |class: Class, text: String, bytes: Option<Vec<u8>>| {
        canaries.push(Canary { class, text, bytes });
    };

    let entropy = rng.fill_bytes(32);
    push(
        Class::SeedPhrase,
        bip39::mnemonic(&entropy).unwrap_or_default(),
        None,
    );

    let key = rng.fill_bytes(32);
    push(Class::Nsec, bech32("nsec", &key), None);

    push(Class::Xpub, xpub_text(&mut rng), None);

    let mut mac = vec![0x02, 0x01, 0x03, 0x6c, 0x6e, 0x64];
    mac.extend(rng.fill_bytes(94));
    push(Class::Macaroon, hex(&mac), Some(mac));

    let onion_key = rng.fill_bytes(32);
    push(
        Class::Onion,
        format!("{}.onion", onion_label(&onion_key)),
        None,
    );

    let last_octet = 1 + rng.next_u64() % 254;
    push(Class::Ipv4, format!("198.51.100.{last_octet}"), None);

    let mut groups = [0x2001u16, 0x0db8, 0, 0, 0, 0, 0, 0];
    for g in groups.iter_mut().skip(2) {
        *g = u16::try_from(rng.next_u64() & 0xffff).unwrap_or(0);
    }
    push(Class::Ipv6, ipv6_text(groups), None);

    push(
        Class::RpcPassword,
        format!("gdlabcanary-{}", hex(&rng.fill_bytes(32))),
        None,
    );

    push(
        Class::ClnRune,
        base64(&rng.fill_bytes(48), true, false),
        None,
    );

    let selector = rng.fill_bytes(1);
    let prefix = if selector.first().is_some_and(|b| b & 1 == 1) {
        "03"
    } else {
        "02"
    };
    push(
        Class::NodePubkey,
        format!("{prefix}{}", hex(&rng.fill_bytes(32))),
        None,
    );

    let host: String = base32_lower(&rng.fill_bytes(10), false)
        .chars()
        .take(10)
        .collect();
    push(Class::Hostname, format!("gdcanary-host-{host}"), None);

    let token: String = base32_lower(&rng.fill_bytes(15), false)
        .chars()
        .take(20)
        .collect();
    CanarySet {
        seed,
        canaries,
        control_token: format!("gdctl{token}"),
    }
}

impl CanarySet {
    /// The canary of `class`.
    pub fn get(&self, class: Class) -> Option<&Canary> {
        self.canaries.iter().find(|c| c.class == class)
    }

    /// The text of `class`, or an empty string if the set has none.
    pub fn text(&self, class: Class) -> &str {
        self.get(class).map_or("", |c| c.text.as_str())
    }

    /// The macaroon's raw bytes.
    pub fn macaroon_bytes(&self) -> &[u8] {
        self.get(Class::Macaroon)
            .and_then(|c| c.bytes.as_deref())
            .unwrap_or(&[])
    }

    /// `canaries.json`: sorted keys, two-space indent, trailing newline.
    pub fn to_json(&self) -> String {
        let items: Vec<Value> = self
            .canaries
            .iter()
            .map(|c| match &c.bytes {
                Some(bytes) => {
                    json!({"class": c.class.name(), "text": c.text, "bytes_hex": hex(bytes)})
                }
                None => json!({"class": c.class.name(), "text": c.text}),
            })
            .collect();
        let doc = json!({
            "canaries": items,
            "control_token": self.control_token,
            "format": 1,
            "seed": self.seed.to_string(),
        });
        let mut text = serde_json::to_string_pretty(&doc).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Reads `canaries.json` back. Fails closed: every class must appear exactly once.
    pub fn from_json(text: &str) -> Result<CanarySet, String> {
        let doc: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
        if doc.get("format") != Some(&json!(1)) {
            return Err("format must be 1".into());
        }
        let seed = doc
            .get("seed")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or("seed must be a decimal string")?;
        let control_token = doc
            .get("control_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .ok_or("control_token missing")?
            .to_string();
        let items = doc
            .get("canaries")
            .and_then(Value::as_array)
            .ok_or("canaries missing")?;
        let mut canaries = Vec::new();
        for item in items {
            let name = item
                .get("class")
                .and_then(Value::as_str)
                .ok_or("class missing")?;
            let class = Class::from_name(name).ok_or("unknown class")?;
            let text = item
                .get("text")
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
                .ok_or("text missing")?;
            let bytes = match item.get("bytes_hex").and_then(Value::as_str) {
                Some(h) => Some(hex_decode(h).ok_or("bytes_hex is not hex")?),
                None => None,
            };
            if canaries.iter().any(|c: &Canary| c.class == class) {
                return Err("a class appears twice".into());
            }
            canaries.push(Canary {
                class,
                text: text.to_string(),
                bytes,
            });
        }
        if canaries.len() != Class::ALL.len() {
            return Err("every class must appear".into());
        }
        if canaries
            .iter()
            .any(|c| c.class == Class::Macaroon && c.bytes.is_none())
        {
            return Err("the macaroon needs bytes_hex".into());
        }
        Ok(CanarySet {
            seed,
            canaries,
            control_token,
        })
    }

    /// `leak.env` for the deliberate-leak run: single-quoted `KEY='value'` lines.
    pub fn leak_env(&self) -> Result<String, String> {
        let label: String = self.text(Class::Macaroon).chars().take(60).collect();
        let lines = [
            ("GD_LEAK_NSEC", self.text(Class::Nsec).to_string()),
            ("GD_LEAK_SEED", self.text(Class::SeedPhrase).to_string()),
            ("GD_LEAK_XPUB", self.text(Class::Xpub).to_string()),
            ("GD_LEAK_MACAROON_LABEL", label),
            (
                "GD_LEAK_MACAROON_B64",
                base64(self.macaroon_bytes(), false, true),
            ),
        ];
        let mut out = String::new();
        for (key, value) in lines {
            if value.contains('\'') || value.contains('\n') {
                return Err(format!("{key} holds a quote or a newline"));
            }
            out.push_str(&format!("{key}='{value}'\n"));
        }
        Ok(out)
    }

    /// `control.env`: one line.
    pub fn control_env(&self) -> String {
        format!("GD_CONTROL_TOKEN={}\n", self.control_token)
    }
}
