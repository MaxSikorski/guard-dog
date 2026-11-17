//! Unpacking compressed request bodies before they are scanned.
//!
//! A leak hidden in a gzip, deflate or brotli body is invisible to a byte scan, so each body is
//! decoded first, in pure Rust, under hard bounds: at most 16 MiB of decoded output per body, at
//! most 1000 times the size of what is being decoded, and at most three nested layers. Hitting a
//! bound is never a pass; neither is a stream that will not decode, or a format that is not
//! supported (zstd, xz, bzip2, zip, 7z). Those come back as problem codes and become findings.
//!
//! What is decoded is decided by the headers (`Content-Encoding`, `Transfer-Encoding`,
//! `Content-Type`, `grpc-encoding`) and by the first bytes of the body and of every decoded layer,
//! whichever says "compressed". `chunked` is plain message framing, which the recorder has already
//! removed, so it is not a compression. What decoded before a corrupt stream went bad is still scanned; what a bound cut off is dropped.

use brotli_decompressor::{BrotliDecompressStream, BrotliResult, BrotliState, StandardAlloc};
use flate2::bufread::{DeflateDecoder, GzDecoder, MultiGzDecoder, ZlibDecoder};
use std::collections::BTreeSet;
use std::io::Read;

/// Decoded output is cut at this many bytes per body (all layers together).
pub const MAX_OUTPUT: usize = 16 * 1024 * 1024;
/// Decoded output may be at most this many times its input.
pub const MAX_RATIO: usize = 1000;
/// Nested decoding stops after this many layers.
pub const MAX_LAYERS: usize = 3;
/// A coding that is not decoded, or a stream that is corrupt.
pub const UNDECODED: &str = "undecoded-content-encoding";
/// A bound was hit: output size, ratio or layers.
pub const BOUND: &str = "decode-bound";

/// All bodies of one capture together may decode to at most this many bytes.
pub const MAX_CAPTURE_OUTPUT: usize = 64 * 1024 * 1024;
/// All bodies of one capture together may have at most this many decoded layers.
pub const MAX_CAPTURE_LAYERS: usize = 4096;

/// What is left to decode in a capture. Pass the same one to every body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Decoded bytes still allowed.
    pub output: usize,
    /// Decoded layers still allowed.
    pub layers: usize,
}

impl Budget {
    /// The budget of a whole capture.
    pub fn capture() -> Budget {
        Budget {
            output: MAX_CAPTURE_OUTPUT,
            layers: MAX_CAPTURE_LAYERS,
        }
    }
}

/// One body may have at most this many decoded layers.
pub const MAX_BODY_LAYERS: usize = 1024;
/// At most this many gzip streams are tried inside one plain body or layer.
const MAX_EMBEDDED: usize = 64;

/// What one decode may use: the body's own bounds, cut down to what the capture has left.
#[derive(Debug, Clone, Copy)]
struct Caps {
    output: usize,
    layers: usize,
    /// Look for gzip streams inside plain bytes (off for a framed gRPC body, whose messages are
    /// looked at one by one instead).
    embedded: bool,
}

/// Like [`decode_body`], but charged to a capture-wide `budget`: what this body decodes to, and
/// the layers it takes, are taken off it. Past it the answer is [`BOUND`].
pub fn decode_with(headers: &[(Vec<u8>, Vec<u8>)], body: &[u8], budget: &mut Budget) -> Decoded {
    let caps = Caps {
        output: MAX_OUTPUT.min(budget.output),
        layers: MAX_BODY_LAYERS.min(budget.layers),
        embedded: true,
    };
    let out = decode_caps(headers, body, caps);
    budget.output = budget.output.saturating_sub(out.total());
    budget.layers = budget.layers.saturating_sub(out.layers.len());
    out
}

/// What decoding one body gave.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// Every decoded output, one per layer (not the body itself).
    pub layers: Vec<Vec<u8>>,
    /// Problem codes: [`UNDECODED`] or [`BOUND`].
    pub problems: BTreeSet<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coding {
    Gzip,
    Deflate,
    Brotli,
    Unsupported,
}

impl Decoded {
    fn total(&self) -> usize {
        self.layers.iter().map(Vec::len).sum()
    }
}

/// One coding name from a header value. `None` means "nothing to decode".
fn coding_of(token: &str, transfer: bool) -> Option<Coding> {
    let name = token.split(';').next().unwrap_or("").trim();
    match name {
        "" | "identity" => None,
        "chunked" if transfer => None,
        "gzip" | "x-gzip" => Some(Coding::Gzip),
        "deflate" => Some(Coding::Deflate),
        "br" => Some(Coding::Brotli),
        _ => Some(Coding::Unsupported),
    }
}

fn codings_in(value: &[u8], transfer: bool) -> Vec<Coding> {
    String::from_utf8_lossy(value)
        .to_ascii_lowercase()
        .split(',')
        .filter_map(|t| coding_of(t, transfer))
        .collect()
}

/// What the first bytes of a body say it is.
fn sniff(data: &[u8]) -> Option<Coding> {
    let starts = |magic: &[u8]| data.starts_with(magic);
    if starts(&[0x1f, 0x8b]) {
        Some(Coding::Gzip)
    } else if zlib_header(data) {
        Some(Coding::Deflate)
    } else if starts(&[0x28, 0xb5, 0x2f, 0xfd])
        || starts(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])
        || starts(&[0x42, 0x5a, 0x68])
        || starts(&[0x50, 0x4b, 0x03, 0x04])
        || starts(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])
    {
        Some(Coding::Unsupported)
    } else {
        None
    }
}

/// Whether `data` starts like a gzip or zlib stream.
pub fn starts_compressed(data: &[u8]) -> bool {
    matches!(sniff(data), Some(Coding::Gzip | Coding::Deflate))
}

/// How a decode ended, besides success.
enum Fail {
    Corrupt,
    Bound,
}

/// Reads `reader` to the end, but not past `limit` bytes. Whatever was read is kept.
fn read_limited<R: Read>(reader: R, limit: usize) -> (Vec<u8>, Result<(), Fail>) {
    let mut out = Vec::new();
    let read = reader.take(limit as u64 + 1).read_to_end(&mut out);
    if out.len() > limit {
        out.truncate(limit);
        return (out, Err(Fail::Bound));
    }
    (out, read.map(|_| ()).map_err(|_| Fail::Corrupt))
}

/// A decode that ended cleanly but left bytes of the input unread is a failure.
fn all_used(result: (Vec<u8>, Result<(), Fail>), unread: &[u8]) -> (Vec<u8>, Result<(), Fail>) {
    match result {
        (out, Ok(())) if !unread.is_empty() => (out, Err(Fail::Corrupt)),
        other => other,
    }
}

fn brotli(data: &[u8], limit: usize) -> (Vec<u8>, Result<(), Fail>) {
    let mut state = BrotliState::new(
        StandardAlloc::default(),
        StandardAlloc::default(),
        StandardAlloc::default(),
    );
    let mut out = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let (mut input_offset, mut total_out) = (0usize, 0usize);
    loop {
        let mut available_in = data.len().saturating_sub(input_offset);
        let mut available_out = buffer.len();
        let mut output_offset = 0usize;
        let result = BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            data,
            &mut available_out,
            &mut output_offset,
            buffer.as_mut_slice(),
            &mut total_out,
            &mut state,
        );
        out.extend_from_slice(buffer.get(..output_offset).unwrap_or(&[]));
        if out.len() > limit {
            out.truncate(limit);
            return (out, Err(Fail::Bound));
        }
        match result {
            BrotliResult::ResultSuccess => {
                let all_used = input_offset == data.len();
                return (out, if all_used { Ok(()) } else { Err(Fail::Corrupt) });
            }
            BrotliResult::NeedsMoreOutput => {}
            BrotliResult::NeedsMoreInput | BrotliResult::ResultFailure => {
                return (out, Err(Fail::Corrupt));
            }
        }
    }
}

/// A zlib header: deflate method, no preset dictionary (nobody could decode one) and a header
/// checksum that divides by 31.
fn zlib_header(data: &[u8]) -> bool {
    matches!(data, [cmf, flg, ..]
        if cmf & 0x0f == 8
            && flg & 0x20 == 0
            && ((u16::from(*cmf) << 8) | u16::from(*flg)) % 31 == 0)
}

/// Decodes one layer. `budget` is what the body may still decode in all.
fn decode_one(coding: Coding, data: &[u8], budget: usize) -> (Vec<u8>, Result<(), Fail>) {
    let limit = budget.min(data.len().saturating_mul(MAX_RATIO));
    let mut unread = data;
    match coding {
        Coding::Gzip => {
            let result = read_limited(MultiGzDecoder::new(&mut unread), limit);
            all_used(result, unread)
        }
        Coding::Brotli => brotli(data, limit),
        Coding::Deflate => {
            // HTTP says zlib; some clients send raw deflate. A zlib header means zlib: its output
            // is kept, and bytes left over after it are a failure. Only when that gave nothing at
            // all, or there is no zlib header, is the raw reading used.
            if zlib_header(data) {
                let result = read_limited(ZlibDecoder::new(&mut unread), limit);
                let first = all_used(result, unread);
                if !first.0.is_empty() || !matches!(first.1, Err(Fail::Corrupt)) {
                    return first;
                }
                unread = data;
                let raw = all_used(
                    read_limited(DeflateDecoder::new(&mut unread), limit),
                    unread,
                );
                return if raw.1.is_ok() { raw } else { first };
            }
            let result = read_limited(DeflateDecoder::new(&mut unread), limit);
            all_used(result, unread)
        }
        Coding::Unsupported => (Vec::new(), Err(Fail::Corrupt)),
    }
}

/// Applies `steps` (then whatever the first bytes show) to `data`, from layer `depth` on.
/// Every decoded layer is added to `out`. Returns false once a problem has stopped the decoding.
fn unpack(data: &[u8], steps: &[Coding], mut depth: usize, out: &mut Decoded, caps: Caps) -> bool {
    let mut declared = steps.iter().copied();
    let mut last: Option<usize> = None;
    loop {
        let input = last
            .and_then(|i| out.layers.get(i))
            .map_or(data, Vec::as_slice);
        let Some(coding) = declared.next().or_else(|| sniff(input)) else {
            let offsets = if caps.embedded {
                gzip_offsets(input)
            } else {
                Vec::new()
            };
            if offsets.is_empty() {
                return true;
            }
            // Copied, so the layers can grow while the bytes are read.
            let copy = input.to_vec();
            return embedded_gzip(&copy, &offsets, depth, out, caps);
        };
        if coding == Coding::Unsupported {
            out.problems.insert(UNDECODED);
            return false;
        }
        let budget = caps.output.saturating_sub(out.total());
        if depth >= MAX_LAYERS
            || out.layers.len() >= caps.layers
            || (budget == 0 && !input.is_empty())
        {
            out.problems.insert(BOUND);
            return false;
        }
        let (decoded, result) = decode_one(coding, input, budget);
        depth += 1;
        match result {
            // A bound ends it: the run has failed, and unpacking and scanning what a bomb
            // produced is the work it is after, so what was cut off is dropped.
            Err(Fail::Bound) => {
                out.problems.insert(BOUND);
                return false;
            }
            // A stream that goes bad part-way: what did decode is still scanned.
            Err(Fail::Corrupt) => {
                out.layers.push(decoded);
                out.problems.insert(UNDECODED);
                return false;
            }
            Ok(()) => out.layers.push(decoded),
        }
        last = out.layers.len().checked_sub(1);
    }
}

/// Where `1f 8b 08` occurs after the first byte, up to 64 places.
fn gzip_offsets(input: &[u8]) -> Vec<usize> {
    input
        .windows(3)
        .enumerate()
        .skip(1)
        .filter(|(_, w)| *w == [0x1f, 0x8b, 0x08])
        .map(|(at, _)| at)
        .take(MAX_EMBEDDED)
        .collect()
}

/// A gzip stream somewhere inside plain bytes (a file part of a multipart upload, say): tried at
/// each `1f 8b 08` after the start, up to 64 of them. A try that does not decode is chance and is
/// ignored; one that does is a layer, unpacked further like any other.
fn embedded_gzip(
    input: &[u8],
    offsets: &[usize],
    depth: usize,
    out: &mut Decoded,
    caps: Caps,
) -> bool {
    for &at in offsets {
        let mut unread = input.get(at..).unwrap_or(&[]);
        let budget = caps.output.saturating_sub(out.total());
        let limit = budget.min(unread.len().saturating_mul(MAX_RATIO));
        let (decoded, result) = read_limited(GzDecoder::new(&mut unread), limit);
        match result {
            Err(Fail::Corrupt) => {}
            Err(Fail::Bound) => {
                out.problems.insert(BOUND);
                return false;
            }
            Ok(()) => {
                if depth >= MAX_LAYERS || out.layers.len() >= caps.layers {
                    out.problems.insert(BOUND);
                    return false;
                }
                out.layers.push(decoded.clone());
                if !unpack(&decoded, &[], depth + 1, out, caps) {
                    return false;
                }
            }
        }
    }
    true
}

/// The gRPC messages of a body: a flag (0 plain, 1 compressed by `grpc-encoding`), a four-byte
/// length, the message. Every message is decoded in its own right. A message flagged compressed
/// when no coding was named cannot be read.
fn unpack_grpc(body: &[u8], coding: Option<Coding>, depth: usize, out: &mut Decoded, caps: Caps) {
    let mut rest = body;
    while !rest.is_empty() {
        let frame = rest.get(..5).and_then(|h| {
            let length = usize::try_from(u32::from_be_bytes(h.get(1..5)?.try_into().ok()?)).ok()?;
            Some((*h.first()?, length))
        });
        let message = frame
            .filter(|(flag, _)| *flag <= 1)
            .and_then(|(flag, length)| Some((flag, rest.get(5..5usize.checked_add(length)?)?)));
        let Some((flag, message)) = message else {
            out.problems.insert(UNDECODED);
            return;
        };
        let steps: Vec<Coding> = match (flag, coding) {
            (0, _) => Vec::new(),
            (_, Some(coding)) => vec![coding],
            (_, None) => {
                out.problems.insert(UNDECODED);
                return;
            }
        };
        if !unpack(message, &steps, depth, out, caps) {
            return;
        }
        rest = rest.get(5 + message.len()..).unwrap_or(&[]);
    }
}

fn unsupported_content_type(media: &str) -> bool {
    matches!(
        media,
        "application/zstd"
            | "application/x-zstd"
            | "application/x-xz"
            | "application/x-lzma"
            | "application/x-bzip"
            | "application/x-bzip2"
            | "application/zip"
            | "application/x-zip-compressed"
            | "application/x-7z-compressed"
            | "application/x-compress"
            | "application/x-lz4"
            | "application/x-brotli"
    )
}

/// Decodes `body` as its headers (and its first bytes) say, layer by layer, within the bounds
/// of one body.
pub fn decode_body(headers: &[(Vec<u8>, Vec<u8>)], body: &[u8]) -> Decoded {
    decode_caps(
        headers,
        body,
        Caps {
            output: MAX_OUTPUT,
            layers: MAX_BODY_LAYERS,
            embedded: true,
        },
    )
}

fn decode_caps(headers: &[(Vec<u8>, Vec<u8>)], body: &[u8], caps: Caps) -> Decoded {
    let mut out = Decoded::default();
    if body.is_empty() {
        return out;
    }
    let (mut transfer, mut content, mut grpc) = (Vec::new(), Vec::new(), None);
    let mut media = String::new();
    for (name, value) in headers {
        let is = |wanted: &str| name.eq_ignore_ascii_case(wanted.as_bytes());
        if is("transfer-encoding") {
            transfer.extend(codings_in(value, true));
        } else if is("content-encoding") {
            content.extend(codings_in(value, false));
        } else if is("grpc-encoding") {
            grpc = codings_in(value, false).into_iter().next().or(grpc);
        } else if is("content-type") {
            media = String::from_utf8_lossy(value)
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
        }
    }
    // The last coding listed was applied last, so it comes off first; transfer codings are outermost.
    let mut steps: Vec<Coding> = transfer
        .into_iter()
        .rev()
        .chain(content.into_iter().rev())
        .collect();
    if steps.is_empty() && matches!(media.as_str(), "application/gzip" | "application/x-gzip") {
        steps.push(Coding::Gzip);
    }
    if unsupported_content_type(&media) {
        out.problems.insert(UNDECODED);
    }
    // A gRPC body is a run of framed messages, whether or not a coding is named.
    let framed = grpc.is_some() || media.starts_with("application/grpc");
    let whole = Caps {
        embedded: caps.embedded && !framed,
        ..caps
    };
    let decoded_whole = unpack(body, &steps, 0, &mut out, whole);
    match grpc {
        Some(Coding::Unsupported) => {
            out.problems.insert(UNDECODED);
        }
        _ if framed && decoded_whole => {
            // The messages inside whatever the whole body decoded to (usually the body itself).
            let inner = out.layers.last().cloned();
            let depth = out.layers.len();
            unpack_grpc(
                inner.as_deref().unwrap_or(body),
                grpc,
                depth,
                &mut out,
                caps,
            );
        }
        _ => {}
    }
    out
}
