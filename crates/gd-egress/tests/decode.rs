//! Unpacking compressed request bodies: what is decoded, what fails closed, and the bounds.

// Test-only crate: see `crates/gd-core/tests/judge_d_injection.rs` for why helpers need this.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod support;

use gd_egress::decode::{BOUND, MAX_OUTPUT, UNDECODED, decode_body};
use std::io::Read;
use support::*;

const SECRET: &[u8] = b"nsec1-generated-test-text-only";

fn header(name: &str, value: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![(name.as_bytes().to_vec(), value.as_bytes().to_vec())]
}

fn last_layer(headers: &[(Vec<u8>, Vec<u8>)], body: &[u8]) -> Option<Vec<u8>> {
    decode_body(headers, body).layers.last().cloned()
}

#[test]
fn the_test_helpers_make_valid_streams() {
    // Checked against the decoders directly, so a broken helper cannot hide a broken judge.
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gzip(SECRET)[..])
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, SECRET);
    out.clear();
    flate2::read::ZlibDecoder::new(&zlib(SECRET)[..])
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, SECRET);
    out.clear();
    flate2::read::DeflateDecoder::new(&deflate_raw(SECRET)[..])
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, SECRET);
    out.clear();
    brotli_decompressor::Decompressor::new(&brotli_stored(SECRET)[..], 4096)
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, SECRET);
}

#[test]
fn each_declared_coding_is_decoded() {
    let cases: [(&str, Vec<u8>); 7] = [
        ("gzip", gzip(SECRET)),
        ("x-gzip", gzip(SECRET)),
        ("GZIP", gzip(SECRET)),
        ("deflate", zlib(SECRET)),
        ("deflate", deflate_raw(SECRET)),
        ("br", brotli_stored(SECRET)),
        ("  gzip ", gzip(SECRET)),
    ];
    for (coding, body) in cases {
        let decoded = decode_body(&header("Content-Encoding", coding), &body);
        assert_eq!(
            decoded.layers.last().map(Vec::as_slice),
            Some(SECRET),
            "{coding}"
        );
        assert!(
            decoded.problems.is_empty(),
            "{coding}: {:?}",
            decoded.problems
        );
    }
    // Header names are matched without regard to case; several codings apply in reverse order.
    let stacked = brotli_stored(&gzip(SECRET));
    let decoded = decode_body(&header("content-encoding", "gzip, br"), &stacked);
    assert_eq!(decoded.layers.last().map(Vec::as_slice), Some(SECRET));
    assert!(decoded.problems.is_empty());
}

#[test]
fn gzip_and_zlib_are_found_by_their_first_bytes() {
    assert_eq!(last_layer(&[], &gzip(SECRET)).as_deref(), Some(SECRET));
    for first_two in [[0x78u8, 0x01], [0x78, 0x5e], [0x78, 0x9c], [0x78, 0xda]] {
        // A zlib header with this pair, then stored deflate data: only the sniffing is under test.
        let mut body = first_two.to_vec();
        body.extend([0x01, 0x05, 0x00, 0xfa, 0xff]);
        body.extend(b"hello");
        body.extend([0x06, 0x2c, 0x02, 0x15]); // adler32 of "hello"
        let decoded = decode_body(&[], &body);
        assert_eq!(
            decoded.layers.last().map(Vec::as_slice),
            Some(&b"hello"[..]),
            "{first_two:02x?}"
        );
        assert!(decoded.problems.is_empty(), "{first_two:02x?}");
    }
    // Content type alone also says gzip.
    for content_type in ["application/gzip", "application/x-gzip"] {
        let decoded = decode_body(&header("Content-Type", content_type), &gzip(SECRET));
        assert_eq!(decoded.layers.last().map(Vec::as_slice), Some(SECRET));
    }
}

#[test]
fn plain_bodies_give_nothing_and_no_problem() {
    for body in [&b"{\"a\":1}"[..], b"", b"x", b"\x1f", b"POST / HTTP/1.1"] {
        let decoded = decode_body(&[], body);
        assert!(
            decoded.layers.is_empty() && decoded.problems.is_empty(),
            "{body:?}"
        );
    }
    for (name, value) in [
        ("Content-Encoding", "identity"),
        ("Content-Encoding", ""),
        ("Transfer-Encoding", "chunked"),
        ("Transfer-Encoding", "identity"),
        ("grpc-encoding", "identity"),
        ("Content-Type", "application/json"),
    ] {
        let decoded = decode_body(&header(name, value), b"{\"a\":1}");
        assert!(decoded.problems.is_empty(), "{name}: {value}");
    }
    // An empty body has nothing hidden in it, whatever the header says.
    let empty = decode_body(&header("Content-Encoding", "gzip"), b"");
    assert!(empty.problems.is_empty());
}

#[test]
fn unsupported_codings_and_formats_fail_closed() {
    for (name, value) in [
        ("Content-Encoding", "zstd"),
        ("Content-Encoding", "compress"),
        ("Content-Encoding", "snappy"),
        ("Content-Encoding", "gzip, zstd"),
        ("Content-Encoding", "something-new"),
        ("Transfer-Encoding", "compress, chunked"),
        ("Content-Type", "application/zstd"),
        ("Content-Type", "application/x-zstd"),
        ("Content-Type", "application/x-xz"),
        ("Content-Type", "application/x-bzip2"),
        ("Content-Type", "application/zip"),
        ("Content-Type", "application/x-7z-compressed"),
        ("grpc-encoding", "zstd"),
        ("grpc-encoding", "snappy"),
    ] {
        let decoded = decode_body(&header(name, value), &grpc_frame(true, b"opaque"));
        assert_eq!(
            decoded.problems.iter().copied().collect::<Vec<_>>(),
            [UNDECODED],
            "{name}: {value}"
        );
    }
    for magic in [
        &[0x28u8, 0xb5, 0x2f, 0xfd][..],
        &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00],
        &[0x42, 0x5a, 0x68],
        &[0x50, 0x4b, 0x03, 0x04],
        &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c],
    ] {
        let mut body = magic.to_vec();
        body.extend(b"....");
        let decoded = decode_body(&[], &body);
        assert!(decoded.problems.contains(UNDECODED), "{magic:02x?}");
    }
}

#[test]
fn corrupt_and_mislabelled_streams_fail_closed() {
    let whole = gzip(&b"some harmless words ".repeat(50));
    let truncated = &whole[..whole.len() / 2];
    let mut flipped = whole.clone();
    let middle = flipped.len() / 2;
    flipped[middle] ^= 0xff;
    let mut trailing = whole.clone();
    trailing.extend(b"trailing bytes");
    let mut bad_crc = whole.clone();
    let end = bad_crc.len();
    bad_crc[end - 6] ^= 0xff;
    for (label, headers, body) in [
        (
            "truncated",
            header("Content-Encoding", "gzip"),
            truncated.to_vec(),
        ),
        ("flipped", header("Content-Encoding", "gzip"), flipped),
        ("bad checksum", header("Content-Encoding", "gzip"), bad_crc),
        (
            "trailing bytes",
            header("Content-Encoding", "gzip"),
            trailing,
        ),
        ("magic only", vec![], vec![0x1f, 0x8b]),
        (
            "labelled gzip, plain text",
            header("Content-Encoding", "gzip"),
            b"not compressed".to_vec(),
        ),
        (
            "labelled br, plain text",
            header("Content-Encoding", "br"),
            b"not compressed at all".to_vec(),
        ),
        (
            "labelled deflate, plain text",
            header("Content-Encoding", "deflate"),
            b"not compressed".to_vec(),
        ),
        (
            "labelled gzip, zlib body",
            header("Content-Encoding", "gzip"),
            zlib(SECRET),
        ),
    ] {
        let decoded = decode_body(&headers, &body);
        assert!(
            decoded.problems.contains(UNDECODED),
            "{label}: {:?}",
            decoded.problems
        );
    }
}

#[test]
fn the_size_ratio_and_layer_bounds_are_real() {
    // Size: stored blocks (ratio 1 to 1) that decode to more than 16 MiB stop at 16 MiB.
    let big = vec![b'a'; MAX_OUTPUT + 4096];
    let decoded = decode_body(&header("Content-Encoding", "gzip"), &gzip_stored(&big));
    assert!(decoded.problems.contains(BOUND), "{:?}", decoded.problems);
    assert!(decoded.layers.iter().all(|l| l.len() <= MAX_OUTPUT));
    // Exactly at the limit is fine.
    let exact = vec![b'b'; MAX_OUTPUT];
    let decoded = decode_body(&header("Content-Encoding", "gzip"), &gzip_stored(&exact));
    assert!(decoded.problems.is_empty(), "{:?}", decoded.problems);
    assert_eq!(decoded.layers.last().map(Vec::len), Some(MAX_OUTPUT));
    // Ratio: zeros shrink about 1000 to 1, and 8 MiB of them is over the line.
    let zeros = gzip_best(&vec![0u8; 8 * 1024 * 1024]);
    assert!(
        zeros.len() * 1000 < 8 * 1024 * 1024,
        "the test input must be a bomb: {} bytes",
        zeros.len()
    );
    let decoded = decode_body(&header("Content-Encoding", "gzip"), &zeros);
    assert!(decoded.problems.contains(BOUND), "{:?}", decoded.problems);
    // A body that compresses well but under the ratio is fine.
    let tame = gzip(&b"abcdefgh".repeat(10_000));
    let decoded = decode_body(&header("Content-Encoding", "gzip"), &tame);
    assert!(decoded.problems.is_empty(), "{:?}", decoded.problems);
    // Layers: three nested are unpacked, a fourth is a bound, never a pass.
    let three = decode_body(&[], &gzip_layers(SECRET, 3));
    assert!(three.problems.is_empty(), "{:?}", three.problems);
    assert_eq!(three.layers.last().map(Vec::as_slice), Some(SECRET));
    let four = decode_body(&[], &gzip_layers(SECRET, 4));
    assert!(four.problems.contains(BOUND), "{:?}", four.problems);
    assert_ne!(four.layers.last().map(Vec::as_slice), Some(SECRET));
}

#[test]
fn grpc_messages_are_unpacked_frame_by_frame() {
    let headers = header("grpc-encoding", "gzip");
    let mut body = grpc_frame(false, b"plain message");
    body.extend(grpc_frame(true, &gzip(SECRET)));
    let decoded = decode_body(&headers, &body);
    assert!(decoded.problems.is_empty(), "{:?}", decoded.problems);
    assert!(decoded.layers.iter().any(|l| l == SECRET));
    // deflate (zlib) messages too.
    let deflated = decode_body(
        &header("grpc-encoding", "deflate"),
        &grpc_frame(true, &zlib(SECRET)),
    );
    assert!(deflated.layers.iter().any(|l| l == SECRET));
    // A frame that runs past the body, a bad flag, or a bad message is not readable.
    let mut cut = grpc_frame(true, &gzip(SECRET));
    cut.truncate(cut.len() - 3);
    assert!(decode_body(&headers, &cut).problems.contains(UNDECODED));
    let mut flag = grpc_frame(true, &gzip(SECRET));
    flag[0] = 2;
    assert!(decode_body(&headers, &flag).problems.contains(UNDECODED));
    assert!(
        decode_body(&headers, &grpc_frame(true, b"not gzip"))
            .problems
            .contains(UNDECODED)
    );
}
