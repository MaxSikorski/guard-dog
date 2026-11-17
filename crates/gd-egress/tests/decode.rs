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

fn zlib_stored(data: &[u8], cmf: u8, flg: u8) -> Vec<u8> {
    // A zlib header with these two bytes, one stored deflate block, and the adler32 checksum.
    let mut body = vec![cmf, flg, 0x01];
    body.extend(u16::try_from(data.len()).unwrap().to_le_bytes());
    body.extend((!u16::try_from(data.len()).unwrap()).to_le_bytes());
    body.extend(data);
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65_521;
        b = (b + a) % 65_521;
    }
    body.extend(((b << 16) | a).to_be_bytes());
    body
}

#[test]
fn every_valid_zlib_header_is_found_by_its_first_bytes() {
    let mut tried = 0;
    // Every window size (the first byte's top half), every second byte that makes the header
    // divisible by 31, with no preset dictionary.
    for cmf in (0..=7u8).map(|w| (w << 4) | 8) {
        for flg in 0..=255u8 {
            if ((u32::from(cmf) << 8) + u32::from(flg)) % 31 != 0 || flg & 0x20 != 0 {
                continue;
            }
            tried += 1;
            let decoded = decode_body(&[], &zlib_stored(SECRET, cmf, flg));
            assert_eq!(
                decoded.layers.last().map(Vec::as_slice),
                Some(SECRET),
                "{cmf:02x} {flg:02x}"
            );
            assert!(decoded.problems.is_empty(), "{cmf:02x} {flg:02x}");
        }
    }
    assert!(tried >= 24, "{tried}");
}

#[test]
fn gzip_inside_a_body_is_found_at_any_offset() {
    let mut multipart = b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"debug.gz\"\r\nContent-Type: application/gzip\r\n\r\n".to_vec();
    multipart.extend(gzip(SECRET));
    multipart.extend(b"\r\n--B--\r\n");
    let headers = header("Content-Type", "multipart/form-data; boundary=B");
    let decoded = decode_body(&headers, &multipart);
    assert!(decoded.layers.iter().any(|l| l == SECRET), "{decoded:?}");
    assert!(decoded.problems.is_empty(), "{:?}", decoded.problems);
    // Two members in one body, and one after a few stray bytes.
    let mut two = b"xx".to_vec();
    two.extend(gzip(SECRET));
    two.extend(b"yy");
    two.extend(gzip(b"second member"));
    let decoded = decode_body(&[], &two);
    assert!(decoded.layers.iter().any(|l| l == SECRET));
    assert!(decoded.layers.iter().any(|l| l == b"second member"));
    // The gzip magic by chance, with no stream behind it, is not a problem.
    let chance = [
        b"text ".to_vec(),
        vec![0x1f, 0x8b, 0x08],
        b" more text".to_vec(),
    ]
    .concat();
    let decoded = decode_body(&[], &chance);
    assert!(decoded.problems.is_empty(), "{:?}", decoded.problems);
    // Plain text has nothing to find.
    assert!(decode_body(&[], b"just text").layers.is_empty());
}

#[test]
fn zlib_with_trailing_bytes_keeps_its_output_and_fails() {
    let mut body = zlib(SECRET);
    body.extend(b"trailing bytes");
    let decoded = decode_body(&header("Content-Encoding", "deflate"), &body);
    assert!(decoded.layers.iter().any(|l| l == SECRET), "{decoded:?}");
    assert!(decoded.problems.contains(UNDECODED));
    // Raw deflate is still taken as raw deflate.
    let decoded = decode_body(&header("Content-Encoding", "deflate"), &deflate_raw(SECRET));
    assert_eq!(decoded.layers.last().map(Vec::as_slice), Some(SECRET));
    assert!(decoded.problems.is_empty());
}

#[test]
fn grpc_frames_marked_compressed_need_an_encoding() {
    let body = grpc_frame(true, &gzip(SECRET));
    for headers in [
        header("Content-Type", "application/grpc"),
        header("Content-Type", "application/grpc+proto"),
        vec![
            (b"Content-Type".to_vec(), b"application/grpc".to_vec()),
            (b"grpc-encoding".to_vec(), b"identity".to_vec()),
        ],
    ] {
        let decoded = decode_body(&headers, &body);
        assert!(decoded.problems.contains(UNDECODED), "{headers:?}");
    }
    // Plain frames under the same content type are fine, and a broken frame is not.
    let plain = decode_body(
        &header("Content-Type", "application/grpc"),
        &grpc_frame(false, b"hi"),
    );
    assert!(plain.problems.is_empty(), "{:?}", plain.problems);
    let broken = decode_body(
        &header("Content-Type", "application/grpc"),
        b"not a frame at all",
    );
    assert!(broken.problems.contains(UNDECODED));
}

#[test]
fn the_capture_budget_is_shared_between_bodies() {
    use gd_egress::decode::{Budget, decode_with};
    // 40 small, tame-looking bodies that each decode to 100 KiB; the capture may decode 1 MiB.
    let body = gzip(&vec![0u8; 100 * 1024]);
    assert!(
        body.len() * 1000 > 100 * 1024,
        "the test input must be under the ratio bound"
    );
    let headers = header("Content-Encoding", "gzip");
    let mut budget = Budget {
        output: 1024 * 1024,
        layers: 4096,
    };
    let (mut kept, mut bounded) = (0usize, 0usize);
    for _ in 0..40 {
        let decoded = decode_with(&headers, &body, &mut budget);
        kept += decoded.layers.iter().map(Vec::len).sum::<usize>();
        bounded += usize::from(decoded.problems.contains(BOUND));
    }
    assert!(kept <= 1024 * 1024, "kept {kept}");
    assert!(bounded >= 25, "bounded {bounded}");
    // The layer count is shared too: 300 compressed one-byte messages against a budget of 10.
    let frames: Vec<u8> = (0..300)
        .flat_map(|_| grpc_frame(true, &gzip(b"x")))
        .collect();
    let mut budget = Budget {
        output: 1024 * 1024,
        layers: 10,
    };
    let decoded = decode_with(&header("grpc-encoding", "gzip"), &frames, &mut budget);
    assert!(decoded.problems.contains(BOUND), "{:?}", decoded.problems);
    assert!(decoded.layers.len() <= 10, "{}", decoded.layers.len());
}
