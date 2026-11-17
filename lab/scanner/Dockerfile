# Guard Dog's scanner image, for the regtest lab only (compose service
# `scanner`, profile `scan`). Not a release artefact: releases are built by the
# release pipeline, never from this file.
#
# Build stage: the official Rust image at the toolchain pinned in
# rust-toolchain.toml (1.99.1), pinned by its multi-arch index digest.
# Runtime stage: distroless cc (no shell, no package manager), pinned the same
# way. Only the binary is copied across. Build it once with
#   docker build -f lab/scanner/Dockerfile -t gd-lab-scanner:local .
# from the repository root. The tag matches the scanner service in
# lab/compose.yml, so running the service does not rebuild it.
FROM rust:1.99.1-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS build
ENV CARGO_BUILD_JOBS=8 CARGO_TERM_COLOR=never
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release -p guard-dog

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/guard-dog /usr/local/bin/guard-dog
USER nonroot
ENTRYPOINT ["/usr/local/bin/guard-dog"]
