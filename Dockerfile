# -- Build libsignal (with Rust) --
FROM rust:1.70.0-slim as rust-builder
RUN apt-get update && apt-get install -y --no-install-recommends make cmake clang llvm protobuf-compiler

WORKDIR /build
# Copy all files needed for Rust build, and no Go files
COPY pkg/libsignalgo/libsignal/. pkg/libsignalgo/libsignal/.
COPY Makefile .

RUN make build_rust
RUN make copy_library

# -- Build mautrix-signal (with Go) --
FROM golang:1.20-bookworm AS go-builder
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates libolm-dev

WORKDIR /build
# Copy all files needed for Go build, and no Rust files
COPY *.go go.* *.yaml ./
COPY pkg/signalmeow/. pkg/signalmeow/.
COPY pkg/libsignalgo/* pkg/libsignalgo/
COPY pkg/libsignalgo/resources/. pkg/libsignalgo/resources/.
COPY config/. config/.
COPY database/. database/.
COPY .git .git
COPY Makefile .
COPY docker-run.sh .

COPY --from=rust-builder /build/libsignal_ffi.a /build/libsignal_ffi.a
RUN make build_go

# -- Run mautrix-signal --
FROM debian:bookworm-slim

ENV UID=1337 \
    GID=1337

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libolm-dev bash jq yq curl

COPY --from=go-builder /build/mautrix-signal /usr/bin/mautrix-signal
COPY --from=go-builder /build/example-config.yaml /opt/mautrix-signal/example-config.yaml
COPY --from=go-builder /build/docker-run.sh /docker-run.sh
RUN chmod +x /docker-run.sh
VOLUME /data

CMD ["/docker-run.sh"]
