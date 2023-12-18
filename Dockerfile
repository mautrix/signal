# -- Build libsignal (with Rust) --
FROM rust:1-alpine as rust-builder
RUN apk add --no-cache git make cmake protoc musl-dev g++ clang-dev

WORKDIR /build
# Copy all files needed for Rust build, and no Go files
COPY pkg/libsignalgo/libsignal/. pkg/libsignalgo/libsignal/.

ENV RUSTFLAGS="-Ctarget-feature=-crt-static" RUSTC_WRAPPER=""
RUN cd pkg/libsignalgo/libsignal/ && cargo build -p libsignal-ffi --release

# -- Build mautrix-signal (with Go) --
FROM golang:1-alpine3.19 AS go-builder
RUN apk add --no-cache git ca-certificates build-base olm-dev

WORKDIR /build
# Copy all files needed for Go build, and no Rust files
COPY *.go go.* *.yaml *.sh ./
COPY pkg/signalmeow/. pkg/signalmeow/.
COPY pkg/libsignalgo/* pkg/libsignalgo/
COPY pkg/libsignalgo/resources/. pkg/libsignalgo/resources/.
COPY config/. config/.
COPY database/. database/.
COPY msgconv/. msgconv/.
COPY .git .git

ENV LIBRARY_PATH=.
COPY --from=rust-builder /build/pkg/libsignalgo/libsignal/target/release/libsignal_ffi.a /build/libsignal_ffi.a
RUN ./build-go.sh

# -- Run mautrix-signal --
FROM alpine:3.19

ENV UID=1337 \
    GID=1337

RUN apk add --no-cache ffmpeg su-exec ca-certificates bash jq curl yq olm

COPY --from=go-builder /build/mautrix-signal /usr/bin/mautrix-signal
COPY --from=go-builder /build/example-config.yaml /opt/mautrix-signal/example-config.yaml
COPY --from=go-builder /build/docker-run.sh /docker-run.sh
VOLUME /data

CMD ["/docker-run.sh"]
