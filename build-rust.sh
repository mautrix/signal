#!/bin/sh
if [[ $DBG -ne 1 ]]; then
    RUST_PROFILE=release
else
    RUST_PROFILE=dev
fi
cd pkg/libsignalgo/libsignal && RUSTFLAGS="-Ctarget-feature=-crt-static" RUSTC_WRAPPER="" cargo build -p libsignal-ffi --profile=$RUST_PROFILE
