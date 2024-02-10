#!/bin/sh
# TODO fix linking with debug library
#if [ "$DBG" != 1 ]; then
#    RUST_PROFILE=release
#else
#    RUST_PROFILE=dev
#fi
RUST_PROFILE=release
cd pkg/libsignalgo/libsignal && RUSTFLAGS="-Ctarget-feature=-crt-static" RUSTC_WRAPPER="" cargo build -p libsignal-ffi --profile=$RUST_PROFILE
