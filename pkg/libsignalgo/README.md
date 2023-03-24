# libsignalgo
Go bindings for [libsignal](https://github.com/signalapp/libsignal).

## Installation
0. Install Rust. You may also need to install libclang-dev manually.
1. Clone [libsignal](https://github.com/signalapp/libsignal) somewhere.
2. Run `cargo build -p libsignal-ffi --release`.
3. Copy `target/release/libsignal_ffi.a` to `/usr/lib/`.
   * Alternatively, set `LIBRARY_PATH` to the directory containing `libsignal_ffi.a`.
4. Use like a normal Go library.

## Regenerating `libsignal-ffi.h`
In the root of the cloned libsignal repo, run

```
$ cbindgen --profile release rust/bridge/ffi -o libsignal-ffi.h
```

then copy the output file to this directory.
