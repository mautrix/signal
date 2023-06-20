# libsignalgo
Go bindings for [libsignal](https://github.com/signalapp/libsignal).

## Installation
0. Install Rust. You may also need to install libclang-dev manually.
1. Clone [libsignal](https://github.com/signalapp/libsignal) somewhere.
2. Run `./update-ffi.sh <path to libsignal>` (this builds the library, regenerates the header, and copies them both here)
3. Copy `libsignal_ffi.a` to `/usr/lib/`.
   * Alternatively, set `LIBRARY_PATH` to the directory containing `libsignal_ffi.a`.
	 Something like this: `LIBRARY_PATH="$LIBRARY_PATH:./pkg/libsignalgo" ./build.sh`
4. Use like a normal Go library.
