#!/bin/bash

# Exit on error
set -e

# Store the libsignal directory path
LIBSIGNAL_DIRECTORY="libsignal"

# Check if libsignal directory exists
if [ ! -d "$LIBSIGNAL_DIRECTORY" ]; then
    echo "Error: Libsignal directory '$LIBSIGNAL_DIRECTORY' does not exist."
    exit 1
fi

echo "// Generated by update-ffi.sh; DO NOT EDIT." > version.go
echo >> version.go
echo "package libsignalgo" >> version.go
echo >> version.go

# Store the current working directory
ORIGINAL_DIR="$(pwd)"

# Navigate to libsignal directory
cd "$LIBSIGNAL_DIRECTORY"

echo "const Version = \"$(git describe --tags --always)\"" >> ../version.go

# Build libsignal
cargo build -p libsignal-ffi --release

# Regenerate the header file
cbindgen --profile release rust/bridge/ffi -o libsignal-ffi.h

# Navigate back to the original directory
cd "$ORIGINAL_DIR"

# Copy files from the libsignal directory
cp "${LIBSIGNAL_DIRECTORY}/target/release/libsignal_ffi.a" .
cp "${LIBSIGNAL_DIRECTORY}/libsignal-ffi.h" .

echo "Files copied successfully."
