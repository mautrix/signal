#!/usr/bin/env bash

# This script is used to generate the protobuf files for the project.
# It is assumed that the protoc compiler is installed and available on the path.

# The script will generate the protobuf files for the following languages:
# - Go

PKG_IMPORT_PATH="go.mau.fi/mautrix-signal/pkg/signalmeow/signalpb"

for file in *.proto
do
    protoc --go_out=. \
    --go_opt=M${file}=$PKG_IMPORT_PATH \
    --go_opt=paths=source_relative \
    $file
done
