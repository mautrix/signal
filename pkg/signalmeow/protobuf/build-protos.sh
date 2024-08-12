#!/bin/sh
PKG_IMPORT_PATH="go.mau.fi/mautrix-signal/pkg/signalmeow/signalpb"
for file in *.proto
do
	# Requires https://go-review.googlesource.com/c/protobuf/+/369634
	protoc --go_out=. \
		--go_opt=M${file}=$PKG_IMPORT_PATH \
		--go_opt=paths=source_relative \
		--go_opt=embed_raw=true \
		$file
done
