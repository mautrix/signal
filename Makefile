.PHONY: all build_rust copy_library build_go clean

all: build_rust copy_library build_go

LIBRARY_NAME=libsignal-ffi
LIBRARY_FILENAME=libsignal_ffi.a
RUST_DIR=pkg/libsignalgo/libsignal
GO_BINARY=mautrix-signal

build_rust:
	cd $(RUST_DIR) && cargo build -p $(LIBRARY_NAME) --release

copy_library:
	cp $(RUST_DIR)/target/release/$(LIBRARY_FILENAME) .

build_go:
	LIBRARY_PATH="$${LIBRARY_PATH}:." go build -ldflags "-X main.Tag=$$(git describe --exact-match --tags 2>/dev/null) -X main.Commit=$$(git rev-parse HEAD) -X 'main.BuildTime=`date '+%b %_d %Y, %H:%M:%S'`'"

clean:
	rm -f ./$(LIBRARY_FILENAME)
	cd $(RUST_DIR) && cargo clean
	rm -f $(GO_BINARY)

