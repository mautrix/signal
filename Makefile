.PHONY: all build_rust copy_library build_go clean

all: build_rust copy_library build_go

LIBRARY_NAME=libsignal-ffi
LIBRARY_FILENAME=libsignal_ffi.a
RUST_DIR=pkg/libsignalgo/libsignal
GO_BINARY=mautrix-signal

ifneq ($(DBG),1)
RUST_PROFILE=release
RUST_TARGET_SUBDIR=release
GO_GCFLAGS=
else
RUST_PROFILE=dev
RUST_TARGET_SUBDIR=debug
GO_GCFLAGS=all=-N -l
endif

build_rust:
	cd $(RUST_DIR) && cargo build -p $(LIBRARY_NAME) --profile=$(RUST_PROFILE)

copy_library:
	cp $(RUST_DIR)/target/$(RUST_TARGET_SUBDIR)/$(LIBRARY_FILENAME) .

build_go:
	LIBRARY_PATH="$${LIBRARY_PATH}:." go build -gcflags "$(GO_GCFLAGS)" -ldflags "-X main.Tag=$$(git describe --exact-match --tags 2>/dev/null) -X main.Commit=$$(git rev-parse HEAD) -X 'main.BuildTime=`date '+%b %_d %Y, %H:%M:%S'`'"

clean:
	rm -f ./$(LIBRARY_FILENAME)
	cd $(RUST_DIR) && cargo clean
	rm -f $(GO_BINARY)
