.PHONY: all build_rust copy_library build_go clean

all: build_rust copy_library build_go

LIBRARY_FILENAME=libsignal_ffi.a
RUST_DIR=pkg/libsignalgo/libsignal
GO_BINARY=mautrix-signal

# TODO fix linking with debug library
#ifneq ($(DBG),1)
RUST_TARGET_SUBDIR=release
#else
#RUST_TARGET_SUBDIR=debug
#endif

build_rust:
	./build-rust.sh

copy_library:
	cp $(RUST_DIR)/target/$(RUST_TARGET_SUBDIR)/$(LIBRARY_FILENAME) .

build_go:
	LIBRARY_PATH="$${LIBRARY_PATH}:." ./build-go.sh

clean:
	rm -f ./$(LIBRARY_FILENAME)
	cd $(RUST_DIR) && cargo clean
	rm -f $(GO_BINARY)
