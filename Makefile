.PHONY: all clean

GO_BINARY=mautrix-signal

all: $(GO_BINARY)

LIBRARY_FILENAME=libsignal_ffi.a
RUST_DIR=pkg/libsignalgo/libsignal

# TODO fix linking with debug library
#ifneq ($(DBG),1)
RUST_TARGET_SUBDIR=release
#else
#RUST_TARGET_SUBDIR=debug
#endif

RUST_LIBRARY_DIR=$(RUST_DIR)/target/$(RUST_TARGET_SUBDIR)
RUST_LIBRARY=$(RUST_LIBRARY_DIR)/$(LIBRARY_FILENAME)

$(RUST_LIBRARY):
	./build-rust.sh

$(GO_BINARY): $(RUST_LIBRARY)
	LIBRARY_PATH="${RUST_LIBRARY_DIR}:$${LIBRARY_PATH}" \
		./build-go.sh $(GO_EXTRA_OPTS)

clean:
	rm -f ./$(LIBRARY_FILENAME)
	cd $(RUST_DIR) && cargo clean
	rm -f $(GO_BINARY)

.PHONY: $(RUST_LIBRARY) $(GO_BINARY)
