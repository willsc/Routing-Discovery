.PHONY: build test lint render

BIN := target/debug/route-discovery

build:
	cargo build

test:
	cargo test

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo clippy --no-default-features --all-targets -- -D warnings

# Review what this host would mesh; needs no FRR or AWS access.
render: build
	$(BIN) mesh inventory
	$(BIN) mesh render-frr
