.PHONY: build test validate demo kernel-test frr-test lint

BIN := target/debug/route-discovery

build:
	cargo build

test:
	cargo test

validate: build
	$(BIN) validate -c examples/linux.toml
	$(BIN) validate -c examples/aws.toml
	$(BIN) validate -c examples/frr.toml
	$(BIN) server validate -c examples/route-server.toml
	$(BIN) mesh render-frr > /dev/null

demo: build
	$(BIN) demo
	$(BIN) server demo

kernel-test:
	cargo test --test kernel_smoke -- --ignored --nocapture

frr-test:
	cargo test --test frr_smoke -- --ignored --nocapture

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
