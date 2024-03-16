all:
	cargo build

wasm:
	cargo build -p wasm-client --target wasm32-unknown-unknown && \
		wasm-bindgen target/wasm32-unknown-unknown/debug/wasm_client.wasm \
			--out-dir ./www --target web
