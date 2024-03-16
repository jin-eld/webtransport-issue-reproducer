## Rust WebTransport example (problem reproducer)

When sending packets to the server from the WASM client it seems that not
all of the packets arrive at the server. This demo code server the purpose of
reproducing the issue.

The communication simulates a simple protocol where data is being sent
from the client to the server and acknowledged by the server.

## Server

The server binds to `127.0.0.1:50443` and listens for incoming WebTransport
connections. It will accept a bidirectional WebTransport stream and
expect chunks of random data. The first two bytes of the transfer will
contain the number of chunks to expect (parsed as u16 in network byte order).
Each chunk is expected to have the size fo 65535 bytes. The last byte of each 
chunk is zeroed out for all chunks except the last chunk. There the last byte 
has the value of `0xff` which tells the server to stop receiving chunks, the 
server will acknowledge by sending `0xaa` back to the client.

The server uses a self signed certificate, which was generated as follows:
```
    openssl ecparam -name secp256r1 -genkey -out ecdsa.key
    openssl req -new -x509 -days 10 -key ecdsa.key -sha384 -out ecdsa.crt \
        -subj "/CN=localhost"
```

## Client

The client connects to `https://127.0.0.1:50443` using the WebTransport
protocol and opens a bidirectional stream. It first sends the number of
chunks encoded as a u16 in network byte order (currently 128 chunks), 
then it sends the actual chunks of random data, 65535 bytes each. The last byte
of each chunk is set to `0x00`, the last byte of the last chunk will be set 
to `0xff` to indicate, that no more chunks will follow. After the last chunk
has been sent, the client will try to read one byte from the server and is
expecting to receive `0xaa` as an acknowledgement.

## WASM Client

The WASM client behaves exactly the same as the native client, however due
to browser limitations only Chromium can be used to connect to a server
which is using a self signed certificate. For this purpose the server
prints a hash which is then used by the client.

In the current git version the hash is hardcoded in `index.html` and
corresponds to the provided keys.

After building, the `./www` directory needs to be exposed via a webserver
(I usually start a local `thttpd` to serve it), then start your
`chromium-browser` and point it to the port where your local thttpd is
running. Open the browser console (developer tools) to see some output.

## Compiling

To build and run the server use the following command:
`cargo run --bin server`

To build and run the client:
`cargo run --bin client`

To build the WASM client you need to install wasm-bindgen:
`cargo install wasm-bindgen-cli`

Then run the following commands:
```
	cargo build -p wasm-client --target wasm32-unknown-unknown && \
		wasm-bindgen target/wasm32-unknown-unknown/debug/wasm_client.wasm \
			--out-dir ./www --target web
```

After that expose the `./www` directory via a webserver of your choice and
navigate your `chromium-browser` to that localhost port.

Note: this will not work with other browsers due to the self signed
server certificate.

## Issue

Both, the native and the WASM client will print that they have sent all 128
chunks to the server. However, in the case of the WASM client, the server
will either get stuck at too few chunks or it will detect that the last
byte of a chunk contains an invalid value.

Server log:
```
...
reading chunk 123
reading chunk 124
unexpected last chunk byte: expected 0, received: 255
```

WASM client log:
```
sending chunk 128 1710552336.279
wasm_client.js:329 all chunks sent 1710552336.281
wasm_client.js:329 reader: unexpected end of stream 1710552336.287
```

From the looks of it either a packet got lost or got corrupted during the
transfer, causing the last byte of a chunk to become invalid.

This was reproduced with Chromium Version 122.0.6261.128 (Official Build)
Fedora Project (64-bit)
