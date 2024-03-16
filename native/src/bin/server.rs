use common::{ACK, CHUNK_CONT, CHUNK_LAST, CHUNK_SIZE_BYTES, LOCALHOST_ADDR};
use hex;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use wtransport::endpoint::IncomingSession;

async fn load_certificate(
    cert: &str,
    key: &str,
) -> Result<wtransport::Certificate, String> {
    let certificate =
        wtransport::Certificate::load(cert, key)
            .await
            .map_err(|e| {
                format!("Could not load certificate: {}", e.to_string())
            })?;

    if let Some(cert_digest) = certificate.hashes().pop() {
        println!(
            "WebTransport certificate digest: {}",
            hex::encode(cert_digest.as_ref())
        );
    }

    return Ok(certificate);
}

async fn handle_new_client(
    mut writer: wtransport::SendStream,
    mut reader: wtransport::RecvStream,
) {
    loop {
        // first two byte is the number of chunks that will follow,
        // chunks have a fixed size of 65535 bytes
        // last chunk byte is zeroed out, the last byte of the last chunk is marked
        // with 0xff
        let mut len_buf = [0; 2];
        let num_chunks: usize = match reader.read_exact(&mut len_buf).await {
            Ok(()) => u16::from_be_bytes(len_buf) as usize,
            Err(e) => {
                println!("failed to read number of chunks: {}", e);
                return;
            }
        };
        println!("expecting {} chunks", num_chunks);

        let mut chunk_buffer = bytes::BytesMut::with_capacity(CHUNK_SIZE_BYTES);
        for i in 0..num_chunks {
            println!("reading chunk {}", i + 1);
            unsafe {
                chunk_buffer.set_len(chunk_buffer.capacity());
            }

            if let Err(e) = reader.read_exact(&mut chunk_buffer).await {
                println!("Error filling chunk buffer: {}", e);
                return;
            }

            let mut expected: u8 = CHUNK_CONT;
            if i == num_chunks - 1 {
                expected = CHUNK_LAST;
            }

            let last_chunk_byte = chunk_buffer[chunk_buffer.len() - 1];

            if last_chunk_byte != expected {
                println!(
                    "unexpected last chunk byte: expected {}, received: {}",
                    expected, last_chunk_byte
                );
                return;
            }
        }
        println!("received all chunks");
        let ack_byte: &[u8] = &[ACK];
        if let Err(e) = writer.write_all(&ack_byte).await {
            println!("failed to write ack byte: {}", e);
            return;
        }
    }
}

async fn handle_incoming_wt_session(
    incoming_session: IncomingSession,
) -> Result<(), String> {
    let session_request = incoming_session.await.map_err(|e| e.to_string())?;
    println!(
        "new WebTransport session: authority: '{}', path: '{}'",
        session_request.authority(),
        session_request.path()
    );

    let connection =
        session_request.accept().await.map_err(|e| e.to_string())?;

    loop {
        match connection.accept_bi().await {
            Ok((writer, reader)) => {
                tokio::spawn(async move {
                    handle_new_client(writer, reader).await;
                });
            }
            Err(e) => {
                return Err(format!("error accepting connection: {}", e));
            }
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn run_server() -> Result<(), String> {
    let certificate = load_certificate("ecdsa.crt", "ecdsa.key").await?;

    let bind_addr = match SocketAddr::from_str(LOCALHOST_ADDR) {
        Ok(a) => a,
        Err(e) => {
            return Err(format!("invalid bind address: {}", e.to_string()));
        }
    };

    let config = wtransport::ServerConfig::builder()
        .with_bind_address(bind_addr)
        .with_certificate(certificate.clone())
        .keep_alive_interval(Some(Duration::from_secs(1)))
        .build();

    let server = match wtransport::Endpoint::server(config) {
        Ok(e) => e,
        Err(e) => {
            return Err(format!(
                "could not create Endpoint for bind_addr '{}': {}",
                bind_addr,
                e.to_string()
            ));
        }
    };

    loop {
        println!("waiting for incoming WT sessions on {:?}", bind_addr);
        let incoming_session = server.accept().await;
        tokio::spawn(async move {
            println!("handling incoming session");
            match handle_incoming_wt_session(incoming_session).await {
                Ok(()) => (),
                Err(e) => {
                    println!("error handling session: {}", e);
                }
            }
        });
    }
}

fn main() {
    if let Err(e) = run_server() {
        println!("server error: {}", e);
    }
}
