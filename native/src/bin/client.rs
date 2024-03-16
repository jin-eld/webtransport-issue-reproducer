use bytes::{BufMut, BytesMut};
use common::{ACK, CHUNK_CONT, CHUNK_LAST, CHUNK_SIZE_BYTES, LOCALHOST_ADDR};

const NUM_SEND_CHUNKS: usize = 128;

async fn send_chunks(
    writer: &mut wtransport::SendStream,
    reader: &mut wtransport::RecvStream,
) -> Result<(), String> {
    let mut rng = fastrand::Rng::new();
    let mut chunk_buffer = BytesMut::with_capacity(CHUNK_SIZE_BYTES * 4);
    for _ in 0..chunk_buffer.capacity() {
        chunk_buffer.put_u8(rng.u8(..));
    }

    let mut sb = bytes::BytesMut::with_capacity(2);
    if NUM_SEND_CHUNKS > u16::MAX.into() {
        return Err(format!(
            "number of chunks to send must not exceed {}",
            u16::MAX
        ));
    }
    sb.put_u16(NUM_SEND_CHUNKS.try_into().unwrap());
    if let Err(e) = writer.write_all(&sb).await {
        return Err(format!("failed to write number of chunks: {}", e));
    }

    println!("Sending {} chunks", NUM_SEND_CHUNKS);

    let mut start_index = 0;

    let cblen = chunk_buffer.len();
    for i in 0..NUM_SEND_CHUNKS {
        println!("sending chunk {}", i + 1);
        let slice =
            &chunk_buffer[start_index..(start_index + CHUNK_SIZE_BYTES - 1)];
        if let Err(e) = writer.write_all(&slice).await {
            return Err(format!("failed to write chunk: {}", e));
        }

        start_index += CHUNK_SIZE_BYTES - 1;
        if (start_index + CHUNK_SIZE_BYTES - 1) > cblen {
            start_index = 0;
        }

        let mut terminate: u8 = CHUNK_CONT;
        if i == NUM_SEND_CHUNKS - 1 {
            terminate = CHUNK_LAST;
        }

        let term_byte: &[u8] = &[terminate];
        if let Err(e) = writer.write_all(&term_byte).await {
            return Err(format!("failed to write termination byte: {}", e));
        }
    }

    let mut ack_buf = [0; 1];
    match reader.read_exact(&mut ack_buf).await {
        Ok(()) => {
            if ack_buf[0] != ACK {
                return Err(format!(
                    "received unexpected ack byte: {:#x}",
                    ack_buf[0]
                ));
            }
        }
        Err(e) => {
            return Err(format!("failed to receive ack from server: {}", e));
        }
    }

    return Ok(());
}

#[tokio::main(flavor = "multi_thread")]
async fn run_client() -> Result<(), String> {
    let config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();

    let client_endpoint = match wtransport::Endpoint::client(config) {
        Ok(ep) => ep,
        Err(e) => {
            return Err(format!(
                "could not create WebTransport client: {}",
                e.to_string()
            ));
        }
    };

    let url = format!("https://{}", LOCALHOST_ADDR);
    let connection = match client_endpoint.connect(url.clone()).await {
        Ok(c) => c,
        Err(e) => {
            return Err(format!("failed to connect to {}: {}", url, e));
        }
    };

    let opening = match connection.open_bi().await {
        Ok(o) => o,
        Err(e) => {
            return Err(format!("failed to open bi-di connection: {}", e));
        }
    };

    let (mut writer, mut reader) = match opening.await {
        Ok(stream) => stream,
        Err(e) => {
            return Err(format!("failed to establish bi-di connection: {}", e));
        }
    };

    send_chunks(&mut writer, &mut reader).await?;
    send_chunks(&mut writer, &mut reader).await?;

    return Ok(());
}

fn main() {
    if let Err(e) = run_client() {
        println!("client error: {}", e);
    }
}
