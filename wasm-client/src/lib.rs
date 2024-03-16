use bytes::{BufMut, BytesMut};
use common::{ACK, CHUNK_CONT, CHUNK_LAST, CHUNK_SIZE_BYTES, LOCALHOST_ADDR};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::js_sys;
use web_sys::{
    ReadableStreamDefaultReader, WebTransport, WebTransportBidirectionalStream,
    WebTransportCloseInfo, WebTransportCongestionControl,
    WebTransportReceiveStream, WebTransportSendStream,
    WritableStreamDefaultWriter,
};

macro_rules! console_log {
    ($($t:tt)*) =>
        (web_sys::console::log_2(
            &wasm_bindgen::JsValue::from_str(&format!($($t)*)),
        &(web_sys::js_sys::Date::now() / 1000.0).into()))
}

const NUM_SEND_CHUNKS: usize = 128;

pub fn jserr_to_string(e: JsValue) -> String {
    return e.as_string().unwrap_or("n/a".to_string());
}

fn close_transport(transport: &WebTransport, reason_str: &str) {
    console_log!("Closing transport with reason {}", reason_str);

    let mut reason = WebTransportCloseInfo::default();
    reason.reason(reason_str);
    transport.close_with_close_info(&reason);
}

async fn send_chunks(
    receiver: &WebTransportReceiveStream,
    sender: &WebTransportSendStream,
    chunk_buffer: &BytesMut,
) -> Result<(), ()> {
    let writer: WritableStreamDefaultWriter = match sender.get_writer() {
        Ok(w) => w,
        Err(e) => {
            console_log!("error getting WT writer: {}", jserr_to_string(e));
            return Err(());
        }
    };

    let mut sb = bytes::BytesMut::with_capacity(2);
    if NUM_SEND_CHUNKS > u16::MAX.into() {
        console_log!("number of chunks to send must not exceed {}", u16::MAX);
        writer.release_lock();
        return Err(());
    }
    sb.put_u16(NUM_SEND_CHUNKS.try_into().unwrap());
    let sb = sb.to_vec();

    let data = js_sys::Uint8Array::from(&sb[..]);
    if let Err(e) = JsFuture::from(writer.write_with_chunk(&data)).await {
        console_log!("failed to write chunk amount: {}", jserr_to_string(e));
        writer.release_lock();
        return Err(());
    }

    console_log!("Sending {} chunks", NUM_SEND_CHUNKS);
    let mut start_index = 0;

    let cblen = chunk_buffer.len();
    for i in 0..NUM_SEND_CHUNKS {
        console_log!("sending chunk {}", i + 1);
        let slice =
            &chunk_buffer[start_index..(start_index + CHUNK_SIZE_BYTES)];

        let mut terminate: u8 = CHUNK_CONT;
        if i == NUM_SEND_CHUNKS - 1 {
            terminate = CHUNK_LAST;
        }

        let data = js_sys::Uint8Array::from(slice);
        let l = data.length();
        if l > 0 {
            data.set_index(l - 1, terminate);
        }

        if let Err(e) = JsFuture::from(writer.write_with_chunk(&data)).await {
            console_log!(
                "failed to write chunk amount: {}",
                jserr_to_string(e)
            );
            writer.release_lock();
            return Err(());
        }

        start_index += CHUNK_SIZE_BYTES;
        if (start_index + CHUNK_SIZE_BYTES) > cblen {
            start_index = 0;
        }
    }
    writer.release_lock();
    console_log!("all chunks sent");

    let reader: ReadableStreamDefaultReader =
        receiver.get_reader().unchecked_into();

    let read_data = JsFuture::from(reader.read()).await;
    reader.release_lock();

    match read_data {
        Ok(data) => {
            let done =
                js_sys::Reflect::get(&data, &js_sys::JsString::from("done"))
                    .unwrap_or(false.into())
                    .unchecked_into::<js_sys::Boolean>();

            if done.is_truthy() {
                console_log!("reader: unexpected end of stream");
                return Err(());
            }

            let value: js_sys::Uint8Array = match js_sys::Reflect::get(
                &data,
                &js_sys::JsString::from("value"),
            ) {
                Ok(v) => v.unchecked_into(),
                Err(e) => {
                    console_log!(
                        "failed to read ack byste from server: {}",
                        jserr_to_string(e)
                    );
                    return Err(());
                }
            };

            let value = value.to_vec();
            if value.len() == 1 && value[0] == ACK {
                return Ok(());
            } else {
                console_log!("received unexpected ACK byte from server!");
                return Err(());
            }
        }
        Err(e) => {
            console_log!(
                "error reading ACK byte from server: {}",
                jserr_to_string(e)
            );
            return Err(());
        }
    }
}

#[wasm_bindgen]
pub async fn client(cert_digest_hex_str: String) {
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Debug);

    let mut rng = fastrand::Rng::new();
    let mut chunk_buffer = BytesMut::with_capacity(CHUNK_SIZE_BYTES * 4);
    for _ in 0..chunk_buffer.capacity() {
        chunk_buffer.put_u8(rng.u8(..));
    }

    let mut options = web_sys::WebTransportOptions::new();
    options.require_unreliable(false);
    options.congestion_control(WebTransportCongestionControl::Throughput);

    if !cert_digest_hex_str.is_empty() {
        console_log!("Using cert digest: {}", cert_digest_hex_str);
        let Some(hash) = hex::decode(cert_digest_hex_str).ok() else {
            console_log!("failed to decode cert digest string");
            return;
        };

        let obj = js_sys::Object::new();
        if js_sys::Reflect::set(&obj, &"algorithm".into(), &"sha-256".into())
            .is_err()
        {
            return;
        }

        let hash_array = js_sys::Uint8Array::from(hash.as_slice());
        if js_sys::Reflect::set(&obj, &"value".into(), &hash_array).is_err() {
            return;
        }

        let hashes = js_sys::Array::of1(&obj);
        options.server_certificate_hashes(&hashes);
    }

    let url = format!("https://{}", LOCALHOST_ADDR);
    let transport =
        match web_sys::WebTransport::new_with_options(&url, &options) {
            Ok(t) => t,
            Err(e) => {
                console_log!(
                    "failed to init WT with options: {}",
                    jserr_to_string(e)
                );
                return;
            }
        };

    let opened_closure = Closure::wrap(Box::new(move |_| {
        console_log!("WebTransport connection has been opened");
    }) as Box<dyn FnMut(JsValue)>);

    let running = Arc::new(AtomicBool::new(true));

    let running_for_closed_cb = running.clone();
    let closed_closure = Closure::wrap(Box::new(move |_a| {
        console_log!("WebTransport connection has been closed");
        running_for_closed_cb.store(false, Ordering::Relaxed);
    }) as Box<dyn FnMut(JsValue)>);

    let ready = transport
        .ready()
        .then(&opened_closure)
        .catch(&closed_closure);
    let closed = transport
        .closed()
        .then(&closed_closure)
        .catch(&closed_closure);

    if let Err(e) = JsFuture::from(js_sys::Promise::race(&js_sys::Array::of2(
        &ready, &closed,
    )))
    .await
    {
        console_log!("failed to connect to {}: {}", url, jserr_to_string(e));
        return;
    }

    if !running.load(Ordering::Relaxed) {
        console_log!("failed to connect to {}", url);
        return;
    }

    let stream: WebTransportBidirectionalStream =
        match JsFuture::from(transport.create_bidirectional_stream()).await {
            Ok(s) => s.into(),
            Err(e) => {
                let err = jserr_to_string(e);
                console_log!(
                    "failed to create a bidirectional stream: {}",
                    err
                );
                close_transport(&transport, err.as_str());
                return;
            }
        };

    let receiver = stream.readable();
    let sender = stream.writable();

    let _ = send_chunks(&receiver, &sender, &chunk_buffer).await;

    if let Err(e) = JsFuture::from(sender.close()).await {
        console_log!("failed to close stream: {}", jserr_to_string(e));
    }
}
