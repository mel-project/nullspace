use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use egui::Context;
use nullspace_client::internal::Event;
use rodio::{Decoder, OutputStreamBuilder, Sink};
use smol::channel::Sender as AsyncSender;
use std::sync::mpsc::{Receiver, Sender as StdSender};

use crate::notify::show_notification;
use crate::rpc::get_rpc;

pub async fn event_loop(
    ctx: Context,
    event_tx: AsyncSender<Event>,
    focused: Arc<AtomicBool>,
    audio_tx: StdSender<Vec<u8>>,
) {
    let rpc = get_rpc();
    let focused_task = focused.clone();
    let mut max_notified = 0;
    loop {
        match rpc.next_event().await {
            Ok(event) => {
                show_notification(&event, &focused_task, &audio_tx, &mut max_notified).await;
                if event_tx.send(event).await.is_err() {
                    break;
                }
                ctx.request_repaint();
            }
            Err(err) => {
                tracing::warn!(error = %err, "event loop error");
            }
        }
    }
}

pub fn spawn_audio_thread() -> StdSender<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || audio_thread(rx));
    tx
}

fn audio_thread(rx: Receiver<Vec<u8>>) {
    let Ok(stream) = OutputStreamBuilder::open_default_stream() else {
        tracing::warn!("failed to open audio output stream");
        return;
    };
    for bytes in rx {
        let cursor = std::io::Cursor::new(bytes);
        let Ok(source) = Decoder::new(cursor) else {
            tracing::warn!("failed to decode notification sound");
            continue;
        };
        let sink = Sink::connect_new(stream.mixer());
        sink.append(source);
        sink.detach();
    }
}
