use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use notify_rust::Notification;
use rodio::{Decoder, OutputStreamBuilder, Sink};
use std::sync::mpsc::{Receiver, Sender as StdSender};
use tokio::sync::mpsc::Sender as TokioSender;
use nullspace_client::internal::{ConvoId, Event, InternalClient, MessageContent};

use crate::promises::flatten_rpc;

const NOTIFICATION_SOUND: &[u8] = include_bytes!("sounds/notification.mp3");

pub async fn event_loop(
    rpc: InternalClient,
    event_tx: TokioSender<Event>,
    focused: Arc<AtomicBool>,
    audio_tx: StdSender<Vec<u8>>,
) {
    let focused_task = focused.clone();
    let mut max_notified = 0;
    loop {
        match rpc.next_event().await {
            Ok(event) => {
                if let Event::ConvoUpdated { convo_id } = &event
                    && !focused_task.load(Ordering::Relaxed)
                    && let ConvoId::Direct { peer } = convo_id {
                        match flatten_rpc(
                            rpc.convo_history(convo_id.clone(), None, None, 1).await,
                        ) {
                            Ok(messages) => {
                                if let Some(message) = messages.last()
                                    && message.sender == *peer
                                    && message.received_at.unwrap_or_default().0 > max_notified
                                {
                                    max_notified = message.received_at.unwrap_or_default().0;
                                    let body = match &message.body {
                                        MessageContent::PlainText(text) => text.clone(),
                                        MessageContent::Markdown(text) => text.clone(),
                                        MessageContent::Attachment { .. } => {
                                            "Attachment".to_string()
                                        }
                                        MessageContent::GroupInvite { .. } => {
                                            "Group invite".to_string()
                                        }
                                    };
                                    if let Err(err) = Notification::new()
                                        .summary(&format!("Message from {}", message.sender))
                                        .body(&body)
                                        .show()
                                    {
                                        tracing::warn!(error = %err, "notification error");
                                    }
                                    play_sound(&audio_tx, NOTIFICATION_SOUND);
                                }
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "failed to fetch latest message");
                            }
                        }
                    }
                if event_tx.send(event).await.is_err() {
                    break;
                }
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

fn play_sound(audio_tx: &StdSender<Vec<u8>>, bytes: &[u8]) {
    if audio_tx.send(bytes.to_vec()).is_err() {
        tracing::warn!("audio thread not available");
    }
}
