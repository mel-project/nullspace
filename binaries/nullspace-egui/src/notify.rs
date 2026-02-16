use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender as StdSender;

#[cfg(not(target_os = "linux"))]
use notify_rust::Notification;

use nullspace_client::internal::{ConvoId, Event, MessageContent};

use crate::promises::flatten_rpc;
use crate::rpc::get_rpc;

const NOTIFICATION_SOUND: &[u8] = include_bytes!("sounds/notification.mp3");

#[cfg(target_os = "linux")]
async fn send_notification_linux(title: String, body: String) -> Result<(), String> {
    use std::process::Command;

    Command::new("notify-send")
        .arg("--app-name=Resplendent Timer")
        .arg(&title)
        .arg(&body)
        .spawn()
        .map_err(|e| format!("Failed to send notification: {}", e))?;

    Ok(())
}

pub async fn show_notification(
    event: &Event,
    focused: &Arc<AtomicBool>,
    audio_tx: &StdSender<Vec<u8>>,
    max_notified: &mut u64,
) {
    if let Event::ConvoUpdated { convo_id } = event
        && !focused.load(Ordering::Relaxed)
        && let ConvoId::Direct { peer } = convo_id
    {
        match flatten_rpc(
            get_rpc()
                .convo_history(convo_id.clone(), None, None, 1)
                .await,
        ) {
            Ok(messages) => {
                if let Some(message) = messages.last()
                    && message.sender == *peer
                    && message.received_at.unwrap_or_default().0 > *max_notified
                {
                    *max_notified = message.received_at.unwrap_or_default().0;
                    let body = match &message.body {
                        MessageContent::PlainText(text) => text.clone(),
                        MessageContent::Attachment { .. } => "Attachment".to_string(),
                        MessageContent::GroupInvite { .. } => "Group invite".to_string(),
                    };
                    let title = format!("Message from {}", message.sender);
                    #[cfg(target_os = "linux")]
                    {
                        if let Err(err) = send_notification_linux(title, body).await {
                            tracing::warn!(error = %err, "notification error");
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        if let Err(err) = Notification::new().summary(&title).body(&body).show() {
                            tracing::warn!(error = %err, "notification error");
                        }
                    }
                    play_sound(audio_tx, NOTIFICATION_SOUND);
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to fetch latest message");
            }
        }
    }
}

fn play_sound(audio_tx: &StdSender<Vec<u8>>, bytes: &[u8]) {
    if audio_tx.send(bytes.to_vec()).is_err() {
        tracing::warn!("audio thread not available");
    }
}
