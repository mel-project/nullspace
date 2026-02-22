use chrono::NaiveDate;
use nullspace_client::internal::{ConvoMessage, MessageContent};
use nullspace_structs::timestamp::NanoTimestamp;

const CLUSTER_WINDOW_NANOS: u64 = 3 * 60 * 1_000_000_000;

#[derive(Clone, Copy, Default)]
pub struct MessageRenderMeta {
    pub date_label: Option<NaiveDate>,
    pub is_beginning: bool,
    pub is_end: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MessageKind {
    Text,
    Attachment,
    GroupInvite,
}

fn message_kind(message: &ConvoMessage) -> MessageKind {
    match message.body {
        MessageContent::PlainText(_) => MessageKind::Text,
        MessageContent::Attachment { .. } => MessageKind::Attachment,
        MessageContent::GroupInvite { .. } => MessageKind::GroupInvite,
    }
}

fn same_cluster(left: &ConvoMessage, right: &ConvoMessage) -> bool {
    if left.sender != right.sender {
        return false;
    }
    if message_kind(left) != message_kind(right) {
        return false;
    }
    if let (Some(left_ts), Some(right_ts)) = (left.received_at, right.received_at) {
        left_ts.0.abs_diff(right_ts.0) <= CLUSTER_WINDOW_NANOS
    } else {
        true
    }
}

pub fn message_render_meta(messages: &[ConvoMessage]) -> Vec<MessageRenderMeta> {
    let mut out = Vec::with_capacity(messages.len());
    for (index, message) in messages.iter().enumerate() {
        let previous = index.checked_sub(1).and_then(|idx| messages.get(idx));
        let next = messages.get(index + 1);
        let previous_date =
            previous.and_then(|msg| msg.received_at.and_then(NanoTimestamp::naive_date));
        let date_label = message
            .received_at
            .and_then(NanoTimestamp::naive_date)
            .filter(|date| Some(*date) != previous_date);
        let is_beginning = previous
            .map(|previous| !same_cluster(previous, message))
            .unwrap_or(true);
        let is_end = next
            .map(|next| !same_cluster(message, next))
            .unwrap_or(true);
        out.push(MessageRenderMeta {
            date_label,
            is_beginning,
            is_end,
        });
    }
    out
}
