use nullspace_client::internal::ConvoMessage;
use std::collections::BTreeMap;
use tracing::debug;

const INITIAL_LIMIT: u16 = 10;
const PAGE_LIMIT: u16 = 10;

#[derive(Clone, Debug, Default)]
pub struct ConvoState {
    pub messages: BTreeMap<i64, ConvoMessage>,
    pub oldest_id: Option<i64>,
    pub latest_received_id: Option<i64>,
    pub last_update_count_seen: u64,
    pub initialized: bool,
    pub no_more_older: bool,
    pub pending_scroll_to_bottom: bool,
}

impl ConvoState {
    fn apply_messages(&mut self, messages: Vec<ConvoMessage>) {
        for msg in messages {
            let msg_id = msg.id;
            if msg.received_at.is_some() {
                self.latest_received_id = Some(
                    self.latest_received_id
                        .map(|id| id.max(msg_id))
                        .unwrap_or(msg_id),
                );
            }
            self.oldest_id = Some(self.oldest_id.map(|id| id.min(msg_id)).unwrap_or(msg_id));
            self.messages.insert(msg_id, msg);
        }
    }

    pub fn load_initial(
        &mut self,
        mut fetch: impl FnMut(Option<i64>, Option<i64>, u16) -> Result<Vec<ConvoMessage>, String>,
    ) {
        match fetch(None, None, INITIAL_LIMIT) {
            Ok(messages) => {
                debug!(count = messages.len(), "chat initial load");
                self.apply_messages(messages);
                self.initialized = true;
            }
            Err(err) => {
                tracing::warn!("chat initial load failed: {err}");
            }
        }
    }

    pub fn refresh_newer(
        &mut self,
        mut fetch: impl FnMut(Option<i64>, Option<i64>, u16) -> Result<Vec<ConvoMessage>, String>,
    ) {
        let mut after = self
            .latest_received_id
            .and_then(|id| id.checked_add(1))
            .unwrap_or_default();
        loop {
            match fetch(None, Some(after), PAGE_LIMIT) {
                Ok(messages) => {
                    tracing::debug!(count = messages.len(), "received chat batch");
                    if messages.is_empty() {
                        break;
                    }
                    after = messages.last().map(|msg| msg.id + 1).unwrap_or_default();
                    self.apply_messages(messages);
                }
                Err(err) => {
                    tracing::warn!("chat history refresh failed: {err}");
                    break;
                }
            }
        }
    }

    pub fn load_older(
        &mut self,
        mut fetch: impl FnMut(Option<i64>, Option<i64>, u16) -> Result<Vec<ConvoMessage>, String>,
    ) {
        if self.no_more_older {
            return;
        }
        let Some(oldest_id) = self.oldest_id else {
            self.no_more_older = true;
            return;
        };
        let Some(before) = oldest_id.checked_sub(1) else {
            self.no_more_older = true;
            return;
        };
        match fetch(Some(before), None, PAGE_LIMIT) {
            Ok(messages) => {
                if messages.is_empty() {
                    self.no_more_older = true;
                } else {
                    self.apply_messages(messages);
                }
            }
            Err(err) => {
                tracing::warn!("chat older load failed: {err}");
            }
        }
    }
}
