use anyctx::AnyCtx;
use futures_concurrency::future::Race;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::str::FromStr;
use nullspace_crypt::hash::Hash;
use nullspace_structs::group::GroupId;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;

use crate::config::Config;

mod dm_common;
mod dm_recv;
mod group;
mod group_recv;
mod rekey;
mod roster;
mod send;

pub use group::{create_group, invite, accept_invite, load_group};
pub use roster::GroupRoster;
pub use send::queue_message;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConvoId {
    Direct { peer: UserName },
    Group { group_id: GroupId },
}

impl ConvoId {
    pub fn convo_type(&self) -> &'static str {
        match self {
            ConvoId::Direct { .. } => "direct",
            ConvoId::Group { .. } => "group",
        }
    }

    pub fn counterparty(&self) -> String {
        match self {
            ConvoId::Direct { peer } => peer.as_str().to_string(),
            ConvoId::Group { group_id } => group_id.to_string(),
        }
    }
}

pub fn parse_convo_id(convo_type: &str, counterparty: &str) -> Option<ConvoId> {
    match convo_type {
        "direct" => UserName::parse(counterparty)
            .ok()
            .map(|peer| ConvoId::Direct { peer }),
        "group" => GroupId::from_str(counterparty)
            .ok()
            .map(|group_id| ConvoId::Group { group_id }),
        _ => None,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvoMessage {
    pub id: i64,
    pub convo_id: ConvoId,
    pub sender: UserName,
    pub body: MessageContent,
    pub send_error: Option<String>,
    pub received_at: Option<NanoTimestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageContent {
    PlainText(String),
    Markdown(String),
    Attachment {
        id: Hash,
        size: u64,
        mime: SmolStr,
        filename: SmolStr,
    },
    GroupInvite { invite_id: i64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvoSummary {
    pub convo_id: ConvoId,
    pub last_message: Option<ConvoMessage>,
}

pub async fn convo_loop(ctx: &AnyCtx<Config>) {
    (
        send::send_loop(ctx),
        dm_recv::dm_recv_loop(ctx),
        group_recv::group_recv_loop(ctx),
        rekey::group_rekey_loop(ctx),
    )
        .race()
        .await;
}
