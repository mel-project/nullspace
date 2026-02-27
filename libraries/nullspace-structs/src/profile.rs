use nullspace_crypt::{
    hash::BcsHashExt,
    signing::{Signable, Signature},
};
use serde::{Deserialize, Serialize};

use crate::{fragment::ImageAttachment, mailbox::MailboxId, timestamp::Timestamp};

/// A signed user profile, containing the profile picture and various other objects.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserProfile {
    pub display_name: Option<String>,
    pub avatar: Option<ImageAttachment>,
    pub dm_mailbox: MailboxId,
    pub created: Timestamp,

    pub signature: Signature,
}

impl Signable for UserProfile {
    fn signed_value(&self) -> Vec<u8> {
        (
            &self.display_name,
            &self.avatar,
            self.dm_mailbox,
            self.created,
        )
            .bcs_keyed_hash("user_profile")
            .to_bytes()
            .to_vec()
    }

    fn signature_mut(&mut self) -> &mut Signature {
        &mut self.signature
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}
