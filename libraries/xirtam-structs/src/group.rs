use bytes::Bytes;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use xirtam_crypt::{
    aead::AeadKey,
    hash::{Hash, HashParseError},
    signing::Signature,
};

use crate::{
    Blob,
    certificate::{CertificateChain, DeviceSecret},
    msg_content::MessagePayload,
    server::{AuthToken, ServerName},
    timestamp::{NanoTimestamp, Timestamp},
    username::UserName,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
#[serde(transparent)]
pub struct GroupId(Hash);

#[derive(Debug, Error)]
#[error("invalid group id")]
pub struct GroupIdParseError;

/// A group descriptor. Describes a group as it exists on a particular server.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct GroupDescriptor {
    pub nonce: Hash,
    pub init_admin: UserName,
    pub created_at: Timestamp,
    pub server: ServerName,
    pub management_key: AeadKey,
}

/// A group invite, sent in messages in JSON format.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct GroupInviteMsg {
    pub descriptor: GroupDescriptor,
    pub group_key: AeadKey,
    pub token: AuthToken,
    pub created_at: NanoTimestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMessage {
    pub nonce: [u8; 24],
    pub ciphertext: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedGroupMessage {
    pub group: GroupId,
    pub sender: UserName,
    pub sender_chain: CertificateChain,
    pub message: Blob,
    pub signature: Signature,
}

#[derive(Debug, Error)]
pub enum GroupMessageError {
    #[error("encode error")]
    Encode,
    #[error("decode error")]
    Decode,
    #[error("encrypt error")]
    Encrypt,
    #[error("decrypt error")]
    Decrypt,
    #[error("verify error")]
    Verify,
}

impl GroupId {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Hash::from_bytes(bytes))
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for GroupId {
    type Err = GroupIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hash = Hash::from_str(s).map_err(|_err: HashParseError| GroupIdParseError)?;
        Ok(Self(hash))
    }
}

impl GroupDescriptor {
    pub fn id(&self) -> GroupId {
        GroupId(Hash::digest(
            &bcs::to_bytes(self).expect("bcs serialization failed"),
        ))
    }
}

impl GroupMessage {
    pub fn encrypt_message(
        group: GroupId,
        message: &Blob,
        sender_username: UserName,
        sender_chain: CertificateChain,
        sender_device: &DeviceSecret,
        key: &AeadKey,
    ) -> Result<Self, GroupMessageError> {
        let signed = signed_bytes(&group, &sender_username, message)?;
        let signature = sender_device.sign(&signed);
        let plaintext = SignedGroupMessage {
            group,
            sender: sender_username,
            sender_chain,
            message: message.clone(),
            signature,
        };
        let plaintext_bytes = bcs::to_bytes(&plaintext).map_err(|_| GroupMessageError::Encode)?;
        let mut nonce = [0u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = key
            .encrypt(nonce, &plaintext_bytes, &[])
            .map_err(|_| GroupMessageError::Encrypt)?;
        Ok(Self {
            nonce,
            ciphertext: Bytes::from(ciphertext),
        })
    }

    pub fn decrypt_message(&self, key: &AeadKey) -> Result<SignedGroupMessage, GroupMessageError> {
        let plaintext = key
            .decrypt(self.nonce, &self.ciphertext, &[])
            .map_err(|_| GroupMessageError::Decrypt)?;
        bcs::from_bytes(&plaintext).map_err(|_| GroupMessageError::Decode)
    }
}

impl SignedGroupMessage {
    pub fn username(&self) -> &UserName {
        &self.sender
    }

    pub fn verify(self, sender_root_hash: Hash) -> Result<Blob, GroupMessageError> {
        self.sender_chain
            .verify(sender_root_hash)
            .map_err(|_| GroupMessageError::Verify)?;
        let device = self.sender_chain.last_device();
        let signed = signed_bytes(&self.group, &self.sender, &self.message)?;
        device
            .pk
            .verify(&self.signature, &signed)
            .map_err(|_| GroupMessageError::Verify)?;
        Ok(self.message)
    }
}

fn signed_bytes(
    group: &GroupId,
    sender: &UserName,
    message: &Blob,
) -> Result<Vec<u8>, GroupMessageError> {
    bcs::to_bytes(&(group, sender, message)).map_err(|_| GroupMessageError::Encode)
}

impl MessagePayload for GroupInviteMsg {
    fn mime() -> &'static str {
        "application/vnd.xirtam.v1.group_invite"
    }
}

/// A group management message, sent in group chats in JSON format.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(rename_all = "snake_case")]
pub enum GroupManageMsg {
    InviteSent(UserName),
    InviteAccepted,
    Ban(UserName),
    Unban(UserName),
    Leave,
    AddAdmin(UserName),
    RemoveAdmin(UserName),
}

impl MessagePayload for GroupManageMsg {
    fn mime() -> &'static str {
        "application/vnd.xirtam.v1.group_manage"
    }
}
