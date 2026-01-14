use bytes::Bytes;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xirtam_crypt::{aead::AeadKey, hash::Hash, signing::Signature};

use crate::{
    certificate::{CertificateChain, DeviceSecret},
    gateway::{AuthToken, GatewayName},
    handle::Handle,
    msg_content::MessagePayload,
    timestamp::Timestamp,
    Blob,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
#[serde(transparent)]
pub struct GroupId(Hash);

/// A group descriptor. Describes a group as it exists on a particular gateway.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct GroupDescriptor {
    pub nonce: Hash,
    pub init_admin: Handle,
    pub created_at: Timestamp,
    pub gateway: GatewayName,
    pub management_key: AeadKey,
}

/// A group invite, sent in messages in JSON format.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct GroupInviteMsg {
    pub descriptor: GroupDescriptor,
    pub group_key: AeadKey,
    pub token: AuthToken,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMessage {
    pub nonce: [u8; 24],
    pub ciphertext: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedGroupMessage {
    pub group: GroupId,
    pub sender: Handle,
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
        sender_handle: Handle,
        sender_chain: CertificateChain,
        sender_device: &DeviceSecret,
        key: &AeadKey,
    ) -> Result<Self, GroupMessageError> {
        let signed = signed_bytes(&group, &sender_handle, message)?;
        let signature = sender_device.sign(&signed);
        let plaintext = SignedGroupMessage {
            group,
            sender: sender_handle,
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
    pub fn handle(&self) -> &Handle {
        &self.sender
    }

    pub fn verify(self, sender_root_hash: Hash) -> Result<Blob, GroupMessageError> {
        let verified = self
            .sender_chain
            .verify(sender_root_hash)
            .map_err(|_| GroupMessageError::Verify)?;
        let device = verified.last().ok_or(GroupMessageError::Verify)?;
        let signed = signed_bytes(&self.group, &self.sender, &self.message)?;
        device
            .pk
            .verify(&self.signature, &signed)
            .map_err(|_| GroupMessageError::Verify)?;
        Ok(self.message)
    }
}

fn signed_bytes(group: &GroupId, sender: &Handle, message: &Blob) -> Result<Vec<u8>, GroupMessageError> {
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
    InviteSent(Handle),
    InviteAccepted,
    Ban(Handle),
    Unban(Handle),
    Leave,
    AddAdmin(Handle),
    RemoveAdmin(Handle),
}

impl MessagePayload for GroupManageMsg {
    fn mime() -> &'static str {
        "application/vnd.xirtam.v1.group_manage"
    }
}
