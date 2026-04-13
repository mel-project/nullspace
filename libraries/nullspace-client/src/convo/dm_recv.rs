use std::time::Duration;

use anyctx::AnyCtx;
use nullspace_structs::event::{Event, EventRecipient};
use nullspace_structs::mailbox::{MailboxEntry, MailboxId};
use nullspace_structs::server::ServerName;

use crate::config::Config;
use crate::convo::{
    NewThreadEvent, THREAD_KIND_DIRECT, ensure_thread_id, insert_thread_event,
    thread_accepts_event_link,
};
use crate::database::DATABASE;
use crate::events::emit_event;
use crate::identity::Identity;
use crate::net::LONG_POLLER;
use crate::net::get_auth_token;
use crate::net::{get_server_client, own_server_name};
use crate::net::{load_mailbox_after, update_mailbox_after};

use super::device_crypt::decrypt_and_verify;
use super::send::store_message_attachments;

pub(super) async fn dm_recv_loop(ctx: &AnyCtx<Config>) {
    loop {
        if let Err(err) = dm_recv_loop_once(ctx).await {
            tracing::error!(error = %err, "dm recv loop error");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn dm_recv_loop_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    // let mut conn = db.acquire().await?;
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    let server_name = own_server_name(ctx, &identity).await?;
    let server = get_server_client(ctx, &server_name).await?;
    let auth = get_auth_token(ctx).await?;
    let mailbox = identity.dm_mailbox_id();
    server
        .mailbox_create(auth, identity.dm_mailbox_key)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let mut after = load_mailbox_after(&mut *db.acquire().await?, &server_name, mailbox).await?;
    let poller = ctx.get(LONG_POLLER);
    loop {
        let entry = match poller
            .recv(server_name.clone(), identity.dm_mailbox_key, mailbox, after)
            .await
        {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(error = %err, "mailbox recv error");
                continue;
            }
        };
        after = entry.received_at;
        match process_mailbox_entry(ctx, &server_name, mailbox, entry).await {
            Ok(Some(convo_id)) => {
                emit_event(ctx, crate::internal::Event::ConvoUpdated { convo_id });
            }
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(error = %err, "failed to process mailbox entry");
            }
        }
    }
}

async fn process_mailbox_entry(
    ctx: &AnyCtx<Config>,
    server_name: &ServerName,
    mailbox: MailboxId,
    entry: MailboxEntry,
) -> anyhow::Result<Option<super::ConvoId>> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    update_mailbox_after(
        &mut *db.acquire().await?,
        server_name,
        mailbox,
        entry.received_at,
    )
    .await?;

    let verified = decrypt_and_verify(ctx, &identity, &entry.body.0).await?;
    let event: Event = bcs::from_bytes(&verified.payload)?;

    if event.sender != verified.sender {
        tracing::warn!(
            event_sender = %event.sender,
            verified_sender = %verified.sender,
            "ignoring event with sender mismatch",
        );
        return Ok(None);
    }

    let dm_recipient = match &event.recipient {
        EventRecipient::Dm(name) => name,
        EventRecipient::Group(_) => {
            tracing::warn!(
                sender = %verified.sender,
                "ignoring group event arriving in DM mailbox (context mismatch)",
            );
            return Ok(None);
        }
    };

    if *dm_recipient != identity.username && verified.sender != identity.username {
        tracing::warn!(
            sender = %verified.sender,
            recipient = %dm_recipient,
            "ignoring dm with mismatched recipient",
        );
        return Ok(None);
    }

    let peer_username = if verified.sender == identity.username {
        dm_recipient.clone()
    } else {
        verified.sender.clone()
    };

    let mut conn = db.acquire().await?;
    let thread_id = ensure_thread_id(&mut conn, THREAD_KIND_DIRECT, peer_username.as_str()).await?;
    if !thread_accepts_event_link(&mut conn, thread_id, event.after.as_ref()).await? {
        tracing::warn!(
            sender = %verified.sender,
            event_after = ?event.after,
            "dropping DM event with unknown event parent",
        );
        return Ok(None);
    }

    let event_hash = event.hash();
    let inserted = insert_thread_event(
        &mut conn,
        &NewThreadEvent {
            thread_id,
            sender: verified.sender.as_str(),
            event_tag: event.tag,
            event_body: &event.body,
            event_after: event.after.as_ref(),
            event_hash: &event_hash,
            sent_at: event.sent_at,
            received_at: Some(entry.received_at),
        },
    )
    .await?;

    if inserted.is_some() {
        store_message_attachments(&mut conn, event.tag, &event.body).await?;
        drop(conn);

        if event.tag == nullspace_structs::event::TAG_GROUP_INVITATION
            && verified.sender != identity.username
        {
            match event.decode_body::<nullspace_structs::event::GroupInvitation>() {
                Ok(invitation) => match super::convo_impl::accept_group_invitation(ctx, &invitation)
                    .await
                {
                    Ok(group_id) => {
                        emit_event(
                            ctx,
                            crate::internal::Event::ConvoUpdated {
                                convo_id: super::ConvoId::Group { group_id },
                            },
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            inviter = %verified.sender,
                            group = %invitation.group_id,
                            "failed to auto-accept group invitation",
                        );
                    }
                },
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        inviter = %verified.sender,
                        "failed to decode raw group invitation event",
                    );
                }
            }
            Ok(None)
        } else {
            Ok(Some(super::ConvoId::Direct {
                peer: peer_username,
            }))
        }
    } else {
        Ok(None)
    }
}
