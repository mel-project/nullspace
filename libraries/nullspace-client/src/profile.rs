use nullspace_crypt::signing::Signable;
use nullspace_structs::fragment::ImageAttachment;
use nullspace_structs::profile::UserProfile;
use nullspace_structs::timestamp::Timestamp;
use nullspace_structs::username::UserName;

use crate::config::Config;
use crate::database::DATABASE;
use crate::identity::identity_exists;
use crate::identity::Identity;
use crate::internal::InternalRpcError;
use crate::server::{get_server_client, own_server_name};
use crate::user_info::get_user_info;

pub async fn get_profile(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<Option<UserProfile>> {
    let user = get_user_info(ctx, username).await?;
    let profile = user
        .server
        .profile(username.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let Some(profile) = profile else {
        return Ok(None);
    };

    let mut verified = false;
    for device_pk in &user.devices {
        if profile.verify(*device_pk).is_ok() {
            verified = true;
            break;
        }
    }

    if !verified {
        return Err(anyhow::anyhow!(
            "profile signature did not verify against any device"
        ));
    }

    Ok(Some(profile))
}

pub async fn own_profile_set(
    ctx: &anyctx::AnyCtx<Config>,
    display_name: Option<String>,
    avatar: Option<ImageAttachment>,
) -> Result<(), InternalRpcError> {
    let db = ctx.get(DATABASE);
    if !identity_exists(&mut *db.acquire().await.map_err(|err| {
        InternalRpcError::Other(err.to_string())
    })?)
    .await
    .map_err(|err| InternalRpcError::Other(err.to_string()))?
    {
        return Err(InternalRpcError::NotReady);
    }
    let identity = Identity::load(
        &mut *db
            .acquire()
            .await
            .map_err(|err| InternalRpcError::Other(err.to_string()))?,
    )
    .await
    .map_err(|err| InternalRpcError::Other(err.to_string()))?;
    let server_name = own_server_name(ctx, &identity)
        .await
        .map_err(|err| InternalRpcError::Other(err.to_string()))?;
    let server = get_server_client(ctx, &server_name)
        .await
        .map_err(|err| InternalRpcError::Other(err.to_string()))?;

    let created = Timestamp::now();
    let mut profile = UserProfile {
        display_name,
        avatar,
        dm_mailbox: identity.dm_mailbox_id(),
        created,
        signature: nullspace_crypt::signing::Signature::from_bytes([0u8; 64]),
    };
    profile.sign(&identity.device_secret);
    server
        .profile_set(identity.username, profile)
        .await
        .map_err(|err| InternalRpcError::Other(err.to_string()))?
        .map_err(|err| InternalRpcError::Other(err.to_string()))?;
    Ok(())
}
