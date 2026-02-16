use nullspace_crypt::signing::Signable;
use nullspace_structs::profile::UserProfile;
use nullspace_structs::username::UserName;

use crate::config::Config;
use crate::user_info::get_user_info;

pub async fn get_profile(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<Option<UserProfile>> {
    let user = get_user_info(ctx, username).await?;
    let profile = user
        .server
        .v1_profile(username.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let Some(profile) = profile else {
        return Ok(None);
    };

    let mut verified = false;
    for device in user.devices.values() {
        if profile.verify(device.device_pk).is_ok() {
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
