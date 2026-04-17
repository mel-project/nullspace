use std::collections::{BTreeMap, BTreeSet};

use nullspace_crypt::hash::Hash;
use nullspace_crypt::signing::SigningPublic;
use nullspace_structs::group::{
    GroupBearerKey, GroupId, GroupMetadata, GroupRoster, GroupRosterSettings, MemberState,
};
use nullspace_structs::server::ServerName;
use nullspace_structs::username::UserName;

pub struct LoadedGbk {
    pub rotation_index: u64,
    pub gbk: GroupBearerKey,
    pub server_name: ServerName,
    pub admin_set: BTreeSet<SigningPublic>,
    pub rotation_hash: Hash,
}

pub async fn store_gbk(
    conn: &mut sqlx::SqliteConnection,
    group_id: GroupId,
    gbk: &GroupBearerKey,
    server_name: &ServerName,
    rotation_index: u64,
    admin_set: &BTreeSet<SigningPublic>,
    rotation_hash: &Hash,
) -> anyhow::Result<()> {
    let gid = group_id.to_bytes().to_vec();
    sqlx::query("DELETE FROM group_keys WHERE group_id = ?")
        .bind(&gid)
        .execute(&mut *conn)
        .await?;

    sqlx::query(
        "INSERT INTO group_keys (group_id, rotation_index, gbk, server_name, admin_set, rotation_hash) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&gid)
    .bind(rotation_index as i64)
    .bind(bcs::to_bytes(gbk)?)
    .bind(server_name.as_str())
    .bind(bcs::to_bytes(admin_set)?)
    .bind(rotation_hash.to_bytes().to_vec())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn replace_current_roster(
    conn: &mut sqlx::SqliteConnection,
    group_id: GroupId,
    rotation_index: u64,
    roster: &GroupRoster,
) -> anyhow::Result<()> {
    let gid = group_id.to_bytes().to_vec();

    sqlx::query(
        "INSERT INTO group_state_current \
         (group_id, rotation_index, title, description, new_members_muted, allow_new_members_to_see_history) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT(group_id) DO UPDATE SET \
           rotation_index = excluded.rotation_index, \
           title = excluded.title, \
           description = excluded.description, \
           new_members_muted = excluded.new_members_muted, \
           allow_new_members_to_see_history = excluded.allow_new_members_to_see_history",
    )
    .bind(&gid)
    .bind(rotation_index as i64)
    .bind(&roster.metadata.title)
    .bind(&roster.metadata.description)
    .bind(roster.settings.new_members_muted)
    .bind(roster.settings.allow_new_members_to_see_history)
    .execute(&mut *conn)
    .await?;

    sqlx::query("DELETE FROM group_members_current WHERE group_id = ?")
        .bind(&gid)
        .execute(&mut *conn)
        .await?;

    for (username, state) in &roster.members {
        sqlx::query(
            "INSERT INTO group_members_current \
             (group_id, username, is_admin, is_muted, is_banned) VALUES (?, ?, ?, ?, 0)",
        )
        .bind(&gid)
        .bind(username.as_str())
        .bind(state.is_admin)
        .bind(state.is_muted)
        .execute(&mut *conn)
        .await?;
    }

    for username in &roster.banned {
        sqlx::query(
            "INSERT INTO group_members_current \
             (group_id, username, is_admin, is_muted, is_banned) VALUES (?, ?, 0, 0, 1)",
        )
        .bind(&gid)
        .bind(username.as_str())
        .execute(&mut *conn)
        .await?;
    }

    sqlx::query("DELETE FROM group_rosters WHERE group_id = ?")
        .bind(gid)
        .execute(&mut *conn)
        .await?;

    Ok(())
}

pub async fn load_roster(
    conn: &mut sqlx::SqliteConnection,
    group_id: GroupId,
) -> anyhow::Result<(u64, GroupRoster)> {
    if let Some(row) = sqlx::query_as::<_, (i64, Option<String>, Option<String>, bool, bool)>(
        "SELECT rotation_index, title, description, new_members_muted, allow_new_members_to_see_history \
         FROM group_state_current WHERE group_id = ?",
    )
    .bind(group_id.to_bytes().to_vec())
    .fetch_optional(&mut *conn)
    .await?
    {
        let member_rows = sqlx::query_as::<_, (String, bool, bool, bool)>(
            "SELECT username, is_admin, is_muted, is_banned \
             FROM group_members_current WHERE group_id = ?",
        )
        .bind(group_id.to_bytes().to_vec())
        .fetch_all(&mut *conn)
        .await?;

        let mut members = BTreeMap::new();
        let mut banned = BTreeSet::new();
        for (username, is_admin, is_muted, is_banned) in member_rows {
            let username = UserName::parse(username)?;
            if is_banned {
                banned.insert(username);
            } else {
                members.insert(
                    username,
                    MemberState {
                        is_admin,
                        is_muted,
                    },
                );
            }
        }

        return Ok((
            row.0 as u64,
            GroupRoster {
                members,
                banned,
                metadata: GroupMetadata {
                    title: row.1,
                    description: row.2,
                },
                settings: GroupRosterSettings {
                    new_members_muted: row.3,
                    allow_new_members_to_see_history: row.4,
                },
            },
        ));
    }

    let Some((rotation_index, roster_bytes)) = sqlx::query_as::<_, (i64, Vec<u8>)>(
        "SELECT rotation_index, roster FROM group_rosters WHERE group_id = ?",
    )
    .bind(group_id.to_bytes().to_vec())
    .fetch_optional(&mut *conn)
    .await?
    else {
        anyhow::bail!("no roster found for group {group_id}");
    };

    let roster: GroupRoster = bcs::from_bytes(&roster_bytes)?;
    replace_current_roster(conn, group_id, rotation_index as u64, &roster).await?;
    Ok((rotation_index as u64, roster))
}

pub async fn remove_local_group_state(
    conn: &mut sqlx::SqliteConnection,
    group_id: GroupId,
) -> anyhow::Result<()> {
    let gid = group_id.to_bytes().to_vec();
    sqlx::query("DELETE FROM group_keys WHERE group_id = ?")
        .bind(&gid)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM group_state_current WHERE group_id = ?")
        .bind(&gid)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM group_members_current WHERE group_id = ?")
        .bind(&gid)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM group_rosters WHERE group_id = ?")
        .bind(gid)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub async fn load_gbk(
    conn: &mut sqlx::SqliteConnection,
    group_id: GroupId,
) -> anyhow::Result<LoadedGbk> {
    let row = sqlx::query_as::<_, (i64, Vec<u8>, String, Vec<u8>, Vec<u8>)>(
        "SELECT rotation_index, gbk, server_name, admin_set, rotation_hash \
         FROM group_keys WHERE group_id = ? ORDER BY rotation_index DESC LIMIT 1",
    )
    .bind(group_id.to_bytes().to_vec())
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| anyhow::anyhow!("no GBK found for group {group_id}"))?;
    let gbk: GroupBearerKey = bcs::from_bytes(&row.1)?;
    let server_name = ServerName::parse(row.2)?;
    let admin_set: BTreeSet<SigningPublic> = bcs::from_bytes(&row.3)?;
    let rotation_hash = Hash::from_bytes(
        row.4
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid rotation_hash length"))?,
    );
    Ok(LoadedGbk {
        rotation_index: row.0 as u64,
        gbk,
        server_name,
        admin_set,
        rotation_hash,
    })
}
