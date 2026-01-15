use anyhow::Context;
use xirtam_structs::group::{GroupId, GroupManageMsg};
use xirtam_structs::username::UserName;

use crate::internal::GroupMemberStatus;

#[derive(Clone, Debug)]
pub struct RosterMember {
    pub username: UserName,
    pub is_admin: bool,
    pub status: GroupMemberStatus,
}

impl RosterMember {
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            GroupMemberStatus::Pending | GroupMemberStatus::Accepted
        )
    }
}

pub struct GroupRoster {
    group_id: GroupId,
    init_admin: UserName,
}

impl GroupRoster {
    pub async fn load(
        tx: &mut sqlx::SqliteConnection,
        group_id: GroupId,
        init_admin: UserName,
    ) -> anyhow::Result<Self> {
        let roster = Self {
            group_id,
            init_admin,
        };
        roster.ensure_initialized(tx).await?;
        Ok(roster)
    }

    pub async fn list(&self, tx: &mut sqlx::SqliteConnection) -> anyhow::Result<Vec<RosterMember>> {
        self.list_raw(tx).await
    }

    pub async fn get(
        &self,
        tx: &mut sqlx::SqliteConnection,
        username: &UserName,
    ) -> anyhow::Result<Option<RosterMember>> {
        self.get_raw(tx, username).await
    }

    pub async fn apply_manage_message(
        &self,
        tx: &mut sqlx::SqliteConnection,
        sender: &UserName,
        manage: GroupManageMsg,
    ) -> anyhow::Result<bool> {
        let sender_member = self.get_raw(tx, sender).await?;
        let sender_active = sender_member.as_ref().is_some_and(RosterMember::is_active);
        let sender_admin = sender_member
            .as_ref()
            .map(|member| member.is_admin && member.is_active())
            .unwrap_or(false);

        let changed = match manage {
            GroupManageMsg::InviteSent(username) => {
                if !sender_active {
                    false
                } else {
                    match self.get_raw(tx, &username).await? {
                        Some(member)
                            if member.status == GroupMemberStatus::Banned
                                || member.status == GroupMemberStatus::Accepted =>
                        {
                            false
                        }
                        Some(member) if member.status == GroupMemberStatus::Pending => false,
                        _ => {
                            self.upsert_member(
                                tx,
                                RosterMember {
                                    username,
                                    is_admin: false,
                                    status: GroupMemberStatus::Pending,
                                },
                            )
                            .await?
                        }
                    }
                }
            }
            GroupManageMsg::InviteAccepted => {
                if let Some(member) = self.get_raw(tx, sender).await? {
                    if member.status == GroupMemberStatus::Banned {
                        false
                    } else {
                        self.upsert_member(
                            tx,
                            RosterMember {
                                username: sender.clone(),
                                is_admin: false,
                                status: GroupMemberStatus::Accepted,
                            },
                        )
                        .await?
                    }
                } else {
                    self.upsert_member(
                        tx,
                        RosterMember {
                            username: sender.clone(),
                            is_admin: false,
                            status: GroupMemberStatus::Accepted,
                        },
                    )
                    .await?
                }
            }
            GroupManageMsg::Leave => match self.get_raw(tx, sender).await? {
                Some(member) if member.status == GroupMemberStatus::Banned => false,
                Some(_) => self.remove_member(tx, sender).await?,
                None => false,
            },
            GroupManageMsg::Ban(username) => {
                if !sender_admin {
                    false
                } else {
                    self.upsert_member(
                        tx,
                        RosterMember {
                            username,
                            is_admin: false,
                            status: GroupMemberStatus::Banned,
                        },
                    )
                    .await?
                }
            }
            GroupManageMsg::Unban(username) => {
                if !sender_admin {
                    false
                } else if let Some(member) = self.get_raw(tx, &username).await? {
                    if member.status == GroupMemberStatus::Banned {
                        self.upsert_member(
                            tx,
                            RosterMember {
                                username,
                                is_admin: false,
                                status: GroupMemberStatus::Pending,
                            },
                        )
                        .await?
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            GroupManageMsg::AddAdmin(username) => {
                if !sender_admin {
                    false
                } else if let Some(member) = self.get_raw(tx, &username).await? {
                    if member.is_active() {
                        self.upsert_member(
                            tx,
                            RosterMember {
                                username,
                                is_admin: true,
                                status: member.status,
                            },
                        )
                        .await?
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            GroupManageMsg::RemoveAdmin(username) => {
                if !sender_admin {
                    false
                } else if let Some(member) = self.get_raw(tx, &username).await? {
                    if member.is_active() {
                        self.upsert_member(
                            tx,
                            RosterMember {
                                username,
                                is_admin: false,
                                status: member.status,
                            },
                        )
                        .await?
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        };

        if changed {
            self.bump_version(tx).await?;
        }
        Ok(changed)
    }

    async fn ensure_initialized(&self, tx: &mut sqlx::SqliteConnection) -> anyhow::Result<()> {
        let row =
            sqlx::query_as::<_, (i64,)>("SELECT roster_version FROM groups WHERE group_id = ?")
                .bind(self.group_id.as_bytes().to_vec())
                .fetch_optional(&mut *tx)
                .await?;
        let Some((version,)) = row else {
            anyhow::bail!("group not found");
        };
        if version != 0 {
            return Ok(());
        }
        let _ = self
            .upsert_member(
                tx,
                RosterMember {
                    username: self.init_admin.clone(),
                    is_admin: true,
                    status: GroupMemberStatus::Accepted,
                },
            )
            .await?;
        sqlx::query("UPDATE groups SET roster_version = 1 WHERE group_id = ?")
            .bind(self.group_id.as_bytes().to_vec())
            .execute(&mut *tx)
            .await?;
        Ok(())
    }

    async fn list_raw(&self, tx: &mut sqlx::SqliteConnection) -> anyhow::Result<Vec<RosterMember>> {
        let rows = sqlx::query_as::<_, (String, i64, String)>(
            "SELECT username, is_admin, status FROM group_members WHERE group_id = ? ORDER BY username",
        )
        .bind(self.group_id.as_bytes().to_vec())
        .fetch_all(&mut *tx)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (username, is_admin, status) in rows {
            let username = UserName::parse(username)?;
            let status = status_from_str(&status).context("invalid group member status")?;
            out.push(RosterMember {
                username,
                is_admin: is_admin != 0,
                status,
            });
        }
        Ok(out)
    }

    async fn get_raw(
        &self,
        tx: &mut sqlx::SqliteConnection,
        username: &UserName,
    ) -> anyhow::Result<Option<RosterMember>> {
        let row = sqlx::query_as::<_, (i64, String)>(
            "SELECT is_admin, status FROM group_members WHERE group_id = ? AND username = ?",
        )
        .bind(self.group_id.as_bytes().to_vec())
        .bind(username.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let Some((is_admin, status)) = row else {
            return Ok(None);
        };
        let status = status_from_str(&status).context("invalid group member status")?;
        Ok(Some(RosterMember {
            username: username.clone(),
            is_admin: is_admin != 0,
            status,
        }))
    }

    async fn upsert_member(
        &self,
        tx: &mut sqlx::SqliteConnection,
        member: RosterMember,
    ) -> anyhow::Result<bool> {
        let existing = sqlx::query_as::<_, (i64, String)>(
            "SELECT is_admin, status FROM group_members WHERE group_id = ? AND username = ?",
        )
        .bind(self.group_id.as_bytes().to_vec())
        .bind(member.username.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((existing_admin, existing_status)) = existing {
            if existing_admin == i64::from(member.is_admin)
                && existing_status == status_as_str(&member.status)
            {
                return Ok(false);
            }
        }
        sqlx::query(
            "INSERT INTO group_members (group_id, username, is_admin, status) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(group_id, username) DO UPDATE SET \
             is_admin = excluded.is_admin, status = excluded.status",
        )
        .bind(self.group_id.as_bytes().to_vec())
        .bind(member.username.as_str())
        .bind(i64::from(member.is_admin))
        .bind(status_as_str(&member.status))
        .execute(&mut *tx)
        .await?;
        Ok(true)
    }

    async fn remove_member(
        &self,
        tx: &mut sqlx::SqliteConnection,
        username: &UserName,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query("DELETE FROM group_members WHERE group_id = ? AND username = ?")
            .bind(self.group_id.as_bytes().to_vec())
            .bind(username.as_str())
            .execute(&mut *tx)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn bump_version(&self, tx: &mut sqlx::SqliteConnection) -> anyhow::Result<()> {
        sqlx::query("UPDATE groups SET roster_version = roster_version + 1 WHERE group_id = ?")
            .bind(self.group_id.as_bytes().to_vec())
            .execute(&mut *tx)
            .await?;
        Ok(())
    }
}

fn status_from_str(value: &str) -> Option<GroupMemberStatus> {
    match value {
        "pending" => Some(GroupMemberStatus::Pending),
        "accepted" => Some(GroupMemberStatus::Accepted),
        "banned" => Some(GroupMemberStatus::Banned),
        _ => None,
    }
}

fn status_as_str(value: &GroupMemberStatus) -> &'static str {
    match value {
        GroupMemberStatus::Pending => "pending",
        GroupMemberStatus::Accepted => "accepted",
        GroupMemberStatus::Banned => "banned",
    }
}
