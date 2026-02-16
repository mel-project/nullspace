use clap::Parser;
use nullspace_crypt::{
    dh::{DhPublic, DhSecret},
    signing::{SigningPublic, SigningSecret},
};
use serde::Serialize;

use crate::shared::print_json;

#[derive(Parser)]
pub struct Args {}

#[derive(Serialize)]
struct Output {
    signing: SigningKeyPair,
    dh: DhKeyPair,
}

#[derive(Serialize)]
struct SigningKeyPair {
    public: SigningPublic,
    secret: SigningSecret,
}

#[derive(Serialize)]
struct DhKeyPair {
    public: DhPublic,
    secret: DhSecret,
}

pub async fn run(_args: Args) -> anyhow::Result<()> {
    let signing_secret = SigningSecret::random();
    let dh_secret = DhSecret::random();
    let output = Output {
        signing: SigningKeyPair {
            public: signing_secret.public_key(),
            secret: signing_secret,
        },
        dh: DhKeyPair {
            public: dh_secret.public_key(),
            secret: dh_secret,
        },
    };
    print_json(&output)?;
    Ok(())
}
