pub mod device;
pub mod dir;
pub mod keygen;

use clap::Subcommand;

use crate::shared::GlobalArgs;

#[derive(Subcommand)]
pub enum Command {
    Keygen(keygen::Args),
    Dir(Box<dir::Args>),
    Device(device::Args),
}

impl Command {
    pub async fn run(self, global: &GlobalArgs) -> anyhow::Result<()> {
        match self {
            Command::Keygen(args) => keygen::run(args).await,
            Command::Dir(args) => dir::run(*args, global).await,
            Command::Device(args) => device::run(args, global).await,
        }
    }
}
