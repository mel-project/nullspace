mod commands;
mod shared;

use clap::Parser;
use shared::GlobalArgs;

#[derive(Parser)]
#[command(name = "xirtam-multitool")]
struct Args {
    #[command(flatten)]
    global: GlobalArgs,
    #[command(subcommand)]
    command: commands::Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    args.command.run(&args.global).await
}
