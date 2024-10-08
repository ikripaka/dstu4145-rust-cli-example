use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use dstu4145_presentation_cli::cli_args::{process_args, CliArgs};

fn main() -> dstu4145_presentation_cli::error::Result<'static, ()>
{
  tracing_subscriber::registry()
    .with(fmt::layer())
    .with(EnvFilter::from_default_env())
    .init();
  let args = CliArgs::parse();
  process_args(args)
}
