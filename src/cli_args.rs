use std::path::PathBuf;
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use crate::error::CliError;

#[derive(Serialize, Deserialize, Debug, Parser)]
pub enum CliArgs
{
  #[command(subcommand)]
  Sign(SignCommand),
  #[command(subcommand)]
  Verify(VerifyCommand),
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
pub enum VerifyCommand
{
  File
  {
    #[arg(short, long)]
    verifying_key : String,
    #[arg(short, long)]
    sign : String,
    #[arg(short, long, value_parser = check_file)]
    filename : PathBuf,
    #[arg(short, long)]
    ec : CurveIndex,
    #[arg(short, long)]
    l_d : u64,
    #[arg(short, long)]
    gost_hash : bool,
  },
  Text
  {
    #[arg(short, long)]
    verifying_key : String,
    #[arg(short, long)]
    sign : String,
    #[arg(short, long)]
    text : String,
    #[arg(short, long)]
    ec : CurveIndex,
    #[arg(short, long)]
    l_d : u64,
    #[arg(short, long)]
    gost_hash : bool,
  },
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
pub enum SignCommand
{
  File
  {
    #[arg(short, long, value_parser = check_file)]
    filename : PathBuf,
    #[arg(short, long)]
    ec : CurveIndex,
    #[arg(short, long)]
    l_d : u64,
    #[arg(short, long)]
    gost_hash : bool,
  },
  Text
  {
    #[arg(short, long)]
    text : String,
    #[arg(short, long)]
    ec : CurveIndex,
    #[arg(short, long)]
    l_d : u64,
    #[arg(short, long)]
    gost_hash : bool,
  },
}

#[derive(ValueEnum, Debug, Clone, Serialize, Deserialize, strum::Display)]
pub enum CurveIndex
{
  EcGF163,
  EcGF167,
  EcGF173,
  EcGF179,
  EcGF191,
  EcGF233,
  EcGF257,
  EcGF307,
  EcGF367,
  EcGF431,
}

fn check_file(path : &str) -> core::result::Result<PathBuf, String>
{
  let path = PathBuf::from(path);
  if path.is_file()
  {
    Ok(path)
  }
  else
  {
    Err(CliError::IncorrectPathToFile(path.clone()).to_string())
  }
}
