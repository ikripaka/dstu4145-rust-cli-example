use std::path::PathBuf;
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use crate::error::CliError;

#[derive(Serialize, Deserialize, Debug, Parser)]
pub enum CliArgs
{
  #[command(subcommand, about = "Command to sign message or file")]
  Sign(SignCommand),
  #[command(subcommand, about = "Command to verify signature for message or file")]
  Verify(VerifyCommand),
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
pub enum VerifyCommand
{
  #[command(about = "Command to sign file")]
  File
  {
    #[arg(short, long)]
    /// Packed public key component in HEX.
    verifying_key : String,
    #[arg(short, long)]
    /// Packed sign in HEX.
    sign : String,
    #[arg(short, long, value_parser = check_file)]
    /// File path to sign specific file.
    filepath : PathBuf,
    #[arg(short, long)]
    /// Elliptic curve that is used for computing points for signing.
    ec : CurveIndex,
    #[arg(short, long)]
    /// Length of packed sign in bits.
    l_d : u64,
    #[arg(short, long)]
    /// Flag that represents enables usage of GOST hash function usage.
    gost_hash : bool,
  },
  #[command(about = "Command to sign message")]
  Msg
  {
    #[arg(short, long)]
    /// Packed public key component in HEX
    verifying_key : String,
    #[arg(short, long)]
    /// Packed sign in HEX
    sign : String,
    #[arg(short, long)]
    /// Message to sign
    msg : String,
    #[arg(short, long)]
    /// Elliptic curve that is used for computing points for signing
    ec : CurveIndex,
    #[arg(short, long)]
    /// Length of packed sign in bits
    l_d : u64,
    #[arg(short, long)]
    /// Flag that enables usage of GOST hash function for verifying
    gost_hash : bool,
  },
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
pub enum SignCommand
{
  #[command(about = "Command to sign file")]
  File
  {
    #[arg(short, long, value_parser = check_file)]
    /// File path to sign specific file
    filepath : PathBuf,
    #[arg(short, long)]
    /// Elliptic curve that is used for computing points for signing
    ec : CurveIndex,
    #[arg(short, long)]
    /// Length of packed sign in bits
    l_d : u64,
    #[arg(short, long)]
    /// Flag that enables usage of GOST hash function usage
    gost_hash : bool,
  },
  #[command(about = "Command to sign message")]
  Msg
  {
    #[arg(short, long)]
    /// Message to sign
    msg : String,
    #[arg(short, long)]
    /// Elliptic curve that is used for computing points for signing
    ec : CurveIndex,
    #[arg(short, long)]
    /// Length of packed sign in bits
    l_d : u64,
    #[arg(short, long)]
    /// Flag that enables usage of GOST hash function usage
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
