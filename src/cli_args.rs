use std::path::PathBuf;
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use crate::error::CliError;
use crate::utils::{read_file, sign_ordinary, sign_original, verify_ordinary, verify_original, write_into_stdout};

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
    #[arg(short, long)]
    /// Optional flag that represents usage of already generated verifying key d
    signing_key : Option<String>,
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
    #[arg(short, long)]
    /// Optional flag that represents usage of already generated verifying key d
    signing_key : Option<String>,
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

pub fn process_args(cli_args : CliArgs) -> crate::error::Result<'static, ()>
{
  match cli_args
  {
    CliArgs::Sign(option) => match option
    {
      SignCommand::File {
        filepath: filename,
        ec,
        l_d,
        gost_hash,
        signing_key,
      } =>
      {
        let msg = read_file(filename.clone())?;

        let (priv_key, pub_key, sign) = match gost_hash
        {
          true => sign_original(ec.clone(), l_d, msg, signing_key),
          false => sign_ordinary(ec.clone(), l_d, msg, signing_key),
        }?;
        write_into_stdout(format!(
          "Program signed file {filename:?} successfully ✔️, \
        d: '{priv_key}', packed_pub_key: '{pub_key}', packed_sign: '{sign}', \
        l_d: {l_d}, ec_option: {ec}, gost_hash_flag: {gost_hash}"
        ))?;
      }
      SignCommand::Msg {
        msg: text,
        ec,
        l_d,
        gost_hash,
        signing_key,
      } =>
      {
        let (priv_key, pub_key, sign) = match gost_hash
        {
          true => sign_original(ec.clone(), l_d, text.as_bytes().to_vec(), signing_key),
          false => sign_ordinary(ec.clone(), l_d, text.as_bytes().to_vec(), signing_key),
        }?;
        write_into_stdout(format!(
          "Program signed msg {text} successfully ✔️, \
        d: '{priv_key}', packed_pub_key: '{pub_key}', packed_sign: '{sign}', \
        l_d: {l_d}, ec_option: {ec}"
        ))?;
      }
    },
    CliArgs::Verify(option) => match option
    {
      VerifyCommand::File {
        verifying_key,
        sign,
        filepath: filename,
        ec,
        l_d,
        gost_hash,
      } =>
      {
        let msg = read_file(&filename)?;
        match gost_hash
        {
          true => verify_original(verifying_key, sign, ec, msg, l_d),
          false => verify_ordinary(verifying_key, sign, ec, msg, l_d),
        }?;
        write_into_stdout(format!(
          "Signature verified successfully ✔️ for file: {filename:?}, gost_hash_flag: {gost_hash}"
        ))?;
      }
      VerifyCommand::Msg {
        verifying_key,
        sign,
        msg: text,
        ec,
        l_d,
        gost_hash,
      } =>
      {
        match gost_hash
        {
          true => verify_original(verifying_key, sign, ec, text.as_bytes().to_vec(), l_d),
          false => verify_ordinary(verifying_key, sign, ec, text.as_bytes().to_vec(), l_d),
        }?;
        write_into_stdout(format!(
          "Signature verified successfully ✔️ for msg: {text:?}, gost_hash_flag: {gost_hash}"
        ))?;
      }
    },
  };
  Ok(())
}
