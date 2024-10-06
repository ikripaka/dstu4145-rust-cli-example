use std::io::Write;
use clap::Parser;
use num_bigint::BigUint;
use num_traits::Num;
use tracing_subscriber::{fmt, EnvFilter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use dstu4145_presentation_cli::cli_args::{CliArgs, SignCommand, VerifyCommand};
use dstu4145_presentation_cli::utils::{read_file, sign_ordinary, sign_original, verify_ordinary, verify_original};

fn main() -> dstu4145_presentation_cli::error::Result<'static, ()>
{
  tracing_subscriber::registry()
    .with(fmt::layer())
    .with(EnvFilter::from_default_env())
    .init();
  let args = CliArgs::parse();
  process_args(args)
}

fn process_args(cli_args : CliArgs) -> dstu4145_presentation_cli::error::Result<'static, ()>
{
  match cli_args
  {
    CliArgs::Sign(option) => match option
    {
      SignCommand::File {
        filename,
        ec,
        l_d,
        gost_hash,
      } =>
      {
        let msg = read_file(filename.clone())?;

        let (priv_key, pub_key, sign) = match gost_hash
        {
          true => sign_original(ec.clone(), l_d, msg),
          false => sign_ordinary(ec.clone(), l_d, msg),
        }?;
        write_into_stdout(format!(
          "Program signed file {filename:?} successfully, \
        d: '{priv_key}', packed_pub_key: '{pub_key}', packed_sign: '{sign}', \
        l_d: {l_d}, ec_option: {ec}, gost_hash_flag: {gost_hash}"
        ))?;
      }
      SignCommand::Text {
        text,
        ec,
        l_d,
        gost_hash,
      } =>
      {
        let (priv_key, pub_key, sign) = match gost_hash
        {
          true => sign_original(ec.clone(), l_d, text.as_bytes().to_vec()),
          false => sign_ordinary(ec.clone(), l_d, text.as_bytes().to_vec()),
        }?;
        write_into_stdout(format!(
          "Program signed msg {text} successfully, \
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
        filename,
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
          "Signature verified successfully for file: {filename:?}, gost_hash_flag: {gost_hash}"
        ))?;
      }
      VerifyCommand::Text {
        verifying_key,
        sign,
        text,
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
          "Signature verified successfully for text: {text:?}, gost_hash_flag: {gost_hash}"
        ))?;
      }
    },
  };
  Ok(())
}

fn write_into_stdout<T : AsRef<str>>(text : T) -> std::io::Result<usize> { std::io::stdout().write(text.as_ref().as_bytes()) }
