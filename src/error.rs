use std::borrow::Cow;
use std::io;
use std::path::PathBuf;
use dstu4145_rust::error::Dstu4145Error;
pub type Result<'a, T> = core::result::Result<T, CliError<'a>>;
#[derive(thiserror::Error, Debug)]
pub enum CliError<'a>
{
  #[error("Got error from signature driver: {0}")]
  SignError(#[from] Dstu4145Error),
  #[error("Got error reading/writing error: '{0}'")]
  FileError(Cow<'a, str>),
  #[error("Incorrect path to the file for signing, please check validity of the path (err: path is not a file), got path: {0}")]
  IncorrectPathToFile(PathBuf),
  #[error("Got error in reading/writing file, error: {0}")]
  IoError(#[from] io::Error),
  #[error("Failed to parse hex string, please check validity of it")]
  FailedToParseHex(#[from] num_bigint::ParseBigIntError),
  #[error("Got signature error, err: {0}")]
  SignatureError(#[from] signature::Error),
}
