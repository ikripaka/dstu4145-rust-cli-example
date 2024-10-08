use std::borrow::Cow;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;
use dstu4145_rust::sign::{Signature, SigningKey, VerifyingKey, VerifyingKeyConstructor};
use gost94::Gost94UA;
use num_bigint::BigUint;
use num_traits::Num;
use poly_algebra::gf::{GFArithmetic, GF163, GF167, GF173, GF179, GF191, GF233, GF257, GF307, GF367, GF431};
use poly_algebra::helpers::get_string_hex_array_plain;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rust_ec::binary_ec::BinaryEC;
use signature::{DigestSigner, DigestVerifier, Signer, Verifier};
use signature::digest::Digest;
use tracing::trace;
use crate::cli_args::CurveIndex;
use crate::error::CliError;

pub fn read_file<T : AsRef<Path>>(filepath : T) -> crate::error::Result<'static, Vec<u8>>
{
  let mut buf = Vec::new();
  let mut file = OpenOptions::new().read(true).open(filepath)?;
  file.read_to_end(&mut buf)?;
  Ok(buf)
}

/// Function that writes bytes into file to reduce difficulty of using it internally.
pub fn write_file<'a, T : AsRef<Path>>(filepath : &'a T, bytes : &'a [u8]) -> crate::error::Result<'a, ()>
{
  let mut file = OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .open(filepath.as_ref())?;
  file.write_all(bytes)?;
  file.flush().map_err(|e| {
    CliError::FileError(Cow::from(format!(
      "Occurred problem with reading file: {e}, filepath: {:?}",
      filepath.as_ref().to_path_buf()
    )))
  })
}

pub fn write_into_stdout<T : AsRef<str>>(text : T) -> std::io::Result<usize>
{
  let mut output = text.as_ref().to_string();
  output.push('\n');
  std::io::stdout().write(output.as_bytes())
}

pub fn sign_ordinary_163<B : AsRef<[u8]>>(
  msg : B,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF163>, VerifyingKey<GF163>, Signature)>
{
  let ec = BinaryEC::generate_m163_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign(msg.as_ref());
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message in GF163");
  Ok((private_key, pub_key, signature))
}

fn generate_keys<'a, T : GFArithmetic<'a>>(
  ec : BinaryEC<T>,
  signing_key_hex : Option<String>,
  l_d : u64,
) -> crate::error::Result<'a, (SigningKey<T>, VerifyingKey<T>)>
{
  let (sign_key, verifying_key) = match signing_key_hex
  {
    None =>
    {
      let mut rng = ChaCha20Rng::from_entropy();
      SigningKey::generate(&mut rng, ec, l_d)
    }
    Some(signing_key) =>
    {
      let d = BigUint::from_str_radix(&signing_key, 16)?;
      SigningKey::from_secret(ec, d.to_bytes_be(), l_d)
    }
  }?;
  Ok((sign_key, verifying_key))
}

pub fn sign_ordinary_167<B : AsRef<[u8]>>(
  msg : B,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF167>, VerifyingKey<GF167>, Signature)>
{
  let ec = BinaryEC::generate_m167_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign(msg.as_ref());
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message in GF167");
  Ok((private_key, pub_key, signature))
}
pub fn sign_ordinary_173<B : AsRef<[u8]>>(
  msg : B,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF173>, VerifyingKey<GF173>, Signature)>
{
  let ec = BinaryEC::generate_m173_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign(msg.as_ref());
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message in GF173");
  Ok((private_key, pub_key, signature))
}
pub fn sign_ordinary_179<B : AsRef<[u8]>>(
  msg : B,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF179>, VerifyingKey<GF179>, Signature)>
{
  let ec = BinaryEC::generate_m179_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign(msg.as_ref());
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message in GF179");
  Ok((private_key, pub_key, signature))
}
pub fn sign_ordinary_191<B : AsRef<[u8]>>(
  msg : B,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF191>, VerifyingKey<GF191>, Signature)>
{
  let ec = BinaryEC::generate_m191_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign(msg.as_ref());
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message in GF191");
  Ok((private_key, pub_key, signature))
}
pub fn sign_ordinary_233<B : AsRef<[u8]>>(
  msg : B,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF233>, VerifyingKey<GF233>, Signature)>
{
  let ec = BinaryEC::generate_m233_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign(msg.as_ref());
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message in GF233");
  Ok((private_key, pub_key, signature))
}
pub fn sign_ordinary_257<B : AsRef<[u8]>>(
  msg : B,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF257>, VerifyingKey<GF257>, Signature)>
{
  let ec = BinaryEC::generate_m257_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign(msg.as_ref());
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message in GF257");
  Ok((private_key, pub_key, signature))
}
pub fn sign_ordinary_307<B : AsRef<[u8]>>(
  msg : B,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF307>, VerifyingKey<GF307>, Signature)>
{
  let ec = BinaryEC::generate_m307_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign(msg.as_ref());
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message in GF307");
  Ok((private_key, pub_key, signature))
}
pub fn sign_ordinary_367<B : AsRef<[u8]>>(
  msg : B,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF367>, VerifyingKey<GF367>, Signature)>
{
  let ec = BinaryEC::generate_m367_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign(msg.as_ref());
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message in GF367");
  Ok((private_key, pub_key, signature))
}
pub fn sign_ordinary_431<B : AsRef<[u8]>>(
  msg : B,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF431>, VerifyingKey<GF431>, Signature)>
{
  let ec = BinaryEC::generate_m431_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign(msg.as_ref());
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message in GF431");
  Ok((private_key, pub_key, signature))
}

pub fn sign_digest_163<D : Digest>(
  digest : D,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF163>, VerifyingKey<GF163>, Signature)>
{
  let ec = BinaryEC::generate_m163_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign_digest(digest);
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message with digest in GF163");
  Ok((private_key, pub_key, signature))
}
pub fn sign_digest_167<D : Digest>(
  digest : D,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF167>, VerifyingKey<GF167>, Signature)>
{
  let ec = BinaryEC::generate_m167_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign_digest(digest);
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message with digest in GF167");
  Ok((private_key, pub_key, signature))
}
pub fn sign_digest_173<D : Digest>(
  digest : D,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF173>, VerifyingKey<GF173>, Signature)>
{
  let ec = BinaryEC::generate_m173_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign_digest(digest);
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message with digest in GF173");
  Ok((private_key, pub_key, signature))
}
pub fn sign_digest_179<D : Digest>(
  digest : D,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF179>, VerifyingKey<GF179>, Signature)>
{
  let ec = BinaryEC::generate_m179_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign_digest(digest);
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message with digest in GF179");
  Ok((private_key, pub_key, signature))
}
pub fn sign_digest_191<D : Digest>(
  digest : D,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF191>, VerifyingKey<GF191>, Signature)>
{
  let ec = BinaryEC::generate_m191_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign_digest(digest);
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message with digest in GF191");
  Ok((private_key, pub_key, signature))
}
pub fn sign_digest_233<D : Digest>(
  digest : D,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF233>, VerifyingKey<GF233>, Signature)>
{
  let ec = BinaryEC::generate_m233_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign_digest(digest);
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message with digest in GF233");
  Ok((private_key, pub_key, signature))
}
pub fn sign_digest_257<D : Digest>(
  digest : D,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF257>, VerifyingKey<GF257>, Signature)>
{
  let ec = BinaryEC::generate_m257_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign_digest(digest);
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message with digest in GF257");
  Ok((private_key, pub_key, signature))
}
pub fn sign_digest_307<D : Digest>(
  digest : D,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF307>, VerifyingKey<GF307>, Signature)>
{
  let ec = BinaryEC::generate_m307_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign_digest(digest);
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message with digest in GF307");
  Ok((private_key, pub_key, signature))
}
pub fn sign_digest_367<D : Digest>(
  digest : D,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF367>, VerifyingKey<GF367>, Signature)>
{
  let ec = BinaryEC::generate_m367_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign_digest(digest);
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message with digest in GF367");
  Ok((private_key, pub_key, signature))
}
pub fn sign_digest_431<D : Digest>(
  digest : D,
  l_d : u64,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (SigningKey<GF431>, VerifyingKey<GF431>, Signature)>
{
  let ec = BinaryEC::generate_m431_pb_curve();
  let (private_key, pub_key) = generate_keys(ec, signing_key, l_d)?;
  let time_before = Instant::now();
  let signature = private_key.sign_digest(digest);
  trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on signing message with digest in GF431");
  Ok((private_key, pub_key, signature))
}

/// Function returns tuple with values `(<private_key_d_in_hex>, <packed_public_key_point>, <packed_signature>)`
pub fn convert_response<'a, T : GFArithmetic<'a>>(
  priv_key : SigningKey<T>,
  pub_key : VerifyingKey<T>,
  sign : Signature,
) -> (String, String, String)
{
  (
    priv_key.get_private_key().to_str_radix(16).to_uppercase(),
    get_string_hex_array_plain(&pub_key.pack()),
    get_string_hex_array_plain(&sign.pack()),
  )
}

pub fn sign_ordinary(
  ec : CurveIndex,
  l_d : u64,
  msg : Vec<u8>,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (String, String, String)>
{
  Ok(match ec
  {
    CurveIndex::EcGF163 =>
    {
      let (priv_key, pub_key, sign) = sign_ordinary_163(msg, l_d, signing_key)?;
      println!("pub key: {:X}", pub_key.get_pub_key());
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF167 =>
    {
      let (priv_key, pub_key, sign) = sign_ordinary_167(&msg, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF173 =>
    {
      let (priv_key, pub_key, sign) = sign_ordinary_173(&msg, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF179 =>
    {
      let (priv_key, pub_key, sign) = sign_ordinary_179(&msg, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF191 =>
    {
      let (priv_key, pub_key, sign) = sign_ordinary_191(&msg, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF233 =>
    {
      let (priv_key, pub_key, sign) = sign_ordinary_233(&msg, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF257 =>
    {
      let (priv_key, pub_key, sign) = sign_ordinary_257(&msg, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF307 =>
    {
      let (priv_key, pub_key, sign) = sign_ordinary_307(&msg, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF367 =>
    {
      let (priv_key, pub_key, sign) = sign_ordinary_367(&msg, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF431 =>
    {
      let (priv_key, pub_key, sign) = sign_ordinary_431(&msg, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
  })
}

pub fn sign_original(
  ec : CurveIndex,
  l_d : u64,
  msg : Vec<u8>,
  signing_key : Option<String>,
) -> crate::error::Result<'static, (String, String, String)>
{
  Ok(match ec
  {
    CurveIndex::EcGF163 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let (priv_key, pub_key, sign) = sign_digest_163(digest, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF167 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let (priv_key, pub_key, sign) = sign_digest_167(digest, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF173 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let (priv_key, pub_key, sign) = sign_digest_173(digest, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF179 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let (priv_key, pub_key, sign) = sign_digest_179(digest, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF191 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let (priv_key, pub_key, sign) = sign_digest_191(digest, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF233 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let (priv_key, pub_key, sign) = sign_digest_233(digest, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF257 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let (priv_key, pub_key, sign) = sign_digest_257(digest, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF307 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let (priv_key, pub_key, sign) = sign_digest_307(digest, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF367 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let (priv_key, pub_key, sign) = sign_digest_367(digest, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
    CurveIndex::EcGF431 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let (priv_key, pub_key, sign) = sign_digest_431(digest, l_d, signing_key)?;
      convert_response(priv_key, pub_key, sign)
    }
  })
}

pub fn verify_ordinary(
  verifying_key : String,
  sign : String,
  ec : CurveIndex,
  msg : Vec<u8>,
  l_d : u64,
) -> crate::error::Result<'static, ()>
{
  match ec
  {
    CurveIndex::EcGF163 =>
    {
      let ec = BinaryEC::generate_m163_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF163> {
        ec,
        q : GF163::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify(&msg, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying GF163 signature")
    }
    CurveIndex::EcGF167 =>
    {
      let ec = BinaryEC::generate_m167_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF167> {
        ec,
        q : GF167::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify(&msg, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying GF167 signature")
    }
    CurveIndex::EcGF173 =>
    {
      let ec = BinaryEC::generate_m173_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF173> {
        ec,
        q : GF173::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify(&msg, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying GF173 signature")
    }
    CurveIndex::EcGF179 =>
    {
      let ec = BinaryEC::generate_m179_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF179> {
        ec,
        q : GF179::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify(&msg, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying GF179 signature")
    }
    CurveIndex::EcGF191 =>
    {
      let ec = BinaryEC::generate_m191_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF191> {
        ec,
        q : GF191::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify(&msg, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying GF191 signature")
    }
    CurveIndex::EcGF233 =>
    {
      let ec = BinaryEC::generate_m233_pb_curve();
      println!("verifying key: {verifying_key}");
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF233> {
        ec,
        q : GF233::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify(&msg, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying GF233 signature")
    }
    CurveIndex::EcGF257 =>
    {
      let ec = BinaryEC::generate_m257_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF257> {
        ec,
        q : GF257::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify(&msg, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying GF257 signature")
    }
    CurveIndex::EcGF307 =>
    {
      let ec = BinaryEC::generate_m307_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF307> {
        ec,
        q : GF307::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify(&msg, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying GF307 signature")
    }
    CurveIndex::EcGF367 =>
    {
      let ec = BinaryEC::generate_m367_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF367> {
        ec,
        q : GF367::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify(&msg, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying GF367 signature")
    }
    CurveIndex::EcGF431 =>
    {
      let ec = BinaryEC::generate_m431_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF431> {
        ec,
        q : GF431::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify(&msg, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying GF431 signature")
    }
  }
  Ok(())
}

pub fn verify_original(
  verifying_key : String,
  sign : String,
  ec : CurveIndex,
  msg : Vec<u8>,
  l_d : u64,
) -> crate::error::Result<'static, ()>
{
  match ec
  {
    CurveIndex::EcGF163 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let ec = BinaryEC::generate_m163_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF163> {
        ec,
        q : GF163::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify_digest(digest, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying with digest GF163 signature")
    }
    CurveIndex::EcGF167 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let ec = BinaryEC::generate_m167_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF167> {
        ec,
        q : GF167::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify_digest(digest, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying with digest GF167 signature")
    }
    CurveIndex::EcGF173 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let ec = BinaryEC::generate_m173_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF173> {
        ec,
        q : GF173::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify_digest(digest, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying with digest GF173 signature")
    }
    CurveIndex::EcGF179 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let ec = BinaryEC::generate_m179_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF179> {
        ec,
        q : GF179::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify_digest(digest, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying with digest GF179 signature")
    }
    CurveIndex::EcGF191 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let ec = BinaryEC::generate_m191_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF191> {
        ec,
        q : GF191::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify_digest(digest, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying with digest GF191 signature")
    }
    CurveIndex::EcGF233 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let ec = BinaryEC::generate_m233_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF233> {
        ec,
        q : GF233::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify_digest(digest, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying with digest GF233 signature")
    }
    CurveIndex::EcGF257 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let ec = BinaryEC::generate_m257_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF257> {
        ec,
        q : GF257::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify_digest(digest, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying with digest GF257 signature")
    }
    CurveIndex::EcGF307 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let ec = BinaryEC::generate_m307_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF307> {
        ec,
        q : GF307::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify_digest(digest, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying with digest GF307 signature")
    }
    CurveIndex::EcGF367 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let ec = BinaryEC::generate_m367_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF367> {
        ec,
        q : GF367::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify_digest(digest, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying with digest GF367 signature")
    }
    CurveIndex::EcGF431 =>
    {
      let mut digest = Gost94UA::new();
      digest.update(msg);
      let ec = BinaryEC::generate_m431_pb_curve();
      let verifying_key = VerifyingKey::try_from(VerifyingKeyConstructor::<GF431> {
        ec,
        q : GF431::from_hex_be(verifying_key)?,
        l_d,
      })?;
      let signature = Signature::try_from(sign.as_str())?;
      let time_before = Instant::now();
      verifying_key.verify_digest(digest, &signature)?;
      trace!(time_spent =?{Instant::now().duration_since(time_before)},"Time spent on verifying with digest GF431 signature")
    }
  }
  Ok(())
}
