//! Differential oracle: asn1c's generated C against rasn, from one schema.

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    path::Path,
    ptr, slice,
};

#[path = "../dependencies/oracle_fuzz.rs"]
mod generated;

pub use generated::oracle_fuzz::{
    InnerSeq, Message, MessageExtGroupExtOct, MessageKind, Packet, Pick, Small,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Encoding {
    Der = 0,
    Ber = 1,
    Uper = 2,
    Aper = 3,
    Oer = 4,
    Xer = 5,
    Jer = 6,
}

impl Encoding {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "der" => Self::Der,
            "ber" => Self::Ber,
            "uper" => Self::Uper,
            "aper" => Self::Aper,
            "oer" => Self::Oer,
            "xer" => Self::Xer,
            "jer" => Self::Jer,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Der => "der",
            Self::Ber => "ber",
            Self::Uper => "uper",
            Self::Aper => "aper",
            Self::Oer => "oer",
            Self::Xer => "xer",
            Self::Jer => "jer",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Xer => "xml",
            Self::Jer => "json",
            _ => "bin",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Pdu {
    Message = 0,
    Packet = 1,
}

impl Pdu {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "message" => Self::Message,
            "packet" => Self::Packet,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Message => "Message",
            Self::Packet => "Packet",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Decoder,
    Encoder,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Decoder => "decoder",
            Self::Encoder => "encoder",
        }
    }

    /// The `(enc_in, enc_out)` pair this campaign runs.
    pub fn directions(self, enc: Encoding) -> (Encoding, Encoding) {
        match self {
            Self::Decoder => (enc, Encoding::Der),
            Self::Encoder => (Encoding::Der, enc),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Decode,
    Encode,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "unsupported encoding",
            Self::Decode => "decode failed",
            Self::Encode => "encode failed",
        })
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    BothRejected,
    OneSided,
    Agree,
    Differ,
}

/// The whole acceptance rule: only differences between two accepted values count.
pub fn verdict(asn1c: Option<&[u8]>, rasn: Option<&[u8]>) -> Verdict {
    match (asn1c, rasn) {
        (None, None) => Verdict::BothRejected,
        (Some(_), None) | (None, Some(_)) => Verdict::OneSided,
        (Some(asn1c), Some(rasn)) if asn1c == rasn => Verdict::Agree,
        (Some(_), Some(_)) => Verdict::Differ,
    }
}

extern "C" {
    fn oracle_convert(
        enc_in: i32,
        enc_out: i32,
        pdu: i32,
        input: *const u8,
        input_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32;
    fn oracle_free(p: *mut u8);
}

pub fn asn1c_transcode(
    enc_in: Encoding,
    enc_out: Encoding,
    pdu: Pdu,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut out: *mut u8 = ptr::null_mut();
    let mut out_len = 0usize;
    // SAFETY: C returns an owned buffer of `out_len` bytes; we copy and free it.
    let rc = unsafe {
        oracle_convert(
            enc_in as i32,
            enc_out as i32,
            pdu as i32,
            input.as_ptr(),
            input.len(),
            &mut out,
            &mut out_len,
        )
    };
    match rc {
        0 if out.is_null() => Ok(Vec::new()),
        0 => {
            let bytes = unsafe { slice::from_raw_parts(out, out_len) }.to_vec();
            unsafe { oracle_free(out) };
            Ok(bytes)
        }
        2 => Err(Error::Decode),
        3 => Err(Error::Encode),
        _ => Err(Error::Unsupported),
    }
}

pub fn rasn_transcode(
    pdu: Pdu,
    enc_in: Encoding,
    enc_out: Encoding,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    match pdu {
        Pdu::Message => rasn_transcode_typed::<Message>(enc_in, enc_out, input),
        Pdu::Packet => rasn_transcode_typed::<Packet>(enc_in, enc_out, input),
    }
}

fn rasn_transcode_typed<T: rasn::Decode + rasn::Encode>(
    enc_in: Encoding,
    enc_out: Encoding,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    let value: T = match enc_in {
        Encoding::Der => rasn::der::decode_with_remainder(input)
            .map_err(|_| Error::Decode)?
            .0,
        Encoding::Ber => rasn::ber::decode_with_remainder(input)
            .map_err(|_| Error::Decode)?
            .0,
        Encoding::Uper => rasn::uper::decode_with_remainder(input)
            .map_err(|_| Error::Decode)?
            .0,
        Encoding::Aper => rasn::aper::decode_with_remainder(input)
            .map_err(|_| Error::Decode)?
            .0,
        Encoding::Oer => rasn::oer::decode_with_remainder(input)
            .map_err(|_| Error::Decode)?
            .0,
        Encoding::Xer => rasn::xer::decode(input).map_err(|_| Error::Decode)?,
        Encoding::Jer => rasn::jer::decode(
            std::str::from_utf8(input).map_err(|_| Error::Decode)?,
        )
        .map_err(|_| Error::Decode)?,
    };
    encode_rasn(enc_out, &value)
}

pub fn encode_rasn<T: rasn::Encode>(enc: Encoding, value: &T) -> Result<Vec<u8>, Error> {
    match enc {
        Encoding::Der => rasn::der::encode(value),
        Encoding::Ber => rasn::ber::encode(value),
        Encoding::Uper => rasn::uper::encode(value),
        Encoding::Aper => rasn::aper::encode(value),
        Encoding::Oer => rasn::oer::encode(value),
        Encoding::Xer => rasn::xer::encode(value),
        Encoding::Jer => rasn::jer::encode(value).map(String::into_bytes),
    }
    .map_err(|_| Error::Encode)
}

pub fn compare(
    mode: Mode,
    enc: Encoding,
    pdu: Pdu,
    input: &[u8],
    out_dir: &Path,
) -> Verdict {
    let (enc_in, enc_out) = mode.directions(enc);
    let asn1c = asn1c_transcode(enc_in, enc_out, pdu, input).ok();
    let rasn = rasn_transcode(pdu, enc_in, enc_out, input).ok();
    let result = verdict(asn1c.as_deref(), rasn.as_deref());

    if result == Verdict::Differ {
        write_finding(out_dir, mode, enc, pdu, input, asn1c.as_deref(), rasn.as_deref());
    }
    result
}

fn write_finding(
    out_dir: &Path,
    mode: Mode,
    enc: Encoding,
    pdu: Pdu,
    input: &[u8],
    asn1c: Option<&[u8]>,
    rasn: Option<&[u8]>,
) {
    let dir = out_dir.join(mode.name()).join(enc.name()).join(pdu.name());
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let name = format!("{:016x}", digest(input));
    let _ = std::fs::write(dir.join(format!("{name}.bin")), input);
    if let Some(bytes) = asn1c {
        let _ = std::fs::write(dir.join(format!("{name}.asn1c")), bytes);
    }
    if let Some(bytes) = rasn {
        let _ = std::fs::write(dir.join(format!("{name}.rasn")), bytes);
    }
}

fn digest(input: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_matrix() {
        let a = b"a".as_slice();
        let b = b"b".as_slice();
        assert_eq!(verdict(None, None), Verdict::BothRejected);
        assert_eq!(verdict(Some(a), None), Verdict::OneSided);
        assert_eq!(verdict(None, Some(a)), Verdict::OneSided);
        assert_eq!(verdict(Some(a), Some(a)), Verdict::Agree);
        assert_eq!(verdict(Some(a), Some(b)), Verdict::Differ);
    }

    /// X.693 §9.1.4: an empty value uses the XML empty-element tag, which the
    /// encoder emits. The decoder returns before consuming that EndElement, so
    /// the next component sees it and decoding fails.
    #[test]
    #[ignore = "rasn XER decoder leaks the EndElement of an empty OCTET STRING"]
    fn xer_empty_octet_string_round_trips() {
        use rasn::prelude::*;

        #[derive(AsnType, Encode, Decode, Debug, PartialEq)]
        struct T {
            s: OctetString,
            n: Integer,
        }

        let value = T {
            s: OctetString::from_static(&[]),
            n: Integer::from(1),
        };
        let xml = rasn::xer::encode(&value).unwrap();
        assert_eq!(rasn::xer::decode::<T>(&xml).unwrap(), value);
    }
}
