use std::path::{Path, PathBuf};

use oracle::{
    encode_rasn, Encoding, InnerSeq, Message, MessageExtGroupExtOct, MessageKind, Packet, Pdu, Pick,
    Small,
};
use rasn::prelude::*;

fn main() {
    let mut args = std::env::args().skip(1);
    let enc = Encoding::from_name(&args.next().expect("encoding")).expect("unknown encoding");
    let pdu = Pdu::from_name(&args.next().expect("pdu")).expect("unknown PDU");
    let root = PathBuf::from(args.next().unwrap_or_else(|| "in".into()));
    let dir = root.join(enc.name()).join(pdu.name());
    std::fs::create_dir_all(&dir).unwrap();

    match pdu {
        Pdu::Message => {
            for (name, value) in messages() {
                write(&dir, enc, name, &value);
            }
        }
        Pdu::Packet => {
            for (name, value) in packets() {
                write(&dir, enc, name, &value);
            }
        }
    }
}

fn write<T: rasn::Encode>(dir: &Path, enc: Encoding, name: &str, value: &T) {
    let bytes = encode_rasn(enc, value).unwrap_or_else(|error| panic!("{name}: {error}"));
    let path = dir.join(format!("{name}.{}", enc.extension()));
    std::fs::write(&path, bytes).unwrap();
    println!("{}", path.display());
}

fn messages() -> Vec<(&'static str, Message)> {
    // Everything absent and at its lower bound: DER contains no DEFAULT.
    let minimal = Message::new(
        0,
        MessageKind::alpha,
        OctetString::from_slice(&[]),
        None,
        Vec::new(),
        None,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
        None,
    );

    // Every component present, both size bounds and an extension addition.
    let stamp: GeneralizedTime = "2024-01-01T00:00:00+00:00".parse().unwrap();
    let flags: BitString = [true, false, true, false].into_iter().collect();
    let rich = Message::new(
        1023,
        MessageKind::omega,
        OctetString::from(vec![0xab; 64]),
        Some("hello".to_string()),
        vec![Integer::from(1), Integer::from(-1)],
        Some(flags),
        Some(ObjectIdentifier::new(vec![1, 2, 840, 113549]).unwrap()),
        Some(stamp),
        Some(InnerSeq::new(
            Some(Integer::from(7)),
            Some(OctetString::from_slice(&[1, 2])),
        )),
        Some(Pick::text("pick".to_string())),
        false,
        Some(3),
        Some(true),
        Some(MessageExtGroupExtOct::new(Some(OctetString::from_slice(&[9])))),
    );

    // Same shape without the string: exercises the extension group over UPER,
    // where asn1c cannot decode rasn's R3 string length determinant.
    let mut no_label = rich.clone();
    no_label.label = None;

    vec![("minimal", minimal), ("rich", rich), ("no_label", no_label)]
}

fn packets() -> Vec<(&'static str, Packet)> {
    let message = messages().remove(2).1;
    vec![
        ("msg", Packet::msg(message)),
        (
            "small",
            Packet::small(Small::new(
                Some(Integer::from(-5)),
                Some(OctetString::from_slice(b"x")),
            )),
        ),
        (
            "ext_oid",
            Packet::extOid(ObjectIdentifier::new(vec![1, 3, 6, 1, 4, 1]).unwrap()),
        ),
    ]
}
