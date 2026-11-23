use std::path::{Path, PathBuf};

use oracle::{compare, Encoding, Mode, Pdu};

fn main() {
    let mut args = std::env::args().skip(1);
    let enc = Encoding::from_name(&args.next().expect("encoding")).expect("unknown encoding");
    let pdu = Pdu::from_name(&args.next().expect("pdu")).expect("unknown PDU");
    let out = PathBuf::from(std::env::var("OUT").unwrap_or_else(|_| "findings".into()));
    run(Mode::Decoder, enc, pdu, &out);
}

fn run(mode: Mode, enc: Encoding, pdu: Pdu, out: &Path) {
    afl::fuzz!(|data: &[u8]| {
        compare(mode, enc, pdu, data, out);
    });
}
