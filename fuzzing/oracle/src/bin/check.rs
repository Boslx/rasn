use std::{path::PathBuf, process::exit};

use oracle::{asn1c_transcode, rasn_transcode, verdict, Encoding, Mode, Pdu, Verdict};

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mode = if args.first().map(String::as_str) == Some("encode") {
        args.remove(0);
        Mode::Encoder
    } else {
        Mode::Decoder
    };
    if args.len() != 3 {
        eprintln!("usage: check [encode] <enc> <Message|Packet> <file>");
        exit(2);
    }

    let enc = Encoding::from_name(&args[0]).expect("unknown encoding");
    let pdu = Pdu::from_name(&args[1]).expect("unknown PDU");
    let file = PathBuf::from(&args[2]);
    let input = std::fs::read(&file).expect("read input");
    let (enc_in, enc_out) = mode.directions(enc);

    let asn1c = asn1c_transcode(enc_in, enc_out, pdu, &input);
    let rasn = rasn_transcode(pdu, enc_in, enc_out, &input);
    println!("asn1c: {}", describe(&asn1c));
    println!("rasn:  {}", describe(&rasn));

    let result = verdict(asn1c.as_deref().ok(), rasn.as_deref().ok());
    println!("verdict: {result:?}");
    if let (Ok(asn1c), Ok(rasn)) = (&asn1c, &rasn) {
        println!("asn1c: {asn1c:02x?}");
        println!("rasn:  {rasn:02x?}");
    }
    exit(if result == Verdict::Differ { 1 } else { 0 });
}

fn describe(result: &Result<Vec<u8>, oracle::Error>) -> String {
    match result {
        Ok(bytes) => format!("ok, {} bytes", bytes.len()),
        Err(error) => error.to_string(),
    }
}
