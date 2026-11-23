use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let gen = out.join("asn1c");
    fs::create_dir_all(&gen).unwrap();

    // asn1c is a one-time external dependency (build it from dependencies/asn1c).
    let asn1c = env::var("ASN1C").unwrap_or_else(|_| "asn1c".into());
    let schema = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("schema/oracle.asn1");

    let status = Command::new(&asn1c)
        .args([
            "-fcompound-names",
            "-gen-APER",
            "-gen-JER",
            "-gen-OER",
            "-no-gen-example",
            "-pdu=all",
        ])
        .arg("-D")
        .arg(&gen)
        .arg(&schema)
        .status()
        .unwrap_or_else(|error| {
            panic!(
                "failed to run `{asn1c}` ({error}); \
                 build the vendored compiler or set ASN1C=/path/to/asn1c"
            )
        });
    assert!(status.success(), "asn1c failed");

    // The C side is the reference implementation, not the target: build it with
    // a plain compiler so its edges never guide AFL. `ORACLE_CC` overrides.
    let compiler = env::var("ORACLE_CC").unwrap_or_else(|_| "cc".into());
    let mut build = cc::Build::new();
    build
        .compiler(&compiler)
        .include(&gen)
        .include("src")
        .warnings(false);
    for entry in fs::read_dir(&gen).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "c") {
            build.file(path);
        }
    }
    build.file("src/bridge.c");
    build.compile("asn1c_oracle");

    println!("cargo:rerun-if-changed=schema/oracle.asn1");
    println!("cargo:rerun-if-changed=src/bridge.c");
    println!("cargo:rerun-if-env-changed=ASN1C");
    println!("cargo:rerun-if-env-changed=ORACLE_CC");
}
