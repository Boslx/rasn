# Minimal oracle fuzzer: asn1c vs rasn

Differential fuzzing of two ASN.1 implementations against one schema,
`schema/oracle.asn1`. The old implementation (`/fuzzer`, LibAFL + forkserver +
stdout channel + `ctarget/main.c`) is ~900 lines. This one is ~200, no C
harness, no build.rs.

## 1. The schema (source of truth)

`schema/oracle.asn1` in this folder. `oracle-codecs`' `build.rs` runs asn1c and
the (local) rasn compiler on this file, so both sides share one abstract syntax
and every difference the oracle reports is an implementation difference.

`Message` (14 components), two nested types (`InnerSeq`, `Pick`), and a second
PDU `Packet` (extensible CHOICE over `Message`, `Small`, `OID`). Every campaign
runs once per PDU, so one binary means two campaigns.

| schema construct | why it is there |
|---|---|
| `...` in `Message`, `Pick`, `Packet` | unknown extension additions must be skipped, not rejected (rasn R2) |
| `[[ extOct ... ]]` | the extension addition group adds no wrapper element/object (rasn R4 in XER/JER) |
| `defFlag BOOLEAN DEFAULT TRUE` | DER must omit defaults (X.690 §11.5); triggers the normalization in §5 |
| `id INTEGER (0..1023)`, `extInt (1..4)` | constrained whole numbers |
| `InnerSeq.a INTEGER` | unconstrained INTEGER |
| `payload OCTET STRING (SIZE(0..64))` + `label UTF8String (SIZE(0..64))` | same constraint, two encodings — the R3 comparison |
| `items SEQUENCE (SIZE(0..4)) OF INTEGER` | SEQUENCE OF and constrained repetition |
| `flags BIT STRING { n0(0), ... }` | named bit list, trailing-zero canonicalization |
| `oid OBJECT IDENTIFIER` | unbounded arcs (rasn R1) |
| `stamp GeneralizedTime` | time canonicalization |
| `Pick` = `num` / `text` / `inner` / `oid` | CHOICE index numbering across `...` (asn1c A1), explicit tag inside a CHOICE |
| `inner [0] EXPLICIT InnerSeq` | nested SEQUENCE behind an explicit tag |
| `Packet` = `[0] Message` / `[1] Small` / ext `OID` | a second, CHOICE-shaped PDU with two tagged alternatives |

Dropped from the wide schema, with what still covers it: `counter`
(unconstrained INTEGER → `InnerSeq.a`), the unnamed sized BIT STRING
(constrained length → `items`), `IA5String`, `PrintableString`,
`NumericString`, `VisibleString`, `BMPString` (→ `label`; charset-only
duplicates), `UTCTime` (→ `GeneralizedTime`), `NULL`, `InnerSeq.c` and
`InnerSeq.nested`, `Pick.bits` and `Pick.items`, `Packet.num` and `Packet.text`
(all duplicates of constructs already present).

Cost: no charset- or two-digit-year-specific divergence can be found any more.
Add those back only after the compact schema runs clean.

Do not extend it "to test more": every added construct widens the encoder
canonicalization surface, which is the noise the rules in §5 filter out.

## 2. The only primitive

```
transcode(impl, enc_in, enc_out, pdu, bytes) -> Option<Vec<u8>>
```

Decode `bytes` as `enc_in`, re-encode the value as `enc_out`. `None` = that
implementation rejected the input (decode *or* encode failed).

- **asn1c side**: `oracle_codecs::convert(enc_in, enc_out, pdu, bytes).ok()`
  — already exists, uses asn1c's generic `asn_decode`/`asn_encode`.
- **rasn side**: ~25-line `match` on the two encodings:

```rust
fn rasn_transcode<T: rasn::Decode + rasn::Encode>(
    enc_in: Encoding, enc_out: Encoding, bytes: &[u8],
) -> Option<Vec<u8>> {
    let value: T = match enc_in {
        Uper => rasn::uper::decode_with_remainder(bytes).ok()?.0,
        Aper => rasn::aper::decode_with_remainder(bytes).ok()?.0,
        // rasn 0.30 has no DER decoder; BER is the lenient superset.
        Ber | Der => rasn::ber::decode_with_remainder(bytes).ok()?.0,
        Oer => rasn::oer::decode_with_remainder(bytes).ok()?.0,
        Xer => rasn::xer::decode(bytes).ok()?,
        Jer => rasn::jer::decode(std::str::from_utf8(bytes).ok()?).ok()?,
        Cbor => return None, // no rasn 0.30 codec
    };
    match enc_out {
        Uper => rasn::uper::encode(&value).ok(),
        Aper => rasn::aper::encode(&value).ok(),
        Ber | Der => rasn::der::encode(&value).ok(),
        Oer => rasn::oer::encode(&value).ok(),
        Xer => rasn::xer::encode(&value).ok(),
        Jer => rasn::jer::encode(&value).ok().map(String::into_bytes),
        Cbor => None,
    }
}
```

## 3. Two campaigns, same primitive

| campaign | fuzzed input is | `enc_in` | `enc_out` | tests |
|---|---|---|---|---|
| **decoder oracle** | bytes in encoding E | `E` | `Der` | decoders of E |
| **encoder oracle** | bytes that must be DER | `Der` | `E` | encoders for E |

- Decoder oracle: both sides decode the fuzzed E-bytes and re-encode to **DER**.
  DER is canonical, so identical bytes ⇔ identical abstract value. Any byte
  difference is a decoder disagreement.
- Encoder oracle: both sides decode the same **DER** input, then encode it as
  another standard E; the two E-encodings must be byte-identical (asn1c's
  output syntaxes are canonical: `Ber/Der → DER`, `Uper/Aper → canonical`,
  `Oer/Xer → canonical`, `Jer`; rasn's are canonical too).
- E ∈ `{uper, aper, ber, der, oer, xer, jer}`. No CBOR: rasn 0.30 has no codec.
  `uper` and `der` are enough to exercise both directions.

The old implementation's `fuzz --enc X` = decoder oracle with `E = X`;
its one-sided buckets were the only asymmetric part, and they are dropped (see §4).

## 4. Acceptance rule (the whole spec)

```
(c, r) = (transcode(asn1c, ...), transcode(rasn, ...))

both None            -> ignore          (invalid input)
exactly one Some     -> ignore          (NOT a finding — "only both accept counts")
both Some, c == r    -> pass
both Some, c != r    -> FINDING
```

No `asn1c_only/`, no `rasn_only/`, no `rasn_panics/` files. One outcome enum:

```rust
enum Verdict { BothRejected, OneSided, Agree, Differ }
fn verdict(c: Option<&[u8]>, r: Option<&[u8]>) -> Verdict   // pure fn, unit-test it
```

Consequence to accept knowingly: a rasn bug that *rejects* something asn1c
accepts (e.g. R1, big OID arcs) can never be reported by this oracle. That is
by design; such bugs are covered by the seed-based `check` runs and by the
`#[ignore]`d tests in `rasn/tests/asn1c_interop.rs`.

## 5. Comparison details

**Decoder oracle, DER output:**

1. If raw `c == r`, pass.
2. Else normalize asn1c's DER through rasn (decode as BER, re-encode as DER) and
   compare again — filters the known asn1c quirk of emitting DEFAULT-valued
   fields (X.690 §11.5 says omit). Only report if still different:

```rust
fn normalize<T: rasn::Decode + rasn::Encode>(der: &[u8]) -> Option<Vec<u8>> {
    rasn::der::encode(&rasn::ber::decode_with_remainder::<T>(der).ok()?.0).ok()
}
```

**Encoder oracle, E output:** compare raw bytes, no normalization — a canonical
output that differs is exactly the bug class being hunted.

**Strictness note:** asn1c decodes `Der` with `ATS_DER` (strict), rasn with its
lenient BER decoder. Non-canonical input is therefore asn1c-rejected →
one-sided → ignored, which is correct here.

## 7. Harness (both binaries, ~25 lines each)

```rust
fn main() {
    let mut args = std::env::args().skip(1);
    let (enc, pdu) = (args.next().unwrap(), args.next().unwrap());
    let out = std::env::var("OUT").unwrap_or_else(|_| "findings".into());
    afl::fuzz!(|data: &[u8]| match pdu.as_str() {
        "Message" => run::<Message>(&enc, "decoder", &out, data),
        "Packet" => run::<Packet>(&enc, "decoder", &out, data),
        _ => panic!("unknown PDU"),
    });
}
```

`encode.rs` is the same with `("Der", enc)` instead of `(enc, "Der")`.
`compare()`:

```rust
pub fn compare<T: rasn::Decode + rasn::Encode>(
    mode: Mode, enc: Encoding, pdu: Pdu, input: &[u8],
    check_der: impl Fn(&[u8]) -> Option<Vec<u8>>,   // normalize(), for decoder mode
    out_dir: &Path,
) -> Verdict
```

Findings: `<out>/<mode>/<enc>/<pdu>/<sha1(mode,enc,pdu,input)>.bin`, plus
`.asn1c` / `.rasn` output files. One file per distinct input; AFL already
dedupes by coverage.

## 8. Build & run

```sh
# one-time: asn1c + libclang via `make deps` (oracle-codecs' build.rs needs both)
cargo install cargo-afl
cd rasn/fuzzing/oracle && cargo afl build --release   # ORACLE_SCHEMA from .cargo/config.toml

target/release/seed uper Message
cargo afl fuzz -i in/uper/Message -o /tmp/afl-dec-uper-msg \
  target/release/decode uper Message

target/release/seed der Message
cargo afl fuzz -i in/der/Message -o /tmp/afl-enc-uper-msg \
  target/release/encode uper Message
```

Build the C side (`bridge.c` + asn1c output) with a plain compiler, never an
AFL wrapper: only rasn's edges should guide mutation. asn1c is the reference
implementation, so its coverage is noise here (override with `ORACLE_CC`).

## 9. Self-checks before fuzzing

0. `seed der Message` then `check der Message in/der/Message/minimal.bin` →
   both accept, equal. Proves the two bindings agree on a value no fuzzer has
   touched yet.
1. `seed uper Message` then `check uper Message in/uper/Message/minimal.bin` →
   both accept, equal (no non-empty string, so R3 does not apply).
2. Encoder oracle on the rich seed with `E=uper` → **must differ**: known
   rasn R3 (size-constrained `UTF8String` length determinant; `rich` carries
   `label = "hello"`). If it agrees, the oracle is broken (e.g. comparing the
   wrong direction). The decoder oracle on `rich` with `E=uper` may diverge as
   well — that is R3 seen from the other side, not a harness bug.
3. `#[test] fn verdict_matrix()` over the five input combinations in §4.
4. One 60 s smoke campaign per campaign type; triage every finding with
   `check` and delete duplicates before reporting.

## 10. Not included (deliberately)

- LibAFL, forkserver, `StdOutObserver`, stdout wiring → replaced by in-process calls.
- `ctarget/main.c` → `oracle_codecs::convert` calls asn1c in-process.
- triage reports, `report.md`, cluster summaries.
- one-sided buckets and `rasn_panics/` (see §4).
- CBOR and CER (rasn 0.30 has no CBOR codec; asn1c rejects CER).
- oer/xer/jer campaigns: the code supports them, but `uper` + `der` exercise
  both directions until those go quiet.

## 11. Limits / risks

- In-process asn1c: a C segfault or a rasn panic kills the persistent AFL
  process; AFL records it as a crash and restarts. No `catch_unwind` — a crash
  *is* a finding.
- asn1c `convert` accepts trailing bytes (prefix decode); rasn
  `decode_with_remainder` does the same. Left/right trailing garbage is not
  compared. Upgrade: require `consumed == input.len()` on both sides.
- Both decoders accepting an input does not prove it valid in the abstract —
  only that both agree. That is the oracle's definition of "valid".
- The compact schema dropped charset and UTCTime variants on purpose (§1): a
  divergence only reachable through IA5String/BMPString/UTCTime will not be
  found.
- Encoder oracle needs a decoder on both sides first; a DER-decoder divergence
  shows up as an encoder divergence too. Re-run `decode der` on the same input
  to attribute before reporting.
