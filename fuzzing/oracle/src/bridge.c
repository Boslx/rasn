// Minimal C bridge over asn1c's generic encoder/decoder. Keep this as small as
// possible: one function that decodes one encoding and re-encodes another.

#include <stddef.h>
#include <stdlib.h>

#include <asn_application.h>

#include "Message.h"
#include "Packet.h"

/* Must match `Encoding` in src/lib.rs. */
enum oracle_encoding {
    ORACLE_DER = 0,
    ORACLE_BER = 1,
    ORACLE_UPER = 2,
    ORACLE_APER = 3,
    ORACLE_OER = 4,
    ORACLE_XER = 5,
    ORACLE_JER = 6,
};

static enum asn_transfer_syntax decode_syntax(int enc) {
    switch (enc) {
    case ORACLE_DER:
        return ATS_DER;
    case ORACLE_BER:
        return ATS_BER;
    case ORACLE_UPER:
        return ATS_UNALIGNED_BASIC_PER;
    case ORACLE_APER:
        return ATS_ALIGNED_BASIC_PER;
    case ORACLE_OER:
        return ATS_BASIC_OER;
    case ORACLE_XER:
        return ATS_BASIC_XER;
    case ORACLE_JER:
        return ATS_JER;
    default:
        return ATS_INVALID;
    }
}

static enum asn_transfer_syntax encode_syntax(int enc) {
    switch (enc) {
    case ORACLE_DER:
        return ATS_DER;
    case ORACLE_BER:
        /* asn1c's BER output is DER-shaped; the oracle compares canonical bytes. */
        return ATS_DER;
    case ORACLE_UPER:
        return ATS_UNALIGNED_CANONICAL_PER;
    case ORACLE_APER:
        return ATS_ALIGNED_CANONICAL_PER;
    case ORACLE_OER:
        return ATS_CANONICAL_OER;
    case ORACLE_XER:
        return ATS_CANONICAL_XER;
    case ORACLE_JER:
        return ATS_JER_MINIFIED;
    default:
        return ATS_INVALID;
    }
}

/* Returns 0 on success, 1 unsupported encoding/PDU, 2 decode failure,
 * 3 encode failure. On success `*out` is malloc'd and freed by oracle_free. */
int oracle_convert(int enc_in, int enc_out, int pdu,
                   const unsigned char *in, size_t in_len,
                   unsigned char **out, size_t *out_len) {
    enum asn_transfer_syntax decode = decode_syntax(enc_in);
    enum asn_transfer_syntax encode = encode_syntax(enc_out);
    const asn_TYPE_descriptor_t *td = NULL;

    if (pdu == 0)
        td = &asn_DEF_Message;
    else if (pdu == 1)
        td = &asn_DEF_Packet;

    if (td == NULL || decode == ATS_INVALID || encode == ATS_INVALID)
        return 1;

    void *value = NULL;
    asn_dec_rval_t decoded = asn_decode(NULL, decode, td, &value, in, in_len);
    if (decoded.code != RC_OK) {
        ASN_STRUCT_FREE(*td, value);
        return 2;
    }

    asn_encode_to_new_buffer_result_t encoded =
        asn_encode_to_new_buffer(NULL, encode, td, value);
    ASN_STRUCT_FREE(*td, value);
    if (encoded.buffer == NULL || encoded.result.encoded < 0)
        return 3;

    *out = encoded.buffer;
    *out_len = (size_t)encoded.result.encoded;
    return 0;
}

void oracle_free(unsigned char *p) {
    free(p);
}
