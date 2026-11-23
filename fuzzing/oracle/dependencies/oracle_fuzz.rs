#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments,
)]
pub mod oracle_fuzz {
    extern crate alloc;
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct InnerSeq {
        pub a: Option<Integer>,
        pub b: Option<OctetString>,
    }
    impl InnerSeq {
        pub fn new(a: Option<Integer>, b: Option<OctetString>) -> Self {
            Self { a, b }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum MessageKind {
        alpha = 0,
        beta = 1,
        gamma = 2,
        delta = 3,
        #[rasn(extension_addition)]
        omega = 4,
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct MessageExtGroupExtOct {
        #[rasn(size("1..=8"), tag(context, 4), identifier = "extOct")]
        pub ext_oct: Option<OctetString>,
    }
    impl MessageExtGroupExtOct {
        pub fn new(ext_oct: Option<OctetString>) -> Self {
            Self { ext_oct }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub struct Message {
        #[rasn(value("0..=1023"))]
        pub id: u16,
        pub kind: MessageKind,
        #[rasn(size("0..=64"))]
        pub payload: OctetString,
        pub label: Option<Utf8String>,
        #[rasn(size("0..=4"))]
        pub items: SequenceOf<Integer>,
        pub flags: Option<BitString>,
        pub oid: Option<ObjectIdentifier>,
        pub stamp: Option<GeneralizedTime>,
        #[rasn(tag(explicit(context, 0)))]
        pub inner: Option<InnerSeq>,
        #[rasn(tag(explicit(context, 1)))]
        pub pick: Option<Pick>,
        #[rasn(default = "message_def_flag_default", identifier = "defFlag")]
        pub def_flag: bool,
        #[rasn(
            extension_addition,
            value("1..=4"),
            tag(context, 2),
            identifier = "extInt"
        )]
        pub ext_int: Option<u8>,
        #[rasn(extension_addition, tag(context, 3), identifier = "extBool")]
        pub ext_bool: Option<bool>,
        #[rasn(extension_addition_group, identifier = "SEQUENCE")]
        pub ext_group_ext_oct: Option<MessageExtGroupExtOct>,
    }
    impl Message {
        pub fn new(
            id: u16,
            kind: MessageKind,
            payload: OctetString,
            label: Option<Utf8String>,
            items: SequenceOf<Integer>,
            flags: Option<BitString>,
            oid: Option<ObjectIdentifier>,
            stamp: Option<GeneralizedTime>,
            inner: Option<InnerSeq>,
            pick: Option<Pick>,
            def_flag: bool,
            ext_int: Option<u8>,
            ext_bool: Option<bool>,
            ext_group_ext_oct: Option<MessageExtGroupExtOct>,
        ) -> Self {
            Self {
                id,
                kind,
                payload,
                label,
                items,
                flags,
                oid,
                stamp,
                inner,
                pick,
                def_flag,
                ext_int,
                ext_bool,
                ext_group_ext_oct,
            }
        }
    }
    fn message_def_flag_default() -> bool {
        true
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    #[non_exhaustive]
    pub enum Packet {
        #[rasn(tag(explicit(context, 0)))]
        msg(Message),
        #[rasn(tag(explicit(context, 1)))]
        small(Small),
        #[rasn(extension_addition)]
        extOid(ObjectIdentifier),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    #[non_exhaustive]
    pub enum Pick {
        num(Integer),
        text(Utf8String),
        #[rasn(tag(explicit(context, 0)))]
        inner(InnerSeq),
        #[rasn(extension_addition)]
        oid(ObjectIdentifier),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct Small {
        pub a: Option<Integer>,
        pub b: Option<OctetString>,
    }
    impl Small {
        pub fn new(a: Option<Integer>, b: Option<OctetString>) -> Self {
            Self { a, b }
        }
    }
}