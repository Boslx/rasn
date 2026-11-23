use rasn::prelude::*;

#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
struct Group {
    #[rasn(tag(context, 0))]
    ext: Option<OctetString>,
}

#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq)]
struct Value {
    id: Integer,
    #[rasn(extension_addition_group)]
    group: Option<Group>,
}

fn value() -> Value {
    Value {
        id: Integer::from(1u32),
        group: Some(Group {
            ext: Some(OctetString::from_slice(&[9])),
        }),
    }
}

#[test]
fn extension_addition_group_has_no_wrapper() {
    // X.680 §24.5: `[[ ... ]]` is only a grouping of extension additions and
    // adds no element to an encoding. The member follows `id` directly.
    assert_eq!(
        rasn::der::encode(&value()).unwrap(),
        [0x30, 0x06, 0x02, 0x01, 0x01, 0x80, 0x01, 0x09]
    );
}

#[test]
fn extension_addition_group_decodes_without_wrapper() {
    let encoded = [0x30, 0x06, 0x02, 0x01, 0x01, 0x80, 0x01, 0x09];
    assert_eq!(rasn::der::decode::<Value>(&encoded).unwrap(), value());
}
