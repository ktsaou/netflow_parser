use netflow_parser::NetflowParser;

#[test]
fn template_id_255_is_rejected() {
    let mut message = Vec::new();
    message.extend_from_slice(&10u16.to_be_bytes());
    message.extend_from_slice(&28u16.to_be_bytes());
    message.extend_from_slice(&1u32.to_be_bytes());
    message.extend_from_slice(&2u32.to_be_bytes());
    message.extend_from_slice(&3u32.to_be_bytes());
    message.extend_from_slice(&2u16.to_be_bytes());
    message.extend_from_slice(&12u16.to_be_bytes());
    message.extend_from_slice(&255u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&4u16.to_be_bytes());

    assert!(NetflowParser::default().parse_bytes(&message).is_err());
}
