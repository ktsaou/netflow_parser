use netflow_parser::variable_versions::ipfix::FlowSetBody;
use netflow_parser::{NetflowPacket, NetflowParser};

fn append_set(message: &mut Vec<u8>, id: u16, body: &[u8]) {
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&u16::try_from(body.len() + 4).unwrap().to_be_bytes());
    message.extend_from_slice(body);
}

#[test]
fn template_withdrawal_takes_effect_in_wire_order() {
    let mut message = Vec::new();
    message.extend_from_slice(&10u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&1u32.to_be_bytes());
    message.extend_from_slice(&2u32.to_be_bytes());
    message.extend_from_slice(&3u32.to_be_bytes());

    let mut records = Vec::new();
    records.extend_from_slice(&256u16.to_be_bytes());
    records.extend_from_slice(&1u16.to_be_bytes());
    records.extend_from_slice(&1u16.to_be_bytes());
    records.extend_from_slice(&4u16.to_be_bytes());
    records.extend_from_slice(&256u16.to_be_bytes());
    records.extend_from_slice(&0u16.to_be_bytes());
    append_set(&mut message, 2, &records);
    append_set(&mut message, 256, &42u32.to_be_bytes());
    let length = u16::try_from(message.len()).unwrap();
    message[2..4].copy_from_slice(&length.to_be_bytes());

    let result = NetflowParser::default().parse_bytes(&message);
    assert!(result.error.is_none(), "{:#?}", result.error);
    let NetflowPacket::IPFix(packet) = &result.packets[0] else {
        panic!("expected IPFIX packet");
    };
    assert!(matches!(packet.flowsets[1].body, FlowSetBody::NoTemplate(_)));
}
