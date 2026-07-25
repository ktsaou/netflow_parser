use std::net::SocketAddr;

use netflow_parser::AutoScopedParser;

fn template_message(domain: u32, template_id: u16) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&10u16.to_be_bytes());
    message.extend_from_slice(&28u16.to_be_bytes());
    message.extend_from_slice(&1u32.to_be_bytes());
    message.extend_from_slice(&2u32.to_be_bytes());
    message.extend_from_slice(&domain.to_be_bytes());
    message.extend_from_slice(&2u16.to_be_bytes());
    message.extend_from_slice(&12u16.to_be_bytes());
    message.extend_from_slice(&template_id.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&4u16.to_be_bytes());
    message
}

#[test]
fn chained_ipfix_messages_are_scoped_by_each_domain() {
    let mut batch = template_message(1, 256);
    batch.extend_from_slice(&template_message(2, 257));

    let source: SocketAddr = "192.0.2.1:2055".parse().unwrap();
    let mut parser = AutoScopedParser::new();
    let result = parser.parse_from_source(source, &batch);

    assert!(result.error.is_none(), "{:#?}", result.error);
    assert_eq!(result.packets.len(), 2);
    assert_eq!(parser.ipfix_source_count(), 2);
}
