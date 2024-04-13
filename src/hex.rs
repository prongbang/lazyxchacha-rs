pub fn decode(text: &str) -> Vec<u8> {
    let mut dst = vec![0; text.len() / 2];
    faster_hex::hex_decode(text.as_bytes(), &mut dst).unwrap_or(());
    dst
}

pub fn encode(byte: Vec<u8>) -> String {
    faster_hex::hex_string(byte.as_slice())
}