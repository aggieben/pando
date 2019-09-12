pub fn u16_from_slice_le(bytes:&[u8]) -> u16 {
    assert_eq!(bytes.len(), 2);

    (u16::from(bytes[1]) << 8) |
    (u16::from(bytes[0]))
}