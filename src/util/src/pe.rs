use nom::IResult;
use nom::bytes::complete::{tag};
use nom::number::complete::le_u32;

fn has_msdos_header(input:&[u8]) -> IResult<&[u8], u32> {
    const dos_begin : [u8; 60] = 
        [0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
         0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
         0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00];
    const dos_end : [u8; 64] =
        [0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd,
         0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
         0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72,
         0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
         0x74, 0x20, 0x62, 0x64, 0x20, 0x72, 0x75, 0x6e,
         0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
         0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a,
         0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let (input, _) = tag(&dos_begin[..])(input)?;
    let (input, lfa) = le_u32(input)?;
    let (input, _) = tag(&dos_end[..])(input)?;

    Ok((input, lfa))
}