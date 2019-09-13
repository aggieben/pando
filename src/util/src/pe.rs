use nom::{IResult};
use nom::bytes::complete::*;
use nom::number::complete::*;

#[derive(Debug)]
struct FileHeader {
    num_sections : u16,
    timestamp : u32,
    opt_header_sz : u16,
    flags : u16
}

fn validate_msdos_header(input:&[u8]) -> IResult<&[u8], u32> {
    const DOS_BEGIN : [u8; 60] = 
        [0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
         0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
         0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00];
    const DOS_END : [u8; 64] =
        [0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd,
         0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
         0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72,
         0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
         0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e,
         0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
         0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a,
         0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let (input, _) = tag(&DOS_BEGIN[..])(input)?;
    let (input, lfa) = le_u32(input)?;
    let (input, _) = tag(&DOS_END[..])(input)?;

    Ok((input, lfa))
}

fn parse_pe_file_header(input:&[u8]) -> IResult<&[u8], FileHeader> {
    const PE_MACHINE : [u8; 2] = [ 0x4c, 0x01 ];

    println!("starting to parse FileHeader");
    let (input, _) = tag(&PE_MACHINE)(input)?;
    println!("parsed machine");
    let (input, num_sections) = le_u16(input)?;
    println!("parsed num_sections");

    let (input, timestamp) = le_u32(input)?;
    println!("parsed timestamp");
    let (input, _) = take(8usize)(input)?;
    println!("skipped 8");
    let (input, opt_hdr_sz) = le_u16(input)?;
    println!("parsed opt_hdr_sz");
    let (input, flags) = le_u16(input)?;
    println!("parsed flags");

    Ok((input, FileHeader {
        num_sections: num_sections,
        timestamp: timestamp,
        opt_header_sz: opt_hdr_sz,
        flags: flags
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON_NET_ASSEMBLY : &[u8] = include_bytes!("../data/Newtonsoft.Json.dll");

    #[test]
    fn validate_msdos_header_ok() {
        let assembly_bytes = &JSON_NET_ASSEMBLY[0..128];

        let result = validate_msdos_header(assembly_bytes);
        match &result {
            Ok((rem, lfa)) => 
                println!("Result: Ok, remaining input: {} bytes; lfa: {}", rem.len(), lfa),
            Err(nom::Err::Error((_, kind))) => 
                println!("Result: Err, error: {:?}", kind),
            _ => 
                println!("Other error.")
        }

        assert!(result.is_ok());

        let (remaining_input,_) = result.unwrap();
        assert_eq!(remaining_input.len(), 0);
    }

    #[test]
    fn parse_pe_file_header_ok() {
        let section_bytes = &JSON_NET_ASSEMBLY[0x84..0x84 + 20];

        let result = parse_pe_file_header(section_bytes);
        match &result {
            Ok((rem, header)) => 
                println!("Result: Ok, remaining input: {} bytes; FileHeader: {:?}", rem.len(), header),
            Err(nom::Err::Error((_, kind))) => 
                println!("Result: Err, error: {:?}", kind),
            _ => 
                println!("Other error.")
        }

        assert!(result.is_ok());

        let (remaining_input,_) = result.unwrap();
        assert_eq!(remaining_input.len(), 0);
    }
}