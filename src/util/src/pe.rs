use std::option::{Option};
use nom::{IResult};
use nom::bytes::complete::*;
use nom::number::complete::*;

#[derive(Debug)]
#[allow(dead_code)]
struct CoffFileHeader {
    machine : u16,
    num_sections : u16,
    timestamp : u32,
    opt_header_size : u16,
    flags : Option<HeaderFlags>
}

#[repr(u16)]
enum Machine {
    IMAGE_FILE_MACHINE_UNKNOWN = 0,
    IMAGE_FILE_MACHINE_AM33 = 0x1d3,        // Matsushita AM33
    IMAGE_FILE_MACHINE_AMD64 = 0x8664,      // x64
    IMAGE_FILE_MACHINE_ARM = 0x1c0,         // ARM little endian
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64,      // ARM64 little endian
    IMAGE_FILE_MACHINE_ARMNT = 0x1c4,       // ARM Thumb-2 little endian
    IMAGE_FILE_MACHINE_EBC = 0xebc,         // EFI byte code
    IMAGE_FILE_MACHINE_I386 = 0x14c,        // Intel 386 or later processors and compatible processors
    IMAGE_FILE_MACHINE_IA64 = 0x200,        // Intel Itanium processor family
    IMAGE_FILE_MACHINE_M32R = 0x9041,       // Mitsubishi M32R little endian
    IMAGE_FILE_MACHINE_MIPS16 = 0x266,      // MIPS16
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366,     // MIPS with FPU
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,   // MIPS16 with FPU
    IMAGE_FILE_MACHINE_POWERPC = 0x1f0,     // Power PC little endian
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,   // Power PC with floating point support
    IMAGE_FILE_MACHINE_R4000 = 0x166,       // MIPS little endian
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032,    // RISC-V 32-bit address space
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064,    // RISC-V 64-bit address space
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128,   // RISC-V 128-bit address space
    IMAGE_FILE_MACHINE_SH3 = 0x1a2,         // Hitachi SH3
    IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,      // Hitachi SH3 DSP
    IMAGE_FILE_MACHINE_SH4 = 0x1a6,         // Hitachi SH4
    IMAGE_FILE_MACHINE_SH5 = 0x1a8,         // Hitachi SH5
    IMAGE_FILE_MACHINE_THUMB = 0x1c2,       // Thumb
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169    // MIPS little-endian WCE v2
}

bitflags! {
    struct HeaderFlags : u16 {
        const IMAGE_FILE_RELOCS_STRIPPED            = 0x0001;
        const IMAGE_FILE_EXECUTABLE_IMAGE           = 0x0002;
        const IMAGE_FILE_LINE_NUMS_STRIPPED         = 0x0004;
        const IMAGE_FILE_LOCAL_SYMS_STRIPPED        = 0x0008;
        const IMAGE_FILE_AGGRESSIVE_WS_TRIM         = 0x0010;
        const IMAGE_FILE_LARGE_ADDRESS_AWARE        = 0x0020;
        const _RESERVED                             = 0x0040;
        const IMAGE_FILE_BYTES_REVERSED_LO          = 0x0080;
        const IMAGE_FILE_32BIT_MACHINE              = 0x0100;
        const IMAGE_FILE_DEBUG_STRIPPED             = 0x0200;
        const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP    = 0x0400;
        const IMAGE_FILE_NET_RUN_FROM_SWAP          = 0x0800;
        const IMAGE_FILE_SYSTEM                     = 0x1000;
        const IMAGE_FILE_DLL                        = 0x2000;
        const IMAGE_FILE_UP_SYSTEM_ONLY             = 0x4000;
        const IMAGE_FILE_BYTES_REVERSED_HI          = 0x8000;
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct OptionalHeader {
    standard_fields : StandardFields,
    windows_fields : WindowsFields,
    dataa_directories : DataDirectories
}

#[derive(Debug)]
struct StandardFields {
    code_size : u32,
    initialized_data_size : u32,
    uninitialized_data_size : u32,
    entry_point_rva : u32,
    code_base : u32,
    data_base : u32
}

#[derive(Debug)]
struct WindowsFields {
    image_base : u32,
    section_alignment : u32,
    file_alignment : u32,
    image_size : u32,
    header_size : u32
}

#[derive(Debug)]
struct DataDirectories {
    import_table : u64,
    relocation_table : u64,
    import_address_table : u64,
    cli_header : u64
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

fn parse_pe_file_header(input:&[u8]) -> IResult<&[u8], CoffFileHeader> {

    println!("starting to parse FileHeader");
    let (input, machine) = le_u16(input)?;
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

    Ok((input, CoffFileHeader {
        machine: machine,
        num_sections: num_sections,
        timestamp: timestamp,
        opt_header_size: opt_hdr_sz,
        flags: HeaderFlags::from_bits(flags)
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

        let (remaining_input,header) = result.unwrap();
        assert_eq!(remaining_input.len(), 0);

        assert_eq!(header.num_sections, 3);
        assert_eq!(header.timestamp, 0xb669c63c);
        assert_eq!(header.opt_header_size, 0x00e0);
        assert_eq!(header.flags, Some(
            HeaderFlags::IMAGE_FILE_DLL
            |HeaderFlags::IMAGE_FILE_LARGE_ADDRESS_AWARE
            |HeaderFlags::IMAGE_FILE_EXECUTABLE_IMAGE));
    }
}