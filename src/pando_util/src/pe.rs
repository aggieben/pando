use std::convert::TryFrom;
use std::option::{Option};
use log::*;
use nom::{
    bytes::complete::{tag, take},
    number::complete::*,
    IResult
};

// #region Types

#[derive(Debug)]
#[allow(dead_code)]
enum Error<E> {
    ParserError(nom::Err<E>),
    SpecError(String),
    Unexpected
}

impl<E> From<nom::Err<E>> for Error<E> {
    fn from(nom_err:nom::Err<E>) -> Self {
        Error::ParserError(nom_err)
    }
}

type PResult<I, O, E=(I,nom::error::ErrorKind)> = Result<(I,O), Error<E>>;

#[derive(Debug)]
#[allow(dead_code)]
struct CoffFileHeader {
    machine : Machine,
    num_sections : u16,
    timestamp : u32,
    opt_header_size : u16,
    flags : Option<HeaderFlags>
}

#[repr(u16)]
#[allow(dead_code)]
#[derive(Debug)]
enum Machine {
    ImageFileMachineUnknown = 0,
    ImageFileMachineAm33 = 0x1d3,        // Matsushita AM33
    ImageFileMachineAmd64 = 0x8664,      // x64
    ImageFileMachineArm = 0x1c0,         // ARM little endian
    ImageFileMachineArm64 = 0xaa64,      // ARM64 little endian
    ImageFileMachineArmnt = 0x1c4,       // ARM Thumb-2 little endian
    ImageFileMachineEbc = 0xebc,         // EFI byte code
    ImageFileMachineI386 = 0x14c,        // Intel 386 or later processors and compatible processors
    ImageFileMachineIa64 = 0x200,        // Intel Itanium processor family
    ImageFileMachineM32r = 0x9041,       // Mitsubishi M32R little endian
    ImageFileMachineMips16 = 0x266,      // MIPS16
    ImageFileMachineMipsfpu = 0x366,     // MIPS with FPU
    ImageFileMachineMipsfpu16 = 0x466,   // MIPS16 with FPU
    ImageFileMachinePowerpc = 0x1f0,     // Power PC little endian
    ImageFileMachinePowerpcfp = 0x1f1,   // Power PC with floating point support
    ImageFileMachineR4000 = 0x166,       // MIPS little endian
    ImageFileMachineRiscv32 = 0x5032,    // RISC-V 32-bit address space
    ImageFileMachineRiscv64 = 0x5064,    // RISC-V 64-bit address space
    ImageFileMachineRiscv128 = 0x5128,   // RISC-V 128-bit address space
    ImageFileMachineSh3 = 0x1a2,         // Hitachi SH3
    ImageFileMachineSh3dsp = 0x1a3,      // Hitachi SH3 DSP
    ImageFileMachineSh4 = 0x1a6,         // Hitachi SH4
    ImageFileMachineSh5 = 0x1a8,         // Hitachi SH5
    ImageFileMachineThumb = 0x1c2,       // Thumb
    ImageFileMachineWcemipsv2 = 0x169    // MIPS little-endian WCE v2
}

impl TryFrom<u16> for Machine {
    type Error = ();

    fn try_from(val:u16) -> Result<Machine,Self::Error> {
        match val {
            v if v == Machine::ImageFileMachineUnknown as u16
                => Ok(Machine::ImageFileMachineUnknown),
            v if v == Machine::ImageFileMachineAm33 as u16
                => Ok(Machine::ImageFileMachineAm33),
            v if v == Machine::ImageFileMachineAmd64 as u16
                => Ok(Machine::ImageFileMachineAmd64),
            v if v == Machine::ImageFileMachineArm as u16
                => Ok(Machine::ImageFileMachineArm64),
            v if v == Machine::ImageFileMachineArmnt as u16
                => Ok(Machine::ImageFileMachineArmnt),
            v if v == Machine::ImageFileMachineEbc as u16
                => Ok(Machine::ImageFileMachineEbc),
            v if v == Machine::ImageFileMachineI386 as u16
                => Ok(Machine::ImageFileMachineI386),
            v if v == Machine::ImageFileMachineIa64 as u16
                => Ok(Machine::ImageFileMachineIa64),
            v if v == Machine::ImageFileMachineM32r as u16
                => Ok(Machine::ImageFileMachineM32r),
            v if v == Machine::ImageFileMachineMips16 as u16
                => Ok(Machine::ImageFileMachineMips16),
            v if v == Machine::ImageFileMachineMipsfpu as u16
                => Ok(Machine::ImageFileMachineMipsfpu),
            v if v == Machine::ImageFileMachineMipsfpu16 as u16
                => Ok(Machine::ImageFileMachineMipsfpu16),
            v if v == Machine::ImageFileMachinePowerpc as u16
                => Ok(Machine::ImageFileMachinePowerpc),
            v if v == Machine::ImageFileMachinePowerpcfp as u16
                => Ok(Machine::ImageFileMachinePowerpcfp),
            v if v == Machine::ImageFileMachineR4000 as u16
                => Ok(Machine::ImageFileMachineR4000),
            v if v == Machine::ImageFileMachineRiscv128 as u16
                => Ok(Machine::ImageFileMachineRiscv128),
            v if v == Machine::ImageFileMachineRiscv32 as u16
                => Ok(Machine::ImageFileMachineRiscv32),
            v if v == Machine::ImageFileMachineRiscv64 as u16
                => Ok(Machine::ImageFileMachineRiscv64),
            v if v == Machine::ImageFileMachineSh3 as u16
                => Ok(Machine::ImageFileMachineSh3),
            v if v == Machine::ImageFileMachineSh3dsp as u16
                => Ok(Machine::ImageFileMachineSh3dsp),
            v if v == Machine::ImageFileMachineSh4 as u16
                => Ok(Machine::ImageFileMachineSh4),
            v if v == Machine::ImageFileMachineSh5 as u16
                => Ok(Machine::ImageFileMachineSh5),
            v if v == Machine::ImageFileMachineThumb as u16
                => Ok(Machine::ImageFileMachineThumb),
            v if v == Machine::ImageFileMachineWcemipsv2 as u16
                => Ok(Machine::ImageFileMachineWcemipsv2),
            _ => {
                error!("Unidentified machine specified.");
                Err(())
            }
        }
    }
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

// #endregion

fn parse_dos_begin(input:&[u8]) -> PResult<&[u8], ()> {
    const DOS_BEGIN : [u8; 60] = 
        [0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
         0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
         0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00];
    let (input, _) = tag(&DOS_BEGIN[..])(input)?;
    Ok((input,()))
}

fn parse_lfa(input:&[u8]) -> PResult<&[u8], u32> {
    let (input, lfa) = le_u32(input)?;
    Ok((input, lfa))
}

fn parse_dos_end(input:&[u8]) -> PResult<&[u8], ()> {
    const DOS_END : [u8; 64] =
        [0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd,
         0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
         0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72,
         0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
         0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e,
         0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
         0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a,
         0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let (input, _) = tag(&DOS_END[..])(input)?;
    Ok((input, ()))
}

fn parse_msdos_header(input:&[u8]) -> PResult<&[u8], u32> {
    let (input, _) = parse_dos_begin(input)?;
    let (input, lfa) = parse_lfa(input)?;
    let (input, _) = parse_dos_end(input)?;

    Ok((input, lfa))
}

fn parse_machine(input:&[u8]) -> PResult<&[u8], Machine> {
    let (input, machine_bytes) = le_u16(input)?;

    match Machine::try_from(machine_bytes) {
        Ok(machine) => Ok((input, machine)),
        Err(_) => {
            let msg = format!("invalid machine type: {}", machine_bytes);
            warn!("invalid machine type: {}", machine_bytes);
            Err(Error::SpecError(msg))
        }
    }
}

fn parse_coff_file_header(input:&[u8]) -> PResult<&[u8], CoffFileHeader> {
    let (input, machine) = parse_machine(input)?;
    let (input, num_sections) = le_u16(input)?;
    let (input, timestamp) = le_u32(input)?;
    let (input, _) = take(8usize)(input)?;
    let (input, opt_hdr_sz) = le_u16(input)?;
    let (input, flags) = le_u16(input)?;

    trace!("parsed CoffFileHeader");

    Ok((input, CoffFileHeader {
        machine: machine,
        num_sections: num_sections,
        timestamp: timestamp,
        opt_header_size: opt_hdr_sz,
        flags: HeaderFlags::from_bits(flags)
    }))
}

fn parse_magic(input:&[u8]) -> PResult<&[u8], ()> {
    const PE_MAGIC : [u8; 2] = [0x0b, 0x01];
    let (input, _) = tag(&PE_MAGIC[..])(input)?;

    Ok((input, ()))
}

fn parse_linker_version(input:&[u8]) -> PResult<&[u8], ()> {
    const VERSION : [u8; 2] = [0x06, 0x00];
    let (input, _) = tag(&VERSION[..])(input)?;

    Ok((input, ()))
}

fn parse_standard_fields(input:&[u8]) -> PResult<&[u8], StandardFields> {
    let (input, _) = parse_magic(input)?;
    let (input, _) = parse_linker_version(input)?;
    let (input, code_size) = le_u32(input)?;
    let (input, data_size) = le_u32(input)?;
    let (input, udata_size) = le_u32(input)?;
    let (input, entry_point_addr) = le_u32(input)?;
    let (input, code_base) = le_u32(input)?;
    let (input, data_base) = le_u32(input)?;

    Ok((input, StandardFields {
        code_size : code_size,
        initialized_data_size : data_size,
        uninitialized_data_size : udata_size,
        entry_point_rva : entry_point_addr,
        code_base : code_base,
        data_base : data_base
    }))
}


#[cfg(test)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
mod tests {
    use std::sync::{Once, ONCE_INIT};
    use super::*;

    const JSON_NET_ASSEMBLY : &[u8] = include_bytes!("../data/Newtonsoft.Json.dll");
    const TEST1_ANY_CPU_DLL : &[u8] = include_bytes!("../data/test1_anycpu.dll");
    const TEST1_ANY_CPU_EXE : &[u8] = include_bytes!("../data/test1_anycpu.exe");
    const TEST1_x86_DLL : &[u8] = include_bytes!("../data/test1_x86.dll");
    const TEST1_x86_EXE : &[u8] = include_bytes!("../data/test1_x86.exe");
    const TEST1_x64_DLL : &[u8] = include_bytes!("../data/test1_x64.dll");
    const TEST1_x64_EXE : &[u8] = include_bytes!("../data/test1_x64.exe");

    const INIT : Once = Once::new();
    fn setup() {
        INIT.call_once(|| {
            let r = pretty_env_logger::try_init();
            debug!("logger enabled: {:?}", r);
        });
    }

    macro_rules! parse_msdos_header_ok {
        ($($name:ident: $value:expr,)*) => {
        paste::item! {
        $(
            #[test]
            fn [<msdos_header_ok__ $name>] () {
                setup();
                let assembly_bytes = &($value)[0..128];
                let f = "[<msdos_header_ok__ $name>]";

                let result = parse_msdos_header(assembly_bytes);
                match &result {
                    Ok((rem, lfa)) => 
                        debug!("[{}] Result: Ok, remaining input: {} bytes; lfa: {}", 
                                f, rem.len(), lfa),
                    Err(Error::ParserError(nom_err)) => 
                        debug!("[{}] Result: Nom Err: {:?}", f, nom_err),
                    Err(Error::SpecError(err_msg)) =>
                        debug!("[{}] {}", f, err_msg),
                    Err(e) => 
                        debug!("[{}] {:?}", f, e)
                }

                assert!(result.is_ok());

                let (remaining_input,_) = result.unwrap();
                assert_eq!(remaining_input.len(), 0);
            }
        )*
        }
        }
    }

    parse_msdos_header_ok!(
        newtonsoft: JSON_NET_ASSEMBLY,
        test1_anycpu_dll: TEST1_ANY_CPU_DLL,
        test1_x86_dll: TEST1_x86_DLL,
        test1_x64_dll: TEST1_x64_DLL,
        test1_anycpu_exe: TEST1_ANY_CPU_EXE,
        test1_x86_exe: TEST1_x86_EXE,
        test1_x64_exe: TEST1_x64_EXE,
    );

    macro_rules! parse_coff_file_header_ok {
        ($($name:ident: $value:expr,)*) => {
        paste::item! {$(
            #[test]
            fn [<parse_coff_file_header_ok__ $name>] () {
                setup();
                let section_bytes = &($value)[0x84..0x98];

                let result = parse_coff_file_header(section_bytes);
                match &result {
                    Ok((rem, header)) => 
                        debug!("Result: Ok, remaining input: {} bytes; FileHeader: {:?}", rem.len(), header),
                    Err(Error::ParserError(nom_err)) => 
                        debug!("Result: Nom Err: {:?}", nom_err),
                    Err(Error::SpecError(err_msg)) =>
                        debug!("{}", err_msg),
                    Err(e) => 
                        debug!("{:?}", e)
                }

                assert!(result.is_ok());

                let (remaining_input,header) = result.unwrap();
                assert_eq!(remaining_input.len(), 0);

                let dotnetAssFlags = HeaderFlags::IMAGE_FILE_LARGE_ADDRESS_AWARE|HeaderFlags::IMAGE_FILE_EXECUTABLE_IMAGE;
                if let Some(flags) = header.flags {
                    assert_eq!(flags & dotnetAssFlags, dotnetAssFlags);
                } else {
                    assert!(false);
                }
            }
        )*}}
    }

    parse_coff_file_header_ok!{
        newtonsoft: JSON_NET_ASSEMBLY,
        test1_anycpu_dll: TEST1_ANY_CPU_DLL,
    }

    #[test]
    fn parse_coff_file_header_ok__test1_anycpu_exe() {
        setup();
        let section_bytes = &(TEST1_ANY_CPU_EXE)[0xec..0xec+20];

        let result = parse_coff_file_header(section_bytes);
        match &result {
            Ok((rem, header)) => 
                debug!("Result: Ok, remaining input: {} bytes; FileHeader: {:?}", rem.len(), header),
            Err(Error::ParserError(nom_err)) => 
                debug!("Result: Nom Err: {:?}", nom_err),
            Err(Error::SpecError(err_msg)) =>
                debug!("{}", err_msg),
            Err(e) => 
                debug!("{:?}", e)
        }

        assert!(result.is_ok());

        let (remaining_input,header) = result.unwrap();
        assert_eq!(remaining_input.len(), 0);

        let dotnetAssFlags = HeaderFlags::IMAGE_FILE_LARGE_ADDRESS_AWARE|HeaderFlags::IMAGE_FILE_EXECUTABLE_IMAGE;
        if let Some(flags) = header.flags {
            assert_eq!(flags & dotnetAssFlags, dotnetAssFlags);
        } else {
            assert!(false);
        }
    }

//     fn parse_standard_fields_ok() {
//         setup();
//         let section_bytes = &JSON_NET_ASSEMBLY[0x98..0x98+28];

//         let result = parse_standard_fields(section_bytes);
//         match &result {
//             Ok((rem, standard_fields)) =>
//                 debug!("Result: Ok, remaining input: {} bytes; StandardFields: {:?}", rem.len(), standard_fields),
//             e => debug!("{:?}", e)
//         }

//         assert!(result.is_ok());

//         let (remaining_input, standard_fields) = result.unwrap();
//         assert_eq!(remaining_input.len(), 0);

// /*

// #[derive(Debug)]
// struct StandardFields {
//     code_size : u32,
//     initialized_data_size : u32,
//     uninitialized_data_size : u32,
//     entry_point_rva : u32,
//     code_base : u32,
//     data_base : u32
// }
// */

//         assert_eq!(standard_fields.code_size, )
//     }
}