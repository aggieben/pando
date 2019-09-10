use std::convert::TryInto;
use std::fs;

#[derive(Debug)]
pub enum Error {
    IoErr(std::io::Error),
    HeaderFormat(String)
}

pub struct Image {
    header:Header
}
impl Image {
    pub fn from(bytes: &[u8]) -> Result<Image, Error> {
        validate_dos_header(bytes).expect("header validation failed");
        let lfanew = get_lfanew(bytes);
        validate_pe_signature(bytes, lfanew).expect("header validation failed");
        
    }

    pub fn from_file(path: &str) -> Result<Image, Error> {
        match fs::read(path) {
            Ok(v) => match Image::from(v.as_slice()) {
                Ok(img) => Ok(img),
                err => err
            },
            Err(ioe) => return Err(Error::IoErr(ioe))
        }
    }
}

pub struct Header {
    file_header : FileHeader
}

pub struct FileHeader {
    num_sections : u16,
    timestamp : u32, // epoch, seconds
    opt_hdr_sz : u16,
    flags : FileHeaderFlags
}
impl FileHeader {
    fn from(bytes: &[u8], lfanew:usize) -> Result<FileHeader, Error> {
        let hdr_bytes = &bytes[lfanew+4..lfanew+24];

        if hdr_bytes[0..2] != [0x4c, 0x01] {
            return Err(Error::HeaderFormat("invalid PE file header; expecting 0x014c".to_string()));
        }

        let num_section_bytes = &hdr_bytes[2..4];
        let timestamp_bytes = &hdr_bytes[4..8];
        let opt_size_bytes = &hdr_bytes[16..18];
        let flags_bytes = &hdr_bytes[18..20];

        Ok(FileHeader {
            num_sections: 
        })
    }
}

bitflags! {
    struct FileHeaderFlags : u16 {
        const IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
        const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
        const IMAGE_FILE_32BIT_MACHINE = 0x0100;
        const IMAGE_FILE_DLL = 0x2000;
        // implementation-specific flags (pivate?)
        // 0x0010, 0x0020, 0x0400, 0x0800
    }
}

pub struct OptionalHeader {

}

pub struct SectionHeader {

}

fn validate_dos_header(bytes:&[u8]) -> Result<(), Error> {
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

    if bytes[0..59] == dos_begin[..] && bytes[63..127] == dos_end[..] {
        Ok(())
    } else {
        Err(Error::HeaderFormat("incorrect MS-DOS header".to_string()))
    }
}

fn get_lfanew(bytes:&[u8]) -> usize {
    ((u32::from(bytes[63]) << 24) |
    (u32::from(bytes[62]) << 16) |
    (u32::from(bytes[61]) << 8) |
    u32::from(bytes[60])).try_into().unwrap()
}

fn validate_pe_signature(bytes:&[u8], lfanew:usize) -> Result<(), Error> {
    const pe_sig : &[u8] = &[0x50u8, 0x45u8, 0x00u8, 0x00u8]; // "PE\0\0"
    let sig_bytes = &bytes[lfanew..lfanew+4];

    if pe_sig == sig_bytes {
        Ok(())
    } else {
        Err(Error::HeaderFormat("invalid PE signature".to_string()))
    }
}