use goblin::pe;

type EResult<E=Vec<String>> = Result<(), E>;

fn merge_error(e1 : EResult, e2 : EResult) -> EResult {
    match (e1,e2) {
        (Err(msglist1), Err(msglist2)) => 
            Err(msglist1.into_iter().chain(msglist2.into_iter()).collect()),
        (Err(msglist1), Ok(_)) => Err(msglist1),
        (Ok(_), Err(msglist2)) => Err(msglist2),
        (Ok(_), Ok(_)) => Ok(())
    }
}

macro_rules! fold_results {
    ( $($r:expr),* ) => {
        {
            let mut results = vec!(
                $(
                    $r,
                )*
            );

            results.into_iter().fold(Ok(()), merge_error)
        }
    };
}

// TODO: do I need a struct CliHeader for use with goblin::pe::utils::get_data?

pub struct NetAssembly<'a> {
    image : pe::PE<'a>
}

pub struct InvalidNetAssembly<'a> {
    image : pe::PE<'a>,
    validation_errors : Vec<String>
}

impl<'a> From<pe::PE<'a>> for NetAssembly<'a> {
    fn from(image: pe::PE<'a>) -> NetAssembly<'a> {
        match validate_image(&image) {
            Ok(_) => NetAssembly { image: image },
            Err(msglist) => panic!("Invalid assembly: {:?}", msglist)
        }
    }
}



fn validate_image(image: &pe::PE) -> EResult {

}

fn validate_file_header(img: &pe::PE) -> EResult {
    let header = &img.header.coff_header;
    validate_machine(header.machine)?;
    validate_symbol_ptr(header.pointer_to_symbol_table)?;
    validate_symbol_num(header.number_of_symbol_table)?;
    validate_file_characteristics(img);

    Ok(())
}

fn validate_machine(machine: u16) -> EResult {
    // according to ECMA335 §II.25.2.2, this value is supposed to be
    // 0x014c; howevever, I think I have observed other values here in practice.
    match machine {
        m if m == 0x14c => Ok(()),
        m => Err(vec!(format!("unexpected machine value: {}", m)))
    }
}

fn validate_symbol_ptr(ptr : u32) -> EResult {
    match ptr {
        p if p == 0 => Ok(()),
        p => Err(vec!(format!("unexpected pointer to symbol table: {}", p)))
    }
}

fn validate_symbol_num(num : u32) -> EResult {
    match num {
        n if n == 0 => Ok(()),
        n => Err(vec!(format!("unexpected number of symbols: {}", n)))
    }
}

fn validate_file_characteristics(img : &pe::PE) -> EResult {
    use pe::characteristic::*;

    let flags = img.header.coff_header.characteristics;

    fold_results! {
        validate_flag(flags, IMAGE_FILE_RELOCS_STRIPPED, 0u16),
        validate_flag(flags, IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_EXECUTABLE_IMAGE)
    }
}

fn validate_32bitonly_flag(img : &pe::PE) -> EResult {
    use pe::characteristic::*;

    let file_flags = img.header.coff_header.characteristics;
    let rt_flags = img.header.optional_header
        .map(|oh| {
            oh.data_directories.get_clr_runtime_header()
                .map(|clih| {
                    // TODO: it doesn't appear that goblin provides types for the CLI header
                });
        });

    match (flag_set())
}

/// Validates that the given flags have the expected value at the provided position
fn validate_flag(flags : u16, position : u16, expectation : u16) -> EResult {
    match flags & position ^ expectation {
        val if val == expectation => Ok(()),
        val => Err(vec!(format!("unexpected file characteristic: {:x}", val)))
    }
}

fn flag_set(flags : u16, position : u16) -> bool {
    match flags & position {
        f if f > 0 => true,
        _ => false
    }
}