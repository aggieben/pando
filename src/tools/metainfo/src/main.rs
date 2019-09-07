#[macro_use]
extern crate clap;

const APP_NAME: &'static str = env!("CARGO_PKG_NAME");
const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const AUTHOR: &'static str = env!("CARGO_PKG_AUTHORS");

fn main() {
    let matches = clap_app!(myapp =>
        (name: APP_NAME)
        (version: VERSION)
        (author: AUTHOR)
        (@arg hex: -x --hex "Prints more things in hex as well as words." )
        (@arg header: -H --header "Prints MetaData header information and sizes.")
        (@arg csv: -c --csv "Prints the header sizes in Comma Separated format.")
        (@arg unsat: -u --unsat "Prints unresolved externals.")
        (@arg ass: -a --assem "Prints only the Assembly information.")
        (@arg schema: -s --schema "Prints the MetaData schema information.")
        (@arg raw: -r --raw "Prints the raw MetaData tables.")
        (@arg heaps: -p --heaps "Prints the raw heaps (only if -raw).")
        (@arg names: -n --names "Prints string columns (only if -raw).")
        (@arg validate: -v --validate "Validate the consistency of the metadata.")
        (@arg nologo: -q --nologo "Do not display the logo and MVID.")
        (@arg objfile: -o --obj +takes_value "Prints the MetaData for the specified obj file in the given archive(.lib)" )
        (@arg input: +required "Filename or filename pattern.")
    ).get_matches();

    if let Some(input) = matches.value_of("input") {
        println!("input: {}", input);
    }
}
