use std::{fs, io::Write, num::NonZeroU64};

use object::{Object, ObjectSection, ObjectSymbol};

fn main() {
    let elf = std::env::args()
        .nth(1)
        .expect("object file path expected as a first argument");
    let sym_name = std::env::args()
        .nth(2)
        .expect("symbol name expected as a first argument");
    let elf = fs::read(elf).expect("opening an object file");
    let elf = object::File::parse(&*elf).expect("parsing an object file");
    let symbol = elf
        .symbols()
        .find(|sym| sym.name().map_or(false, |name| name == sym_name))
        .expect("no symbol with specified name was found");
    let data_size = NonZeroU64::new(symbol.size()).expect("symbol has size == 0");
    let section = elf
        .section_by_index(
            symbol
                .section_index()
                .expect("could not get section index from the symbol"),
        )
        .expect("symbol has index to nonexistent section");
    let data = section
        .data_range(symbol.address(), data_size.get())
        .expect("getting symbol data from a section")
        .expect("symbol data is outside of its associated section data");

    std::io::stdout()
        .lock()
        .write_all(data)
        .expect("unable to write symbol data to stdout");
}
