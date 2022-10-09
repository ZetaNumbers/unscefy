#![feature(cstr_from_bytes_until_nul)]

mod sce;
mod strtab;
mod symtab;

use std::{
    cell::RefCell,
    env,
    ffi::CStr,
    fs::{self, File},
    io::{self, Read, Seek, Write},
    mem,
};

use color_eyre::eyre::{self, Context};
use object::{elf, endian, pod};
use strtab::StrTab;

use crate::symtab::SymTab;

fn is_et_sce(e_type: u16) -> bool {
    matches!(
        e_type,
        sce::ET_SCE_EXEC
            | sce::ET_SCE_RELEXEC
            | sce::ET_SCE_STUBLIB
            | sce::ET_SCE_DYNAMIC
            | sce::ET_SCE_PSPRELEXEC
            | sce::ET_SCE_PPURELEXEC
            | sce::ET_SCE_UNK
    )
}

/// target endian
type TE = object::LittleEndian;

fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    let input = env::args()
        .nth(1)
        .expect("First argument should be input SCE ELF file");
    let output = env::args()
        .nth(2)
        .expect("Second argument should be output SCE ELF");
    fs::copy(input, &output).expect("Could not copy input file into the output file position");
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(output)
        .expect("Unable to open input file");
    assert_eq!(file.stream_position()?, 0);

    let mut eh = load_header(&mut file)
        .wrap_err("Error while loading ELF file header, perhaps input file is not an ELF")?;

    let pht = load_program_headers(&eh, &mut file)?;

    let mut sht = load_section_headers(&eh, &mut file)?;
    assert!(sht.is_empty());
    // NULL section
    sht.push(zeroed());

    let mut shstr = StrTab::new();
    sht.extend(sections_from_segments(&pht, &mut shstr));
    let (symtab, symproxy) = SymTab::new();
    add_section_symbols(&sht, &shstr, &symproxy);

    let mut file = RefCell::new(file);
    symproxy.close();
    futures::executor::block_on(symtab.store(&file, &mut sht, &mut shstr, Link::Static));
    shstr.store_shstrtab(&mut sht, &mut eh, file.get_mut());
    store_section_headers(&sht, &mut eh, file.get_mut())?;
    store_header(&eh, file.get_mut())?;

    Ok(())
}

fn add_section_symbols(
    sht: &[elf::SectionHeader32<TE>],
    shstrtab: &StrTab,
    symtab: &symtab::Proxy,
) {
    sht.iter()
        .enumerate()
        .filter(|(_i, sh)| sh.sh_type.getn() != elf::SHT_NULL)
        .for_each(|(i, sh)| {
            let name = sh.sh_name.getn().try_into().unwrap();
            let name = CStr::from_bytes_until_nul(&shstrtab.strings()[name..]).unwrap();
            let mut symbol = elf::Sym32 {
                st_size: sh.sh_size,
                st_other: elf::STV_DEFAULT,
                st_shndx: ede(i.try_into().unwrap()),
                ..zeroed()
            };
            symbol.set_st_info(elf::STB_LOCAL, elf::STT_SECTION);
            let _ = symtab.add_symbol(name.into(), symbol).unwrap();
        })
}

fn sections_from_segments(
    pht: &[elf::ProgramHeader32<TE>],
    shstr: &mut StrTab,
) -> Vec<elf::SectionHeader32<TE>> {
    let mut sht = Vec::new();

    let text = &mut ("text", 0);
    let bss = &mut ("bss", 0);
    let data = &mut ("data", 0);
    let rodata = &mut ("rodata", 0);
    let mut sh_name = |(name, count): &mut (&str, u32)| {
        let name = if *count == 0 {
            format!(".{name}\0")
        } else {
            format!(".{name}{count}\0")
        };
        let out = shstr.push_cstr(CStr::from_bytes_with_nul(name.as_ref()).unwrap());
        *count += 1;
        out
    };

    for ph in pht {
        if ph.p_type.getn() != elf::PT_LOAD {
            continue;
        }

        let read = (ph.p_flags.getn() & elf::PF_R) != 0;
        let writ = (ph.p_flags.getn() & elf::PF_W) != 0;
        let exec = (ph.p_flags.getn() & elf::PF_X) != 0;
        let sh_flags = (u32::from(writ) * elf::SHF_WRITE)
            | (u32::from(exec) * elf::SHF_EXECINSTR)
            | elf::SHF_ALLOC;
        let sh_flags = ede(sh_flags);

        if exec {
            assert_eq!(ph.p_filesz, ph.p_memsz);
            sht.push(elf::SectionHeader32 {
                sh_name: ede(sh_name(text)),
                sh_type: ede(elf::SHT_PROGBITS),
                sh_flags,
                sh_addr: ph.p_vaddr,
                sh_offset: ph.p_offset,
                sh_size: ph.p_filesz,
                sh_addralign: ph.p_align,
                ..zeroed()
            })
        } else if writ {
            let (data_sz, bss_sz) = (
                ph.p_filesz.getn(),
                ph.p_memsz
                    .getn()
                    .checked_sub(ph.p_filesz.getn())
                    .expect("sh_memsz < sh_filesz"),
            );
            if data_sz > 0 {
                sht.push(elf::SectionHeader32 {
                    sh_name: ede(sh_name(data)),
                    sh_type: ede(elf::SHT_PROGBITS),
                    sh_flags,
                    sh_addr: ph.p_vaddr,
                    sh_offset: ph.p_offset,
                    sh_size: ede(data_sz),
                    sh_addralign: ph.p_align,
                    ..zeroed()
                });
            }
            if bss_sz > 0 {
                let sh_addralign = ph.p_align.getn();
                let sh_addralign = sh_addralign
                    .checked_shr(
                        sh_addralign
                            .trailing_zeros()
                            .saturating_sub(data_sz.trailing_zeros()),
                    )
                    .unwrap_or(0);
                sht.push(elf::SectionHeader32 {
                    sh_name: ede(sh_name(bss)),
                    sh_type: ede(elf::SHT_NOBITS),
                    sh_flags,
                    sh_addr: ede(ph.p_vaddr.getn() + data_sz),
                    sh_size: ede(bss_sz),
                    sh_addralign: ede(sh_addralign),
                    ..zeroed()
                });
            }
        } else if read {
            assert_eq!(ph.p_filesz, ph.p_memsz);
            sht.push(elf::SectionHeader32 {
                sh_name: ede(sh_name(rodata)),
                sh_type: ede(elf::SHT_PROGBITS),
                sh_flags,
                sh_addr: ph.p_vaddr,
                sh_offset: ph.p_offset,
                sh_size: ph.p_filesz,
                sh_addralign: ph.p_align,
                ..zeroed()
            })
        }
    }

    sht
}

fn load_section_headers(
    eh: &elf::FileHeader32<TE>,
    file: &mut File,
) -> eyre::Result<Vec<elf::SectionHeader32<TE>>> {
    let mut sht = vec![zeroed::<elf::SectionHeader32<TE>>(); eh.e_shnum.getn().into()];
    if !sht.is_empty() {
        file.seek(io::SeekFrom::Start(eh.e_shoff.getn().into()))?;
        file.read_exact(pod::bytes_of_slice_mut(&mut sht))?;
    }
    Ok(sht)
}

fn store_section_headers(
    sht: &[elf::SectionHeader32<TE>],
    eh: &mut elf::FileHeader32<TE>,
    file: &mut File,
) -> eyre::Result<()> {
    eh.e_shoff = ede(append_file(file, pod::bytes_of_slice(sht))?.try_into()?);
    eh.e_shentsize = ede(mem::size_of::<elf::SectionHeader32<TE>>().try_into()?);
    eh.e_shnum = ede(sht.len().try_into()?);
    Ok(())
}

fn load_program_headers(
    eh: &elf::FileHeader32<TE>,
    file: &mut File,
) -> eyre::Result<Vec<elf::ProgramHeader32<TE>>> {
    let mut pht = vec![zeroed::<elf::ProgramHeader32<TE>>(); eh.e_phnum.getn().into()];
    if !pht.is_empty() {
        file.seek(io::SeekFrom::Start(eh.e_phoff.getn().into()))?;
        file.read_exact(pod::bytes_of_slice_mut(&mut pht))?;
    }
    assert!(pht.iter().all(|ph| matches!(
        ph.p_type.getn(),
        elf::PT_LOAD | sce::PT_SCE_RELA | sce::PT_SCE_COMMENT | sce::PT_SCE_VERSION
    )));
    Ok(pht)
}

fn load_header(file: &mut File) -> eyre::Result<elf::FileHeader32<TE>> {
    let mut eh = zeroed::<elf::FileHeader32<TE>>();
    file.read_exact(pod::bytes_of_mut(&mut eh))?;
    ensure_header(eh)?;
    Ok(eh)
}

fn store_header(eh: &elf::FileHeader32<TE>, file: &mut File) -> eyre::Result<()> {
    file.rewind()?;
    file.write_all(pod::bytes_of(eh))?;
    Ok(())
}

fn ensure_header(eh: elf::FileHeader32<TE>) -> eyre::Result<()> {
    eyre::ensure!(
        eh.e_ident.magic == elf::ELFMAG,
        "Wrong ELF magic: {:x?}",
        eh.e_ident.magic
    );
    eyre::ensure!(
        eh.e_ident.class == elf::ELFCLASS32,
        "Wrong target class: {}",
        eh.e_ident.class,
    );
    eyre::ensure!(
        eh.e_ident.data == elf::ELFDATA2LSB,
        "Wrong target endian: {}",
        eh.e_ident.data,
    );
    eyre::ensure!(
        eh.e_ident.version == 1,
        "Wrong ELF version: {:x?}",
        eh.e_ident.version
    );
    eyre::ensure!(
        eh.e_machine.getn() == elf::EM_ARM,
        "Wrong target arch: {}",
        eh.e_machine.getn(),
    );
    if eh.e_shnum.getn() != 0 {
        eyre::ensure!(
            mem::size_of::<elf::SectionHeader32<TE>>() == eh.e_shentsize.getn().try_into()?,
            "Wrong section header entry size: {}",
            eh.e_shentsize.getn(),
        );
    }
    if eh.e_phnum.getn() != 0 {
        eyre::ensure!(
            mem::size_of::<elf::ProgramHeader32<TE>>() == eh.e_phentsize.getn().try_into()?,
            "Wrong program header entry size: {}",
            eh.e_phentsize.getn(),
        );
    }
    eyre::ensure!(
        is_et_sce(eh.e_type.getn()),
        "Wrong ELF type: {}",
        eh.e_type.getn()
    );

    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub enum Link {
    Dynamic,
    Static,
}

/// Encode in default endian
fn ede<T>(n: T::Native) -> T
where
    T: DefaultEndianAgnosticUtils,
{
    T::from_native(n)
}

trait DefaultEndianAgnosticUtils {
    type Native;

    fn getn(self) -> Self::Native;
    fn from_native(n: Self::Native) -> Self;
}

impl<E> DefaultEndianAgnosticUtils for endian::U32<E>
where
    E: endian::Endian + Default,
{
    type Native = u32;

    fn getn(self) -> Self::Native {
        self.get(Default::default())
    }

    fn from_native(n: Self::Native) -> Self {
        Self::new(Default::default(), n)
    }
}

impl<E> DefaultEndianAgnosticUtils for endian::U16<E>
where
    E: endian::Endian + Default,
{
    type Native = u16;

    fn getn(self) -> Self::Native {
        self.get(Default::default())
    }

    fn from_native(n: Self::Native) -> Self {
        Self::new(Default::default(), n)
    }
}

fn append_file(file: &mut File, data: &[u8]) -> io::Result<u64> {
    let cursor = file.seek(io::SeekFrom::End(0))?;
    file.write_all(data)?;
    Ok(cursor)
}

fn zeroed<T>() -> T
where
    T: object::Pod,
{
    unsafe { mem::zeroed() }
}
