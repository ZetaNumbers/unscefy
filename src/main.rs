mod sce;

use std::{
    env, fs,
    io::{self, Read, Seek, Write},
    mem,
};

use color_eyre::eyre::{self, Context};
use object::{elf, endian, pod};

const ALL_ET_SCE: [u16; 7] = [
    sce::ET_SCE_EXEC,
    sce::ET_SCE_RELEXEC,
    sce::ET_SCE_STUBLIB,
    sce::ET_SCE_DYNAMIC,
    sce::ET_SCE_PSPRELEXEC,
    sce::ET_SCE_PPURELEXEC,
    sce::ET_SCE_UNK,
];

const _: () = assert!(mem::size_of::<isize>() >= 4);

/// target endian
type TE = object::LittleEndian;
#[allow(non_upper_case_globals)]
const TE: TE = object::LittleEndian;

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

    let mut pht = vec![zeroed::<elf::ProgramHeader32<TE>>(); eh.e_phnum.get(TE) as usize];
    if !pht.is_empty() {
        file.seek(io::SeekFrom::Start(eh.e_phoff.get(TE).into()))?;
        file.read_exact(pod::bytes_of_slice_mut(&mut pht))?;
    }

    let mut sht = vec![zeroed::<elf::SectionHeader32<TE>>(); eh.e_shnum.get(TE) as usize];
    if !sht.is_empty() {
        file.seek(io::SeekFrom::Start(eh.e_shoff.get(TE).into()))?;
        file.read_exact(pod::bytes_of_slice_mut(&mut sht))?;
    }
    assert!(sht.is_empty());
    assert!(pht.iter().all(|ph| [
        elf::PT_LOAD,
        sce::PT_SCE_RELA,
        sce::PT_SCE_COMMENT,
        sce::PT_SCE_VERSION
    ]
    .contains(&ph.p_type.get(TE))));

    // NULL section
    sht.push(zeroed());
    let mut shstr = ShStrTab::new();

    let [mut text, mut bss, mut data, mut rodata] = [0; 4];
    for ph in &pht {
        if ph.p_type.get(TE) != elf::PT_LOAD {
            continue;
        }

        let read = (ph.p_flags.get(TE) & elf::PF_R) != 0;
        let writ = (ph.p_flags.get(TE) & elf::PF_W) != 0;
        let exec = (ph.p_flags.get(TE) & elf::PF_X) != 0;
        let sh_flags =
            (writ as u32 * elf::SHF_WRITE) | (exec as u32 * elf::SHF_EXECINSTR) | elf::SHF_ALLOC;
        let sh_flags = endian::U32::new(TE, sh_flags);

        if exec {
            assert_eq!(ph.p_filesz, ph.p_memsz);

            let sh_name = if text == 0 {
                std::write!(shstr, ".text")
            } else {
                std::write!(shstr, ".text{text}")
            }
            .unwrap();
            text += 1;

            sht.push(elf::SectionHeader32 {
                sh_name: endian::U32::new(TE, sh_name),
                sh_type: endian::U32::new(TE, elf::SHT_PROGBITS),
                sh_flags,
                sh_addr: ph.p_vaddr,
                sh_offset: ph.p_offset,
                sh_size: ph.p_filesz,
                sh_addralign: ph.p_align,
                ..zeroed()
            })
        } else if writ {
            let (data_sz, bss_sz) = (
                ph.p_filesz.get(TE),
                ph.p_memsz
                    .get(TE)
                    .checked_sub(ph.p_filesz.get(TE))
                    .expect("sh_memsz < sh_filesz"),
            );
            if data_sz > 0 {
                let sh_name = if data == 0 {
                    std::write!(shstr, ".data")
                } else {
                    std::write!(shstr, ".data{data}")
                }
                .unwrap();
                data += 1;
                sht.push(elf::SectionHeader32 {
                    sh_name: endian::U32::new(TE, sh_name),
                    sh_type: endian::U32::new(TE, elf::SHT_PROGBITS),
                    sh_flags,
                    sh_addr: ph.p_vaddr,
                    sh_offset: ph.p_offset,
                    sh_size: ph.p_filesz,
                    sh_addralign: ph.p_align,
                    ..zeroed()
                });
            }
            if bss_sz > 0 {
                let sh_name = if bss == 0 {
                    std::write!(shstr, ".bss")
                } else {
                    std::write!(shstr, ".bss{bss}")
                }
                .unwrap();
                bss += 1;
                let sh_addralign = ph.p_align.get(TE);
                let sh_addralign = sh_addralign
                    .checked_shr(
                        sh_addralign
                            .trailing_zeros()
                            .saturating_sub(data_sz.trailing_zeros()),
                    )
                    .unwrap_or(0);
                sht.push(elf::SectionHeader32 {
                    sh_name: endian::U32::new(TE, sh_name),
                    sh_type: endian::U32::new(TE, elf::SHT_NOBITS),
                    sh_flags,
                    sh_addr: endian::U32::new(TE, ph.p_vaddr.get(TE) + data_sz),
                    sh_size: ph.p_memsz,
                    sh_addralign: endian::U32::new(TE, sh_addralign),
                    ..zeroed()
                });
            }
        } else if read {
            assert_eq!(ph.p_filesz, ph.p_memsz);

            let sh_name = if rodata == 0 {
                std::write!(shstr, ".rodata")
            } else {
                std::write!(shstr, ".rodata{rodata}")
            }
            .unwrap();
            rodata += 1;
            sht.push(elf::SectionHeader32 {
                sh_name: endian::U32::new(TE, sh_name),
                sh_type: endian::U32::new(TE, elf::SHT_PROGBITS),
                sh_flags,
                sh_addr: ph.p_vaddr,
                sh_offset: ph.p_offset,
                sh_size: ph.p_filesz,
                sh_addralign: ph.p_align,
                ..zeroed()
            })
        }
    }

    // Write section headers name table
    shstr.finalize(&mut file, &mut eh, &mut sht)?;

    // Write section headers
    eh.e_shoff
        .set(TE, file.seek(io::SeekFrom::End(0))?.try_into()?);
    file.write_all(pod::bytes_of_slice(&sht))?;
    eh.e_shentsize
        .set(TE, mem::size_of::<elf::SectionHeader32<TE>>().try_into()?);
    eh.e_shnum.set(TE, sht.len().try_into()?);

    // Override ELF header
    file.rewind()?;
    file.write_all(pod::bytes_of(&eh))?;

    Ok(())
}

fn load_header(file: &mut fs::File) -> eyre::Result<elf::FileHeader32<TE>> {
    let mut eh = zeroed::<elf::FileHeader32<TE>>();
    file.read_exact(pod::bytes_of_mut(&mut eh))?;

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
        eh.e_machine.get(TE) == elf::EM_ARM,
        "Wrong target arch: {}",
        eh.e_machine.get(TE),
    );
    if eh.e_shnum.get(TE) != 0 {
        eyre::ensure!(
            mem::size_of::<elf::SectionHeader32<TE>>() == eh.e_shentsize.get(TE).try_into()?,
            "Wrong section header entry size: {}",
            eh.e_shentsize.get(TE),
        );
    }
    if eh.e_phnum.get(TE) != 0 {
        eyre::ensure!(
            mem::size_of::<elf::ProgramHeader32<TE>>() == eh.e_phentsize.get(TE).try_into()?,
            "Wrong program header entry size: {}",
            eh.e_phentsize.get(TE),
        );
    }
    eyre::ensure!(
        ALL_ET_SCE.contains(&eh.e_type.get(TE)),
        "Wrong ELF type: {}",
        eh.e_type.get(TE)
    );

    Ok(eh)
}

struct ShStrTab {
    data: Vec<u8>,
}

impl ShStrTab {
    fn new() -> Self {
        ShStrTab { data: vec![b'\0'] }
    }

    fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) -> std::io::Result<u32> {
        let cur = self.size();
        self.data.write_fmt(format_args!("{args}\0"))?;
        Ok(cur)
    }

    fn size(&self) -> u32 {
        self.data
            .len()
            .try_into()
            .expect("'.shstrtab' section size exceeded 32 bit limit")
    }

    fn finalize(
        mut self,
        file: &mut fs::File,
        eh: &mut elf::FileHeader32<TE>,
        sht: &mut Vec<elf::SectionHeader32<TE>>,
    ) -> io::Result<()> {
        let sh_name = write!(self, ".shstrtab")?;
        let sh_offset = file
            .seek(io::SeekFrom::End(0))?
            .try_into()
            .expect("file size exceeded 32 bits");
        file.write_all(&self.data)?;
        eh.e_shstrndx.set(
            TE,
            sht.len()
                .try_into()
                .expect("exceeded 16 bit section header table limit"),
        );
        sht.push(elf::SectionHeader32 {
            sh_name: endian::U32::new(TE, sh_name),
            sh_type: endian::U32::new(TE, elf::SHT_STRTAB),
            sh_offset: endian::U32::new(TE, sh_offset),
            sh_size: endian::U32::new(TE, self.size()),
            sh_addralign: endian::U32::new(TE, 1),
            ..zeroed()
        });
        Ok(())
    }
}

fn zeroed<T>() -> T
where
    T: object::Pod,
{
    unsafe { mem::zeroed() }
}
