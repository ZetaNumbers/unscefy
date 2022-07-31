#![feature(array_chunks, split_array)]

use std::{iter, ops::Range};

use goblin::{
    elf::{Elf, ProgramHeader},
    elf32::{
        header::EM_ARM,
        program_header::{pt_to_str, PF_R, PF_W, PF_X},
        reloc::r_to_str,
    },
};

const MACHINE: u16 = EM_ARM;

fn main() {
    let elf_binary = std::fs::read(
        std::env::args()
            .nth(1)
            .expect("No path argument is provided"),
    )
    .unwrap();

    let elf = Elf::parse(&elf_binary).unwrap();
    assert_eq!(elf.header.e_machine, MACHINE);

    let relocations = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_SCE_RELA)
        .flat_map(|ph| {
            let mut dwords = elf_binary[ph.p_offset.try_into().unwrap()..]
                [..ph.p_filesz.try_into().unwrap()]
                .array_chunks::<4>()
                .map(|b| u32::from_le_bytes(*b));
            iter::from_fn(move || SceRelocInfo::from_data(&mut dwords))
        })
        .collect();

    let program_headers: Vec<SceProgramHeaderInfo> =
        elf.program_headers.iter().map(|ph| ph.into()).collect();

    let text_ph = program_headers
        .iter()
        .filter(|ph| ph.exec)
        .max_by_key(|ph| ph.filesz)
        .unwrap();
    let text_offset = text_ph.offset.try_into().unwrap();

    let module_info: SceModuleInfo =
        whole_take_from_bytes(&mut &elf_binary[text_offset..][elf.entry.try_into().unwrap()..])
            .unwrap();

    let imports: Vec<SceLibImport> =
        whole_from_bytes_all(&elf_binary[text_offset..][module_info.stub_range()]).collect();

    let info = SceElfInfo {
        program_headers,
        relocations,
        module_info,
        imports,
    };

    println!("{}", serde_json::to_string_pretty(&info).unwrap());
}

#[derive(Debug, Clone, serde::Serialize)]
struct SceElfInfo {
    program_headers: Vec<SceProgramHeaderInfo>,
    relocations: Vec<SceRelocInfo>,
    module_info: SceModuleInfo,
    imports: Vec<SceLibImport>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "infover")]
enum SceModuleInfo {
    V6 {
        modattribute: u16,
        modversion: [u8; 2],
        modname: String,
        gp_value: u32,
        ent_top: u32,
        ent_btm: u32,
        stub_top: u32,
        stub_btm: u32,
        dbg_fingerprint: u32,
        tls_start: u32,
        tls_filesz: u32,
        tls_memsz: u32,
        start_entry: u32,
        stop_entry: u32,
        arm_exidx_top: u32,
        arm_exidx_btm: u32,
        arm_extab_top: u32,
        arm_extab_btm: u32,
    },
}

impl SceModuleInfo {
    fn stub_range(&self) -> Range<usize> {
        match *self {
            SceModuleInfo::V6 {
                stub_top, stub_btm, ..
            } => stub_top as _..stub_btm as _,
        }
    }
}

impl TakeFromBytes for SceModuleInfo {
    fn take_from_bytes(bytes: &mut &[u8]) -> Option<Self> {
        let modattribute = take_from_bytes(bytes)?;
        let modversion = take_from_bytes(bytes)?;
        let modname = String::from_utf8_lossy(&take_from_bytes::<[u8; 27]>(bytes)?).into_owned();
        assert_eq!(take_from_bytes::<u8>(bytes)?, 6);

        Some(SceModuleInfo::V6 {
            modattribute,
            modversion,
            modname,
            gp_value: take_from_bytes(bytes)?,
            ent_top: take_from_bytes(bytes)?,
            ent_btm: take_from_bytes(bytes)?,
            stub_top: take_from_bytes(bytes)?,
            stub_btm: take_from_bytes(bytes)?,
            dbg_fingerprint: take_from_bytes(bytes)?,
            tls_start: take_from_bytes(bytes)?,
            tls_filesz: take_from_bytes(bytes)?,
            tls_memsz: take_from_bytes(bytes)?,
            start_entry: take_from_bytes(bytes)?,
            stop_entry: take_from_bytes(bytes)?,
            arm_exidx_top: take_from_bytes(bytes)?,
            arm_exidx_btm: take_from_bytes(bytes)?,
            arm_extab_top: take_from_bytes(bytes)?,
            arm_extab_btm: take_from_bytes(bytes)?,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "size")]
enum SceLibImport {
    Sz52 {
        version: u16,
        attribute: u16,
        nfunc: u16,
        nvar: u16,
        ntls: u16,
        #[serde(skip)]
        reserved: [u8; 4],
        libname_nid: u32,
        libname_addr: u32,
        sce_sdk_version: u32,
        func_nid_table: u32,
        func_entry_table: u32,
        var_nid_table: u32,
        var_entry_table: u32,
        tls_nid_table: u32,
        tls_entry_table: u32,
    },
}

impl TakeFromBytes for SceLibImport {
    fn take_from_bytes(b: &mut &[u8]) -> Option<Self> {
        let size: u16 = take_from_bytes(b)?;
        assert_eq!(size, 52);

        Some(SceLibImport::Sz52 {
            version: take_from_bytes(b)?,
            attribute: take_from_bytes(b)?,
            nfunc: take_from_bytes(b)?,
            nvar: take_from_bytes(b)?,
            ntls: take_from_bytes(b)?,
            reserved: take_from_bytes(b)?,
            libname_nid: take_from_bytes(b)?,
            libname_addr: take_from_bytes(b)?,
            sce_sdk_version: take_from_bytes(b)?,
            func_nid_table: take_from_bytes(b)?,
            func_entry_table: take_from_bytes(b)?,
            var_nid_table: take_from_bytes(b)?,
            var_entry_table: take_from_bytes(b)?,
            tls_nid_table: take_from_bytes(b)?,
            tls_entry_table: take_from_bytes(b)?,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct SceProgramHeaderInfo {
    #[serde(rename = "type")]
    typ: &'static str,
    offset: u64,
    filesz: u64,
    read: bool,
    write: bool,
    exec: bool,
    vaddr: u64,
    paddr: u64,
    memsz: u64,
    align: u64,
}

impl From<&ProgramHeader> for SceProgramHeaderInfo {
    fn from(ph: &ProgramHeader) -> Self {
        SceProgramHeaderInfo {
            typ: sce_pt_to_str(ph.p_type),
            read: ph.p_flags & PF_R != 0,
            write: ph.p_flags & PF_W != 0,
            exec: ph.p_flags & PF_X != 0,
            offset: ph.p_offset,
            filesz: ph.p_filesz,
            vaddr: ph.p_vaddr,
            paddr: ph.p_paddr,
            memsz: ph.p_memsz,
            align: ph.p_align,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "format")]
enum SceRelocInfo {
    Long {
        symbol_segment: u32,
        #[serde(rename = "type")]
        typ: &'static str,
        patch_segment: u32,
        type2: &'static str,
        dist2: u32,
        addend: u32,
        offset: u32,
    },
    Short {
        symbol_segment: u32,
        #[serde(rename = "type")]
        typ: &'static str,
        patch_segment: u32,
        offset: u32,
        offset_hi: u32,
        addend: u32,
    },
}

impl SceRelocInfo {
    fn from_data(dwords: &mut impl Iterator<Item = u32>) -> Option<SceRelocInfo> {
        let first = dwords.next()?;
        match first & 0xF {
            0 => {
                let dwords = [first, dwords.next().unwrap(), dwords.next().unwrap()];
                let typ = dwords[0] >> 8 & 0xFF;
                let type2 = dwords[0] >> 20 & 0xFF;
                Some(SceRelocInfo::Long {
                    symbol_segment: dwords[0] >> 4 & 0xF,
                    typ: r_to_str(typ, MACHINE),
                    patch_segment: dwords[0] >> 16 & 0xF,
                    type2: r_to_str(type2, MACHINE),
                    dist2: dwords[0] >> 28 & 0xF,
                    addend: dwords[1],
                    offset: dwords[2],
                })
            }
            1 => {
                let dwords = [first, dwords.next().unwrap()];
                let typ = dwords[0] >> 8 & 0xFF;
                Some(SceRelocInfo::Short {
                    symbol_segment: dwords[0] >> 4 & 0xF,
                    typ: r_to_str(typ, MACHINE),
                    patch_segment: dwords[0] >> 16 & 0xF,
                    offset: dwords[0] >> 20 & 0xFFF,
                    offset_hi: dwords[1] & 0x3FF,
                    addend: dwords[1] >> 12 & 0x3FFFFF,
                })
            }
            other => panic!("unknown SCE reloc format: {other}"),
        }
    }
}

const PT_SCE_RELA: u32 = 0x60000000;
const PT_SCE_COMMENT: u32 = 0x6FFFFF00;
const PT_SCE_VERSION: u32 = 0x6FFFFF01;

fn sce_pt_to_str(pt: u32) -> &'static str {
    match pt {
        PT_SCE_RELA => "PT_SCE_RELA",
        PT_SCE_COMMENT => "PT_SCE_COMMENT",
        PT_SCE_VERSION => "PT_SCE_VERSION",
        other => pt_to_str(other),
    }
}

fn take_from_bytes<T: TakeFromBytes>(bytes: &mut &[u8]) -> Option<T> {
    T::take_from_bytes(bytes)
}

fn whole_take_from_bytes<T: TakeFromBytes>(bytes: &mut &[u8]) -> Option<T> {
    if bytes.is_empty() {
        return None;
    }
    Some(T::take_from_bytes(bytes).unwrap())
}

fn whole_from_bytes_all<'a, T: TakeFromBytes>(mut bytes: &'a [u8]) -> impl Iterator<Item = T> + 'a {
    iter::from_fn(move || whole_take_from_bytes(&mut bytes))
}

trait TakeFromBytes: Sized {
    fn take_from_bytes(bytes: &mut &[u8]) -> Option<Self>;
}

impl TakeFromBytes for u32 {
    fn take_from_bytes(bytes: &mut &[u8]) -> Option<Self> {
        Some(u32::from_le_bytes(*take_bytes(bytes)?))
    }
}

impl TakeFromBytes for u16 {
    fn take_from_bytes(bytes: &mut &[u8]) -> Option<Self> {
        Some(u16::from_le_bytes(*take_bytes(bytes)?))
    }
}

impl TakeFromBytes for u8 {
    fn take_from_bytes(bytes: &mut &[u8]) -> Option<Self> {
        Some(u8::from_le_bytes(*take_bytes(bytes)?))
    }
}

impl<const N: usize> TakeFromBytes for [u8; N] {
    fn take_from_bytes(bytes: &mut &[u8]) -> Option<Self> {
        take_bytes(bytes).copied()
    }
}

fn take_bytes<'a, const N: usize>(bytes: &mut &'a [u8]) -> Option<&'a [u8; N]> {
    if bytes.len() < N {
        assert_eq!(bytes.len(), 0);
        return None;
    }

    let out;
    (out, *bytes) = bytes.split_array_ref();
    Some(out)
}
