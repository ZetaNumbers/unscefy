#![feature(array_chunks, split_array, int_roundings, strict_provenance)]

// mod vmem;
mod bits;
mod take_from_bytes;

use std::{ops::Range, ptr};

use bits::Bits;
use goblin::{
    elf::{Elf, ProgramHeader},
    elf32::{
        header::EM_ARM,
        program_header::{pt_to_str, PF_R, PF_W, PF_X, PT_LOAD},
        reloc::r_to_str,
    },
};

use take_from_bytes::{
    take_from_bytes, whole_from_bytes_all, whole_take_from_bytes, TakeFromBytes,
};

const MACHINE: u16 = EM_ARM;

fn main() {
    assert!(std::mem::size_of::<usize>() >= 4);

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
            whole_from_bytes_all(
                &elf_binary[ph.p_offset.try_into().unwrap()..][..ph.p_filesz.try_into().unwrap()],
            )
        })
        .collect();

    let mut program_headers: Vec<SceProgramHeaderInfo> =
        elf.program_headers.iter().map(|ph| ph.into()).collect();

    program_headers
        .iter_mut()
        .filter(|ph| ph.typ == PT_LOAD)
        .for_each(|ph| {
            ph.loaded = Some(
                region::alloc_at(
                    ptr::invalid::<u8>(ph.vaddr.try_into().unwrap()),
                    ph.memsz.try_into().unwrap(),
                    region::Protection::READ_WRITE,
                )
                .unwrap(),
            );
        });

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

#[derive(serde::Serialize)]
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
        assert_eq!(take_from_bytes::<u32>(bytes)?, 0);

        Some(SceModuleInfo::V6 {
            modattribute,
            modversion,
            modname,
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
    Sz36 {
        version: u16,
        attribute: u16,
        libname_nid: u32,
        libname_addr: u32,
        func_nid_table: u32,
        func_entry_table: u32,
        var_nid_table: u32,
        var_entry_table: u32,
    },
    Sz52 {
        version: u16,
        attribute: u16,
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
        match size {
            36 => {
                let version = take_from_bytes(b)?;
                let attribute = take_from_bytes(b)?;
                let nfunc: u16 = take_from_bytes(b)?;
                let nvar: u16 = take_from_bytes(b)?;
                let ntls: u16 = take_from_bytes(b)?;
                let libname_nid = take_from_bytes(b)?;
                let libname_addr = take_from_bytes(b)?;
                let func_nid_table = take_from_bytes(b)?;
                let func_entry_table = take_from_bytes(b)?;
                let var_nid_table = take_from_bytes(b)?;
                let var_entry_table = take_from_bytes(b)?;
                Some(SceLibImport::Sz36 {
                    version,
                    attribute,
                    libname_nid,
                    libname_addr,
                    func_nid_table,
                    func_entry_table,
                    var_nid_table,
                    var_entry_table,
                })
            }
            52 => {
                let version = take_from_bytes(b)?;
                let attribute = take_from_bytes(b)?;
                let nfunc: u16 = take_from_bytes(b)?;
                let nvar: u16 = take_from_bytes(b)?;
                let ntls: u16 = take_from_bytes(b)?;
                let _reserved: [u8; 4] = take_from_bytes(b)?;
                let libname_nid = take_from_bytes(b)?;
                let libname_addr = take_from_bytes(b)?;
                let sce_sdk_version = take_from_bytes(b)?;
                let func_nid_table = take_from_bytes(b)?;
                let func_entry_table = take_from_bytes(b)?;
                let var_nid_table = take_from_bytes(b)?;
                let var_entry_table = take_from_bytes(b)?;
                let tls_nid_table = take_from_bytes(b)?;
                let tls_entry_table = take_from_bytes(b)?;
                Some(SceLibImport::Sz52 {
                    version,
                    attribute,
                    libname_nid,
                    libname_addr,
                    sce_sdk_version,
                    func_nid_table,
                    func_entry_table,
                    var_nid_table,
                    var_entry_table,
                    tls_nid_table,
                    tls_entry_table,
                })
            }
            other => unimplemented!("SceLibImport::Sz{other}"),
        }
    }
}

#[derive(serde::Serialize)]
struct SceProgramHeaderInfo {
    #[serde(rename = "type", serialize_with = "sce_pt_serialize")]
    typ: u32,
    offset: u64,
    filesz: u64,
    read: bool,
    write: bool,
    exec: bool,
    vaddr: u64,
    paddr: u64,
    memsz: u64,
    align: u64,
    #[serde(skip)]
    loaded: Option<region::Allocation>,
}

fn sce_pt_serialize<S>(p_type: &u32, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    ser.serialize_str(sce_pt_to_str(*p_type))
}

impl From<&ProgramHeader> for SceProgramHeaderInfo {
    fn from(ph: &ProgramHeader) -> Self {
        SceProgramHeaderInfo {
            typ: ph.p_type,
            read: ph.p_flags & PF_R != 0,
            write: ph.p_flags & PF_W != 0,
            exec: ph.p_flags & PF_X != 0,
            offset: ph.p_offset,
            filesz: ph.p_filesz,
            vaddr: ph.p_vaddr,
            paddr: ph.p_paddr,
            memsz: ph.p_memsz,
            align: ph.p_align,
            loaded: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "format")]
enum SceRelocInfo {
    Fmt0 {
        symbol_segment: u32,
        #[serde(rename = "type", serialize_with = "sce_reloc_type_serialize")]
        typ: u32,
        patch_segment: u32,
        #[serde(serialize_with = "sce_reloc_type_serialize")]
        type2: u32,
        dist2: u32,
        addend: u32,
        offset: u32,
    },
    Fmt1 {
        symbol_segment: u32,
        #[serde(rename = "type", serialize_with = "sce_reloc_type_serialize")]
        typ: u32,
        patch_segment: u32,
        offset: u32,
        offset_hi: u32,
        addend: u32,
    },
    Fmt2 {
        symbol_segment: u32,
        #[serde(rename = "type", serialize_with = "sce_reloc_type_serialize")]
        typ: u32,
        offset: u32,
        addend: u32,
    },
    Fmt3 {
        symbol_segment: u32,
        ins_mode: u32,
        offset: u32,
        dist2: u32,
        addend: u32,
    },
    Fmt4 {
        offset: u32,
        dist2: u32,
    },
    Fmt5 {
        dist1: u32,
        dist2: u32,
        dist3: u32,
        dist4: u32,
    },
    Fmt6 {
        offset: u32,
    },
    Fmt7 {
        offsets: [u32; 4],
    },
    Fmt8 {
        offsets: [u32; 7],
    },
    Fmt9 {
        offsets: [u32; 14],
    },
}

fn sce_reloc_type_serialize<S>(p_type: &u32, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    ser.serialize_str(r_to_str(*p_type, MACHINE))
}

impl TakeFromBytes for SceRelocInfo {
    fn take_from_bytes(b: &mut &[u8]) -> Option<Self> {
        let mut b = Bits::take_from_bytes(b, false);
        let format = b.take(4)?;
        let res = Some(match format {
            0 => SceRelocInfo::Fmt0 {
                symbol_segment: b.take(4)?,
                typ: b.take(8)?,
                patch_segment: b.take(4)?,
                type2: b.take(8)?,
                dist2: b.take(4)?,
                addend: b.take(32)?,
                offset: b.take(32)?,
            },
            1 => SceRelocInfo::Fmt1 {
                symbol_segment: b.take(4)?,
                typ: b.take(8)?,
                patch_segment: b.take(4)?,
                offset: b.take(12)?,
                offset_hi: b.take(10)?,
                addend: b.take(22)?,
            },
            2 => SceRelocInfo::Fmt2 {
                symbol_segment: b.take(4)?,
                typ: b.take(8)?,
                offset: b.take(16)?,
                addend: b.take(32)?,
            },
            3 => {
                b.padding = true;
                SceRelocInfo::Fmt3 {
                    symbol_segment: b.take(4)?,
                    ins_mode: b.take(1)?,
                    offset: b.take(18)?,
                    dist2: b.take(5)?,
                    addend: b.take(22)?,
                }
            }
            4 => SceRelocInfo::Fmt4 {
                offset: b.take(23)?,
                dist2: b.take(5)?,
            },
            5 => SceRelocInfo::Fmt5 {
                dist1: b.take(9)?,
                dist2: b.take(5)?,
                dist3: b.take(9)?,
                dist4: b.take(5)?,
            },
            6 => SceRelocInfo::Fmt6 {
                offset: b.take(28)?,
            },
            7 => SceRelocInfo::Fmt7 {
                offsets: b.take_array(7)?,
            },
            8 => SceRelocInfo::Fmt8 {
                offsets: b.take_array(4)?,
            },
            9 => SceRelocInfo::Fmt9 {
                offsets: b.take_array(2)?,
            },
            other => unimplemented!("SceRelocInfo::Fmt{other}"),
        });
        assert!(b.padding || b.holding_bits() == 0, "{res:?}");
        res
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

struct Segment<'a> {
    base_vaddr: u32,
    bytes: &'a [u8],
    relocs: &'a [SceRelocInfo],
}

struct Relocation {
    pointee_segment: u32,
    pointee_offset: u32,
    pointer_segment: u32,
    pointer_offset: u32,
}
