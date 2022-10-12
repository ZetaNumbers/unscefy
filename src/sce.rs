#![allow(dead_code, nonstandard_style)]

use std::io::{self, Read, Write};

use bytemuck::{Pod, Zeroable};

/// SCE Executable file
pub const ET_SCE_EXEC: u16 = 0xFE00;

/// SCE Relocatable file
pub const ET_SCE_RELEXEC: u16 = 0xFE04;

/// SCE SDK Stubs
pub const ET_SCE_STUBLIB: u16 = 0xFE0C;

/// Unused
pub const ET_SCE_DYNAMIC: u16 = 0xFE18;

/// Unused (PSP ELF only)
pub const ET_SCE_PSPRELEXEC: u16 = 0xFFA0;

/// Unused (SPU ELF only)
pub const ET_SCE_PPURELEXEC: u16 = 0xFFA4;

/// Unknown
pub const ET_SCE_UNK: u16 = 0xFFA5;

/// SCE Relocations
pub const PT_SCE_RELA: u32 = 0x60000000;

/// Unused
pub const PT_SCE_COMMENT: u32 = 0x6FFFFF00;

/// Unused
pub const PT_SCE_VERSION: u32 = 0x6FFFFF01;

/// Unknown
pub const PT_SCE_UNK: u32 = 0x70000001;

/// Unused (PSP ELF only)
pub const PT_SCE_PSPRELA: u32 = 0x700000A0;

/// Unused (SPU ELF only)
pub const PT_SCE_PPURELA: u32 = 0x700000A4;

pub const MODULE_NAME_MAX_LEN: usize = 27;

pub type Elf32_Addr = u32;
pub type Elf32_Word = u32;

pub enum SceModuleInfo {
    V0(SceModuleInfoV0),
    V1(SceModuleInfoV1),
    V2(SceModuleInfoV2),
    V3(SceModuleInfoV3),
    V6(SceModuleInfoV6),
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable, Pod)]
pub struct SceModuleInfoCommon {
    modattribute: u16,
    modversion: [u8; 2],
    modname: [u8; MODULE_NAME_MAX_LEN],
    infover: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable, Pod)]
pub struct SceModuleInfoV0 {
    c: SceModuleInfoCommon,
    gp_value: Elf32_Addr,
    ent_top: Elf32_Addr,
    ent_btm: Elf32_Addr,
    stub_top: Elf32_Addr,
    stub_btm: Elf32_Addr,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable, Pod)]
pub struct SceModuleInfoV1 {
    c: SceModuleInfoCommon,
    gp_value: Elf32_Addr,
    ent_top: Elf32_Addr,
    ent_btm: Elf32_Addr,
    stub_top: Elf32_Addr,
    stub_btm: Elf32_Addr,
    dbg_fingerprint: Elf32_Word,
    start_entry: Elf32_Addr,
    stop_entry: Elf32_Addr,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable, Pod)]
pub struct SceModuleInfoV2 {
    c: SceModuleInfoCommon,
    gp_value: Elf32_Addr,
    ent_top: Elf32_Addr,
    ent_btm: Elf32_Addr,
    stub_top: Elf32_Addr,
    stub_btm: Elf32_Addr,
    dbg_fingerprint: Elf32_Word,
    start_entry: Elf32_Addr,
    stop_entry: Elf32_Addr,
    arm_exidx_top: Elf32_Addr,
    arm_exidx_btm: Elf32_Addr,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable, Pod)]
pub struct SceModuleInfoV3 {
    c: SceModuleInfoCommon,
    gp_value: Elf32_Addr,
    ent_top: Elf32_Addr,
    ent_btm: Elf32_Addr,
    stub_top: Elf32_Addr,
    stub_btm: Elf32_Addr,
    dbg_fingerprint: Elf32_Word,
    start_entry: Elf32_Addr,
    stop_entry: Elf32_Addr,
    arm_exidx_top: Elf32_Addr,
    arm_exidx_btm: Elf32_Addr,
    tls_start: Elf32_Addr,
    tls_filesz: Elf32_Addr,
    tls_memsz: Elf32_Addr,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable, Pod)]
pub struct SceModuleInfoV6 {
    c: SceModuleInfoCommon,
    gp_value: Elf32_Addr,
    ent_top: Elf32_Addr,
    ent_btm: Elf32_Addr,
    stub_top: Elf32_Addr,
    stub_btm: Elf32_Addr,
    dbg_fingerprint: Elf32_Word,
    tls_start: Elf32_Addr,
    tls_filesz: Elf32_Addr,
    tls_memsz: Elf32_Addr,
    start_entry: Elf32_Addr,
    stop_entry: Elf32_Addr,
    arm_exidx_top: Elf32_Addr,
    arm_exidx_btm: Elf32_Addr,
    arm_extab_top: Elf32_Addr,
    arm_extab_btm: Elf32_Addr,
}

pub enum SceLibStubTable {
    S24(SceLibStubTable24),
    S2C(SceLibStubTable2C),
    S34(SceLibStubTable34),
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable, Pod)]
pub struct SceLibStubTableCommon {
    size: u16,
    version: u16,
    attribute: u16,
    nfunc: u16,
    nvar: u16,
    ntls: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable, Pod)]
pub struct SceLibStubTable24 {
    c: SceLibStubTableCommon,
    libname_nid: Elf32_Word,
    libname: Elf32_Addr,
    func_nid_table: Elf32_Addr,
    func_entry_table: Elf32_Addr,
    var_nid_table: Elf32_Addr,
    var_entry_table: Elf32_Addr,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable, Pod)]
pub struct SceLibStubTable2C {
    c: SceLibStubTableCommon,
    reserved: [u8; 4],
    libname: Elf32_Addr,
    func_nid_table: Elf32_Addr,
    func_entry_table: Elf32_Addr,
    var_nid_table: Elf32_Addr,
    var_entry_table: Elf32_Addr,
    tls_nid_table: Elf32_Addr,
    tls_entry_table: Elf32_Addr,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable, Pod)]
pub struct SceLibStubTable34 {
    c: SceLibStubTableCommon,
    reserved: [u8; 4],
    libname_nid: Elf32_Word,
    libname: Elf32_Addr,
    sce_sdk_version: Elf32_Word,
    func_nid_table: Elf32_Addr,
    func_entry_table: Elf32_Addr,
    var_nid_table: Elf32_Addr,
    var_entry_table: Elf32_Addr,
    tls_nid_table: Elf32_Addr,
    tls_entry_table: Elf32_Addr,
}

impl SceModuleInfo {
    pub fn from_reader<R>(x: &mut R) -> io::Result<Self>
    where
        R: Read,
    {
        let mut c = SceModuleInfoCommon::zeroed();
        x.read_exact(bytemuck::bytes_of_mut(&mut c))?;
        Ok(match c.infover {
            0 => SceModuleInfo::V0(continue_read(&c, x)?),
            1 => SceModuleInfo::V1(continue_read(&c, x)?),
            2 => SceModuleInfo::V2(continue_read(&c, x)?),
            3 => SceModuleInfo::V3(continue_read(&c, x)?),
            6 => SceModuleInfo::V6(continue_read(&c, x)?),
            other => unimplemented!("SceModuleInfoCommon::infover = {other}"),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            SceModuleInfo::V0(m) => bytemuck::bytes_of(m),
            SceModuleInfo::V1(m) => bytemuck::bytes_of(m),
            SceModuleInfo::V2(m) => bytemuck::bytes_of(m),
            SceModuleInfo::V3(m) => bytemuck::bytes_of(m),
            SceModuleInfo::V6(m) => bytemuck::bytes_of(m),
        }
    }

    pub fn common(&self) -> &SceModuleInfoCommon {
        match self {
            SceModuleInfo::V0(m) => &m.c,
            SceModuleInfo::V1(m) => &m.c,
            SceModuleInfo::V2(m) => &m.c,
            SceModuleInfo::V3(m) => &m.c,
            SceModuleInfo::V6(m) => &m.c,
        }
    }

    pub fn stub_top(&self) -> &Elf32_Addr {
        match self {
            SceModuleInfo::V0(m) => &m.stub_top,
            SceModuleInfo::V1(m) => &m.stub_top,
            SceModuleInfo::V2(m) => &m.stub_top,
            SceModuleInfo::V3(m) => &m.stub_top,
            SceModuleInfo::V6(m) => &m.stub_top,
        }
    }

    pub fn stub_btm(&self) -> &Elf32_Addr {
        match self {
            SceModuleInfo::V0(m) => &m.stub_btm,
            SceModuleInfo::V1(m) => &m.stub_btm,
            SceModuleInfo::V2(m) => &m.stub_btm,
            SceModuleInfo::V3(m) => &m.stub_btm,
            SceModuleInfo::V6(m) => &m.stub_btm,
        }
    }
}

impl SceLibStubTable {
    pub fn from_reader<R>(x: &mut R) -> io::Result<Self>
    where
        R: Read,
    {
        let mut c = SceLibStubTableCommon::zeroed();
        x.read_exact(bytemuck::bytes_of_mut(&mut c))?;
        Ok(match c.size {
            0x24 => SceLibStubTable::S24(continue_read(&c, x)?),
            0x2C => SceLibStubTable::S2C(continue_read(&c, x)?),
            0x34 => SceLibStubTable::S34(continue_read(&c, x)?),
            other => unimplemented!("SceLibStubTableCommon::size = {other}"),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            SceLibStubTable::S24(m) => bytemuck::bytes_of(m),
            SceLibStubTable::S2C(m) => bytemuck::bytes_of(m),
            SceLibStubTable::S34(m) => bytemuck::bytes_of(m),
        }
    }
}

fn continue_read<C, R, T>(common: &C, x: &mut R) -> io::Result<T>
where
    C: Pod,
    R: Read,
    T: Pod,
{
    let mut v = T::zeroed();
    let mut b = bytemuck::bytes_of_mut(&mut v);
    b.write_all(bytemuck::bytes_of(common)).unwrap();
    x.read_exact(b)?;
    Ok(v)
}
