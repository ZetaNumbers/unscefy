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

pub enum SceModuleInfo {
    V0(SceModuleInfoV0),
    V1(SceModuleInfoV1),
    V2(SceModuleInfoV2),
    V3(SceModuleInfoV3),
    V6(SceModuleInfoV6),
}

impl SceModuleInfo {
    pub fn from_reader<R>(x: &mut R) -> io::Result<SceModuleInfo>
    where
        R: Read,
    {
        let mut c = SceModuleInfoCommon::zeroed();
        x.read_exact(bytemuck::bytes_of_mut(&mut c))?;
        Ok(match c.infover {
            0 => SceModuleInfo::V0(continue_read(c, x)?),
            1 => SceModuleInfo::V1(continue_read(c, x)?),
            2 => SceModuleInfo::V2(continue_read(c, x)?),
            3 => SceModuleInfo::V3(continue_read(c, x)?),
            6 => SceModuleInfo::V6(continue_read(c, x)?),
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
}

fn continue_read<R, T>(common: SceModuleInfoCommon, x: &mut R) -> io::Result<T>
where
    R: Read,
    T: Pod,
{
    let mut v = T::zeroed();
    let mut b = bytemuck::bytes_of_mut(&mut v);
    b.write_all(bytemuck::bytes_of(&common)).unwrap();
    x.read_exact(b)?;
    Ok(v)
}
