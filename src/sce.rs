#![allow(dead_code)]

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
