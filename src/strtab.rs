use std::{ffi::CStr, fs::File};

use object::elf;

use crate::{ede, zeroed, Link, TE};

pub struct StrTab {
    strings: Vec<u8>,
    base_indices: Vec<u32>,
}

impl StrTab {
    pub fn new() -> Self {
        StrTab {
            strings: "\0".into(),
            base_indices: vec![0, 1],
        }
    }

    pub fn push_cstr(&mut self, s: &CStr) -> u32 {
        let cur = self.strings.len().try_into().unwrap();
        self.strings.extend_from_slice(s.to_bytes_with_nul());
        self.base_indices.push(cur);
        cur
    }

    pub fn store_shstrtab(
        mut self,
        sht: &mut Vec<elf::SectionHeader32<TE>>,
        eh: &mut elf::FileHeader32<TE>,
        file: &mut File,
    ) -> u32 {
        let cur = sht.len().try_into().unwrap();
        sht.push(elf::SectionHeader32 {
            sh_name: ede(self.push_cstr(CStr::from_bytes_with_nul(b".shstrtab\0").unwrap())),
            sh_type: ede(elf::SHT_STRTAB),
            sh_offset: ede(crate::append_file(file, &self.strings)
                .unwrap()
                .try_into()
                .unwrap()),
            sh_size: ede(self.strings.len().try_into().unwrap()),
            sh_addralign: ede(1),
            ..zeroed()
        });
        eh.e_shstrndx = ede(cur);
        cur.into()
    }

    pub fn store_strtab(
        self,
        file: &mut File,
        sht: &mut Vec<elf::SectionHeader32<TE>>,
        shstrtab: &mut StrTab,
        link: Link,
    ) -> u32 {
        let cur = sht.len().try_into().unwrap();
        sht.push(elf::SectionHeader32 {
            sh_offset: ede(crate::append_file(file, &self.strings)
                .unwrap()
                .try_into()
                .unwrap()),
            sh_name: ede(shstrtab
                .push_cstr(
                    CStr::from_bytes_with_nul(match link {
                        Link::Static => b".strtab\0",
                        Link::Dynamic => b".dynstr\0",
                    })
                    .unwrap(),
                )
                .try_into()
                .unwrap()),
            sh_type: ede(elf::SHT_STRTAB),
            sh_size: ede(self.strings.len().try_into().unwrap()),
            sh_addralign: ede(1),
            ..zeroed()
        });
        cur
    }

    pub fn strings(&self) -> &[u8] {
        self.strings.as_ref()
    }
}
