use std::{
    cell::RefCell,
    ffi::{CStr, CString},
    fs::File,
    mem,
};

use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use object::{elf, pod};

use crate::{append_file, ede, strtab::StrTab, zeroed, Link, TE};

pub struct SymTab {
    rx: mpsc::UnboundedReceiver<Payload>,
}

impl SymTab {
    pub fn new() -> (Self, Proxy) {
        let (tx, rx) = mpsc::unbounded();
        (SymTab { rx }, Proxy { tx })
    }

    pub async fn store(
        mut self,
        file: &RefCell<File>,
        sht: &mut Vec<elf::SectionHeader32<TE>>,
        shstrtab: &mut StrTab,
        link: Link,
    ) {
        let mut local = Vec::new();
        let mut global = Vec::new();

        while let Some(payload) = self.rx.next().await {
            if payload.symbol.st_bind() == elf::STB_GLOBAL {
                &mut global
            } else {
                &mut local
            }
            .push(payload)
        }

        let sh_info = u32::try_from(local.len()).unwrap() + 1;

        let mut syms = vec![zeroed()];
        let mut names = StrTab::new();
        local
            .into_iter()
            .chain(global)
            .for_each(|mut payload: Payload| {
                let sym_idx = syms.len().try_into().unwrap();
                let st_name = names.push_cstr(&payload.name);
                payload.symbol.st_name = ede(st_name);
                syms.push(payload.symbol);
                let _ = payload.idx_tx.send(sym_idx);
            });

        let sh_link = names.store_strtab(&mut file.borrow_mut(), sht, shstrtab, link);

        let sym_bytes = pod::bytes_of_slice(&syms);
        let sh_offset = append_file(&mut file.borrow_mut(), sym_bytes)
            .unwrap()
            .try_into()
            .unwrap();

        let sh_name = shstrtab.push_cstr(
            CStr::from_bytes_with_nul(match link {
                Link::Static => b".symtab\0",
                Link::Dynamic => b".dynsym\0",
            })
            .unwrap(),
        );

        let sh_size = sym_bytes.len().try_into().unwrap();
        sht.push(elf::SectionHeader32 {
            sh_name: ede(sh_name),
            sh_type: ede(match link {
                Link::Static => elf::SHT_SYMTAB,
                Link::Dynamic => elf::SHT_DYNSYM,
            }),
            sh_flags: ede(match link {
                Link::Dynamic => elf::SHF_ALLOC,
                Link::Static => 0,
            }),
            sh_offset: ede(sh_offset),
            sh_size: ede(sh_size),
            sh_link: ede(sh_link),
            sh_info: ede(sh_info),
            sh_addralign: ede(4),
            sh_entsize: ede(mem::size_of::<elf::Sym32<TE>>().try_into().unwrap()),
            sh_addr: zeroed(),
        })
    }
}

pub struct Proxy {
    tx: mpsc::UnboundedSender<Payload>,
}

impl Proxy {
    pub fn add_symbol(
        &self,
        name: CString,
        symbol: elf::Sym32<TE>,
    ) -> Result<oneshot::Receiver<u32>, mpsc::SendError> {
        let (tx, rx) = oneshot::channel();
        let payload = Payload {
            name,
            symbol,
            idx_tx: tx,
        };
        self.tx
            .unbounded_send(payload)
            .map_err(|e| e.into_send_error())?;
        Ok(rx)
    }

    pub fn close(&self) {
        self.tx.close_channel()
    }
}

struct Payload {
    name: CString,
    symbol: elf::Sym32<TE>,
    idx_tx: oneshot::Sender<u32>,
}
