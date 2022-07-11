use std::{
    error::Error, fmt::Debug, fs::File, io::ErrorKind, mem::size_of,
    path::Path,
};

use bincode::{options, Options};
use getset::Getters;
use memmap2::{Mmap, MmapOptions};

use crate::{
    data::{E64Hdr, E64Shdr, E64Sym, EIdent, StrTab},
    view::{
        EHdrView, EIClass, EIData, EIdentView, EType, Hex64, MagicNums,
        SHEntries, SHType, SHdrView, SymBinding, SymTab, SymType, SymValue,
        SymView, SymVisi, SHFLAGS, SID,
    },
};


#[derive(Clone, Getters)]
#[getset(get = "pub")]
pub struct Elf {
    ehdr: EHdrView,

    /// Section Name String Table
    shstrtab: StrTab,
    shentries: SHEntries,

    /// Symbol Table Entry Related String Table
    strtab: StrTab,
    symtab: SymTab,

    dynsym: SymTab
}

macro_rules! bincode_options {
    () => {
        options().with_fixint_encoding()
    };
}


impl Elf {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        let config = bincode_options!();
        let reader = File::open(path)?;

        let mmap = unsafe { MmapOptions::new().map(&reader)? };

        let eident: EIdent =
            config.deserialize(&mmap[..size_of::<EIdent>()])?;

        let eidentview: EIdentView = eident.into();

        if matches!(eidentview.class, EIClass::Bit32) {
            Self::load_32_from_mmap(mmap)
        } else if matches!(eidentview.class, EIClass::Bit64) {
            Self::load_64_from_mmap(mmap)
        } else {
            Err(Box::new(std::io::Error::new(
                ErrorKind::Other,
                format!("Unknown Elf class {:?}", eidentview),
            )))
        }
    }

    pub fn load_64_from_mmap(mmap: Mmap) -> Result<Self, Box<dyn Error>> {
        let config = bincode_options!();
        let ehdr: E64Hdr = config.deserialize(&mmap[..size_of::<E64Hdr>()])?;
        let ehdr: EHdrView = ehdr.into();

        let shstrtab: StrTab;

        let shoff = ehdr.section_hdr_offset().0 as usize;

        let shentries = if shoff > 0 {
            let entry_size = *ehdr.section_hdr_ent_sz() as usize;
            let entry_num = *ehdr.section_hdr_ent_num() as usize;

            let mut sh_entries = Vec::with_capacity(entry_num);
            for i in 0..entry_num {
                let sh_entry: E64Shdr = config.deserialize(
                    &mmap
                        [shoff + i * entry_size..shoff + (i + 1) * entry_size],
                )?;

                sh_entries.push(sh_entry);
            }

            let shstr_tab_entry = if *ehdr.section_str_tab_idx() == SID::XIndex
            {
                &sh_entries[sh_entries[0].link() as usize]
            } else {
                &sh_entries[Into::<usize>::into(*ehdr.section_str_tab_idx())]
            };

            let sec_offset = shstr_tab_entry.offset() as usize;
            let sec_size = shstr_tab_entry.size() as usize;

            shstrtab = StrTab::new(Vec::from_iter(
                mmap[sec_offset..sec_offset + sec_size].iter().cloned(),
            ));

            let mut sh_view_entries = vec![];
            for entry in sh_entries.iter() {
                let ty = SHType::from(entry.ty());
                let flags = SHFLAGS::from(entry.flags() as u32);
                let name = shstrtab.get(entry.name() as usize).unwrap();

                let sh_entry_view = SHdrView {
                    name,
                    ty,
                    flags,
                    addr: Hex64(entry.addr()),
                    offset: Hex64(entry.offset()),
                    size: entry.size(),
                    link: entry.link(),
                    info: entry.info(),
                    addr_align: entry.addr_align(),
                    ent_size: entry.ent_size(),
                };
                sh_view_entries.push(sh_entry_view)
            }

            SHEntries(sh_view_entries)
        } else {
            shstrtab = StrTab::empty();

            SHEntries(vec![])
        };


        /* Load strtab */
        let strtab = load_strtab_from_sh(&shentries, ".strtab", &mmap);

        /* Load symtab */
        let symtab =
            load_sym64tab_from_sh(&shentries, ".symtab", &strtab, ehdr.ty(), &mmap)?;

        /* Load dynstr */
        let dynstr = load_strtab_from_sh(&shentries, ".dynstr", &mmap);

        /* Load dynsym */
        let dynsym =
            load_sym64tab_from_sh(&shentries, ".dynsym", &&dynstr, ehdr.ty(), &mmap)?;

        #[allow(unused)]
        if let Some(sh) = shentries.get(".bss") {
            let sec_offset = sh.offset().0 as usize;
            let sec_size = *sh.size() as usize;

            let raw = Vec::from_iter(
                mmap[sec_offset..sec_offset + sec_size].iter().cloned(),
            );

            // println!(".bss raw data {:?}", raw)
        }


        Ok(Self {
            ehdr,
            shstrtab,
            shentries,
            strtab,
            symtab,
            dynsym
        })
    }


    pub fn load_32_from_mmap(_mmap: Mmap) -> Result<Self, Box<dyn Error>> {
        todo!()
    }
}



////////////////////////////////////////////////////////////////////////////////
//// Into Implementations

impl Into<EIdentView> for EIdent {
    fn into(self) -> EIdentView {
        let magic_nums = MagicNums(self.magic_nums());
        let class: EIClass = unsafe { std::mem::transmute(self.class) };
        let data: EIData = unsafe { std::mem::transmute(self.data) };

        EIdentView {
            magic_nums,
            class,
            data,
            version: self.version,
            osabi: self.osabi,
            abiversion: self.abiversion,
            nident: self.nident,
        }
    }
}

fn load_strtab_from_sh(
    shentries: &SHEntries,
    secname: &str,
    mmap: &Mmap,
) -> StrTab {
    if let Some(sh) = shentries.get(secname) {
        let sec_offset = sh.offset().0 as usize;
        let sec_size = *sh.size() as usize;

        StrTab::new(Vec::from_iter(
            mmap[sec_offset..sec_offset + sec_size].iter().cloned(),
        ))
    } else {
        StrTab::empty()
    }
}

fn load_sym64tab_from_sh(
    shentries: &SHEntries,
    secname: &str,
    strtab: &StrTab,
    ety: &EType,
    mmap: &Mmap,
) -> Result<SymTab, Box<dyn Error>> {
    let config = bincode_options!();

    Ok(if let Some(sh) = shentries.get(secname) {
        let sym_sz = size_of::<E64Sym>();
        debug_assert_eq!(sym_sz, sh.ent_size as usize);
        let sym_num = sh.size as usize / sym_sz;

        let sec_off = sh.offset.0 as usize;
        let mut symentries = Vec::with_capacity(sym_num);

        for i in 0..sym_num {
            let sym: E64Sym = config.deserialize(
                &mmap[sec_off + i * sym_sz..sec_off + (i + 1) * sym_sz],
            )?;

            let name = strtab.get(sym.name() as usize).unwrap_or_default();

            let bind = SymBinding::load_from_info(sym.info());
            let ty = SymType::load_from_info(sym.info());
            let visi = SymVisi::load_from_other(sym.other());
            let shndx = SID::from(sym.shndx());

            let value = match ety {
                EType::REL => {
                    if shndx == SID::Common {
                        SymValue::Alignment(sym.value())
                    } else {
                        SymValue::SectionOffset(sym.value())
                    }
                }
                EType::EXEC | EType::DYN => {
                    SymValue::VirAddr(Hex64(sym.value()))
                }
                _ => unreachable!("ty: {:#?}", ety),
            };

            let symview = SymView {
                name,
                bind,
                ty,
                visi,
                shndx,
                value,
                size: sym.size(),
            };

            symentries.push(symview);
        }

        SymTab(symentries)
    } else {
        SymTab(vec![])
    })

}

impl Debug for Elf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Elf")
            .field("ehdr", &self.ehdr)
            // .field("shstrtab", &self.shstrtab)
            .field("shentries", &self.shentries)
            // .field("strtab", &self.strtab)
            .field("symtab", &self.symtab)
            .field("dynsym", &self.dynsym)
            .finish()
    }
}
