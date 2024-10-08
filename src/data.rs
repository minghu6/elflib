use getset::CopyGetters;
use serde::Deserialize;


////////////////////////////////////////////////////////////////////////////////
//// Elf Header

#[derive(CopyGetters, Default, Deserialize)]
#[getset(get_copy = "pub")]
pub struct E64Hdr {
    /// Elf Header Identifier
    ident: EIdent,

    /// Object file type:
    ///
    /// | Type | value  | meaning |
    /// |---------|---|--------------|
    /// | ET_NONE | 0 | No file type |
    /// | ET_REL | 1 | Relocatable file |
    /// | ET_EXEC | 2 | Executable file (just check if no-pie, gcc compiles bin using -pie default) |
    /// | ET_DYN | 3 | Shared object file |
    /// | ET_CORE | 4 | Core file
    /// | ET_LOOS | 0xfe00 | Operating system-specific
    /// | ET_HIOS | 0xfeff | Operating system-specific
    /// | ET_LOPROC | 0xff00 | Processor-specific
    /// | ET_HIPROC | 0xffff | Processor-specific
    ///
    ty: u16,

    /// required architecture
    /// ref https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html#elfid
    machine: u16,

    /// EV_VERSION, should be 1
    version: u32,

    entry: u64,

    phoff: u64,
    shoff: u64,

    flags: u32,
    ehsize: u16,  // header size

    ph_tab_entry_size: u16,  // Bytes of One Entry of Program Header Table
    ph_tab_entry_num: u16,  // Program Header Table Entry Count

    sh_tab_entry_size: u16,  // Section Header Table Entry Size
    sh_tab_entry_num: u16,   // Section Header Table Entry Number

    sh_strtab_idx: u16  // Section header string table index
}

#[derive(CopyGetters, Default, Deserialize)]
#[getset(get_copy = "pub")]
pub struct E32Hdr {
    ident: EIdent,
    ty: u16,
    machine: u16,
    version: u32,
    entry: u32,

    phoff: u64,
    shoff: u64,

    flags: u32,
    ehsize: u16,

    ph_tab_entry_size: u16,
    ph_tab_entry_num: u16,

    sh_tab_entry_size: u16,
    sh_tab_entry_num: u16,

    sh_strtab_idx: u16
}

#[repr(C)]
#[derive(CopyGetters, Default, Deserialize, Clone, Copy)]
#[getset(get_copy = "pub")]
pub struct EIdent {
    /// Indicate file type
    pub(crate) magic_nums: [u8; 4],

    /// 0 - Invalid class
    /// 1 - 32 bit object
    /// 2 - 64 bit object
    pub(crate) class: u8,

    /// 0 - Invalid data encoding
    /// 1 - LSB (least significant bit, little endian)
    /// 2 - MSB
    pub(crate) data: u8,

    /// ELF header version number (EI_VERSION).
    /// Currently, this value must be EV_CURRENT (that's 1, 1.2 is final version of elf)
    pub(crate) version: u8,

    /// Identifies the operating system and ABI to which the object is targeted.
    /// Some fields in other ELF structures have flags and values that have operating system or ABI specific meanings.
    /// The interpretation of those fields is determined by the value of this byte
    pub(crate) osabi: u8,

    /// The interpretation of this version number is dependent on the ABI identified by the EI_OSABI field.
    /// If no values are specified for the EI_OSABI field for the processor,
    /// or no version values are specified for the ABI determined by a particular value of the EI_OSABI byte,
    /// the value 0 is used to indicate unspecified.
    pub(crate) abiversion: u8,
    _pad: [u8; 6],

    /// Fixed value: 16, indicate that EIdent bytes
    pub(crate) nident: u8,
}



////////////////////////////////////////////////////////////////////////////////
//// Program Header

#[derive(CopyGetters, Default, Deserialize)]
#[getset(get_copy = "pub")]
pub struct E64Phdr {
    /// Segment type
    /// https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html#p_type
    ///
    /// | Type | value |
    /// |------|-------|
    /// | NULL | 0 |
    /// | LOAD | 1 |
    /// | DYNAMIC | 2 |
    /// | INTERP | 3 |
    /// | NOTE | 4 |
    /// | SHLIB | 5 |
    /// | PHDR | 6 |
    /// | TLS | 7 |
    /// | LOOS | 0x6000_0000 |
    /// | HIOS | 0x6fff_ffff |
    /// | LOPROC | 0x7000_0000 |
    /// | HIPROC | 0x7fff_ffff |
    ty: u32,

    /// Segement bits X/W/R os, proc spec etc.
    flags: u32,

    /// Segment offset (for file)
    offset: u64,

    /// Virtual address (in memory)
    vaddr: u64,

    /// Physical address (Just on systems for which physical addressing)
    /// Othersiwse it's unspecified content.
    paddr: u64,

    /// In file image segment size
    filesz: u64,

    /// In memory image segment size
    memsz: u64,

    /// Gives the segment alignment in memory and file
    /// 0 and 1 means no alignment is required
    /// Otherwise, p_align should be a positive, integral power of 2,
    /// loadable process segments must have congruent(重叠) values for p_vaddr and p_offset, modulo the page size
    align: u64
}

#[derive(CopyGetters, Default, Deserialize)]
#[getset(get_copy = "pub")]
pub struct E32Phdr {
    ty: u32,
    offset: u32,

    vaddr: u32,
    paddr: u32,

    filesz: u32,
    memsz: u32,

    flags: u32,
    align: u32
}



////////////////////////////////////////////////////////////////////////////////
//// Section Header

#[derive(CopyGetters, Default, Deserialize)]
#[getset(get_copy = "pub")]
pub struct E64Shdr {
    /// Section name - string tab idx
    name: u32,

    /// Section type
    ty: u32,

    /// Section flags
    flags: u64,

    /// Section virtual address at executation
    addr: u64,

    /// Section offset
    offset: u64,

    /// Section size
    size: u64,

    /// Holds a section header table index link,
    /// whose interpretion depends on the section type.
    link: u32,

    /// Holds extra information, whose interpretion depends on the section type
    info: u32,

    /// The value of sh_addr must be congruent to 0, modulo the value of sh_addralign.
    /// Currently, only 0 and positive integral powers of two are allowed.
    /// Values 0 and 1 mean the section has no alignment constraints.
    addr_align: u64,

    /// Some sections hold a table of fixed-size entries,
    /// such as a symbol table. For such a section,
    /// this member gives the size in bytes of each entry.
    /// The member contains 0 if the section does not hold
    /// a table of fixed-size entries
    ent_size: u64
}

#[derive(CopyGetters, Default, Deserialize)]
#[getset(get_copy = "pub")]
pub struct E32Shdr {
    name: u32,
    ty: u32,
    flags: u32,
    addr: u32,
    offset: u32,
    size: u32,
    link: u32,
    info: u32,
    addr_align: u32,
    ent_size: u32
}


////////////////////////////////////////////////////////////////////////////////
//// Section Data

#[derive(Clone)]
pub struct StrTab(Vec<u8>);


////////////////////////////////////////////////////////////////////////////////
//// Symbol Table

#[derive(CopyGetters, Default, Deserialize, Debug)]
#[getset(get_copy = "pub")]
pub struct E64Sym {
    name: u32,

    /// type and binding
    info: u8,

    /// the first 2 bit indicates that visibility
    /// the last 6 bit is unspecified
    other: u8,

    /// Section index
    shndx: u16,

    /// This member gives the value of the associated symbol.
    /// Depending on the context, this may be an absolute value, an address, and so on;
    value: u64,
    size: u64
}


#[derive(CopyGetters, Default, Deserialize)]
#[getset(get_copy = "pub")]
pub struct E32Sym {
    name: u32,
    value: u32,
    size: u32,
    info: u8,
    other: u8,
    shndx: u16
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations


impl StrTab {
    pub fn empty() -> Self {
        StrTab(Vec::new())
    }

    pub fn new(vec: Vec<u8>) -> Self {
        Self(vec)
    }

    pub fn get(&self, idx: usize) -> Option<String> {
        if idx >= self.0.len() {
            return None;
        }

        let mut s = String::new();

        for i in idx..self.0.len() {
            if self.0[i] == 0 {
                break;
            }

            s.push(self.0[i] as char)
        }

        Some(s)
    }

    pub fn str_vec(&self) -> Vec<String> {
        let mut str_vec = vec![];

        if self.0.is_empty() {
            return str_vec;
        }

        let mut s = String::new();
        for i in 1..self.0.len() {
            if self.0[i] == 0 {
                str_vec.push(s);
                s = String::new();
                continue;
            }

            s.push(self.0[i] as char);
        }

        str_vec
    }

}


#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use crate::view::EIClass;

    use super::{E64Hdr, EIdent};

    #[test]
    fn echo_size() {
        println!("EIClass: {}", size_of::<EIClass>());
        println!("EIdent: {}", size_of::<EIdent>());
        println!("E64Hdr: {}", size_of::<E64Hdr>());
    }
}
