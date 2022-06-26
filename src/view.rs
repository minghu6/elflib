use std::fmt::Debug;
use std::mem::transmute;

use crate::data::{E64Hdr, E64Phdr, EIdent};

#[derive(Default, Debug)]
pub enum EIClass {
    #[default]
    Invalid,
    Bit32,
    Bit64,
}

#[derive(Default, Debug)]
pub enum EIData {
    #[default]
    Invalid,
    LSB,
    MSB,
}

#[derive(Default, Debug)]
#[repr(u16)]
pub enum EType {
    #[default]
    None,
    REL,
    EXEC,
    DYN,
    CORE,

    LOOS = 0xfe00,
    HIOS = 0xfeff,

    LOPROC = 0xff00,
    HIPROC = 0xffff,
}

#[repr(transparent)]
struct Hex64(u64);

#[derive(Default, Debug)]
#[repr(u16)]
pub enum EMachine {
    #[default]
    None,

    SPARC = 2, // SPARC
    _386 = 3,  // Intel 80386

    _860 = 7, // Intel 80860
    MIPS = 8, // MIPS I

    _960 = 19,  // Intel 80960
    PPC = 20,   // Power PC
    PPC64 = 21, // 64-bit Power PC

    IA64 = 50,  // Intel IA-64
    MIPSX = 51, // Stanford MIPS-X

    X86_64 = 62, // AMD x86-64 architecture
    PJ = 91,     // picoJava
}

/// (Program header entry) Segemnt Type
#[derive(Default, Debug)]
#[repr(u32)]
pub enum PhType {
    /// This type indicates this entry should be ignored
    #[default]
    NULL,

    /// Specify a loadable segment
    LOAD,

    /// Specify dynamic linking information
    DYNAMIC,

    /// Specify the loacation and size of a path name (null-terminated)
    /// to invoke as an interpreter. This segment type is only for executable files (including shared objections)
    /// it may not occur more than once in a file. If it's present, it must precede any loadable segment entry.
    INTERP,

    /// Specify the location and size of auxiliary information
    NOTE,

    /// reserved
    SHLIB,

    /// Specify the location adn size of the program header table itself.
    /// It may only occur if the program header table is part
    /// of the memory image of the program. If it's present,
    /// it must precede any loadable segment entry.
    PHDR,

    /// Specify the Thread-Local Storage templates
    TLS,

    /// reserved for operating system-specified semnatics
    LOOS = 0x6000_0000,

    /// reserved for operating system-specified semnatics
    HIOS = 0x6fff_ffff,

    /// reserved for processor-specific semantics
    LOPROC = 0x7000_0000,

    /// reserved for processor-specific semantics
    HOPROC = 0x7fff_ffff,
}


/// https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html#p_flags
#[derive(Debug)]
pub enum PFlagBit {
    X,
    W,
    R,
    MASKOS(u8),
    MASKPROC(u8),
}

#[derive(Debug)]
pub struct PFLAGS(Vec<PFlagBit>);

pub struct E64PhEntries(Option<Vec<E64Phdr>>);


/// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html#sh_type
#[derive(Debug)]
pub enum ShType {
    /// The section header doesn't have an associated value
    /// Other members of the section header have undefined value
    NULL,

    /// The section holds information defined by program whose
    /// fromat and meaning are determined solely by the program.
    PROGBITS,

    /// Hold a symbol table. Currently, an object file may have only one section of each type,
    /// but this restriction may be relaxed in the future.
    /// Typically, SHT_SYMTAB provides symbols for link editing,
    /// though it may also be used for dynamic linking.
    SYMTBL,

    /// Hold a string table
    STRTBL,

    /// Hold relocation entries with explicit addends, such as type Elf32_Rela for the 32-bit
    /// class of object files or type Elf64_Rela for the 64-bit class of object files.
    RELA,

    /// Hold a symbol hash table.
    HASH,

    /// Hold information for dynamic linking
    DYNAMIC,

    /// Hold information that marks the file in some way.
    NOTE,

    /// A section of this type occupies no space in the file
    /// but otherwise resembles PROGBITS
    NOBITS,

    /// The section holds relocation entries without explicit addends
    REL,

    /// reserved
    SHLIB,

    /// The section contains an array of pointers to initialization functions
    /// Each pointer in the array is tabken as a parameterless procedure wit a void return.
    INITARRAY,

    /// Same with INITARRAY except for termination functions
    FINIARRAY,

    /// preinit functions
    PREINITARRAY,

    GROUP,

    SYMTBLSHNDX,

    SPECOS(u32),

    SPECPROC(u32),

    SPECUSER(u32)
}



impl Debug for Hex64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:04x}", &self.0)
    }
}

impl Debug for E64Hdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let etype: EType = unsafe { std::mem::transmute(self.r#type()) };
        let machine: EMachine = unsafe { std::mem::transmute(self.machine()) };

        f.debug_struct("E64Hdr")
            .field("ident", &self.ident())
            .field("r#type", &etype)
            .field("machine", &machine)
            .field("version", &self.version())
            .field("entry", &Hex64(self.entry()))
            .field("program header offset", &Hex64(self.phoff()))
            .field("section header offset", &Hex64(self.shoff()))
            .field("flags", &self.flags())
            .field("elf header size (bytes)", &self.ehsize())
            .field(
                "program header table entry size",
                &self.ph_tbl_entry_size(),
            )
            .field(
                "program header table entry number",
                &self.ph_tbl_entry_num(),
            )
            .field(
                "section header table entry size",
                &self.sh_tbl_entry_size(),
            )
            .field(
                "section header table entry number",
                &self.sh_tbl_entry_num(),
            )
            .field(
                "string table index of section header table (decimal)",
                &self.sh_strtbl_idx(),
            )
            .finish()
    }
}

impl Debug for EIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[repr(transparent)]
        struct MagicNum([u8; 4]);

        impl Debug for MagicNum {
            fn fmt(
                &self,
                f: &mut std::fmt::Formatter<'_>,
            ) -> std::fmt::Result {
                write!(
                    f,
                    "{:0x}, {:0x}, {:0x}, {:0x}",
                    self.0[0], self.0[1], self.0[2], self.0[3]
                )
            }
        }

        let class: EIClass = unsafe { std::mem::transmute(self.class()) };
        let data: EIData = unsafe { std::mem::transmute(self.data()) };

        f.debug_struct("EIdent")
            .field("magic_nums", &MagicNum(self.magic_nums()))
            .field("class", &class)
            .field("data", &data)
            .field("version", &self.version())
            .field("osabi", &self.osabi())
            .field("abiversion", &self.abiversion())
            .field("_pad", &self._pad())
            .field("nident", &self.nident())
            .finish()
    }
}

impl From<u32> for PFLAGS {
    fn from(val: u32) -> Self {
        let mut flags = vec![];

        if val & 0b1u32 > 0 {
            flags.push(PFlagBit::X);
        }

        if val & 0b10u32 > 0 {
            flags.push(PFlagBit::W)
        }

        if val & 0b100u32 > 0 {
            flags.push(PFlagBit::R)
        }

        let os_spec = (val & 0x0ff0_0000) as u8;
        let proc_spec = (val & 0xf000_0000) as u8;

        if os_spec > 0 {
            flags.push(PFlagBit::MASKOS(os_spec))
        }

        if proc_spec > 0 {
            flags.push(PFlagBit::MASKPROC(proc_spec));
        }

        PFLAGS(flags)
    }
}

impl Debug for E64Phdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ptype: PhType = unsafe { std::mem::transmute(self.r#type()) };
        let flags = PFLAGS::from(self.flags());

        f.debug_struct("E64Phdr")
            .field("r#type", &ptype)
            .field("flags", &flags)
            .field("offset", &Hex64(self.offset()))
            .field("vaddr", &Hex64(self.vaddr()))
            .field("paddr", &Hex64(self.paddr()))
            .field("filesz", &self.filesz())
            .field("memsz", &self.memsz())
            .field("align", &self.align())
            .finish()
    }
}

impl Debug for E64PhEntries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref entries) = self.0 {
            for (i, entry) in entries.into_iter().enumerate() {
                writeln!(f, "{}: {:#?}", i, entry)?;
            }
            Ok(())
        } else {
            write!(f, "None")
        }
    }
}

impl From<u32> for ShType {
    fn from(val: u32) -> Self {
        if val >= 0x6000_0000 && val <= 0x6fff_ffff {
            ShType::SPECOS(val)
        }
        else if val >= 0x7000_0000 && val <= 0x7fff_ffff {
            ShType::SPECPROC(val)
        }
        else if val >= 0x8000_0000 {
            ShType::SPECUSER(val)
        }
        else {
            unsafe { transmute::<u64, Self>(val as u64) }
        }
    }
}



#[cfg(test)]
mod tests {
    use std::{error::Error, fs::File, mem::size_of};

    use bincode::{options, Options};
    use memmap2::MmapOptions;

    use super::E64Hdr;
    use crate::{data::E64Phdr, view::E64PhEntries};

    #[test]
    fn it_works() -> Result<(), Box<dyn Error>> {
        let config = options().with_fixint_encoding();
        let reader = File::open("./draft/arr")?;

        let mmap = unsafe { MmapOptions::new().map(&reader)? };

        let elf64hdr: E64Hdr =
            config.deserialize(&mmap[..size_of::<E64Hdr>()])?;

        let ph = if elf64hdr.phoff() > 0 {
            let phoff = elf64hdr.phoff() as usize;
            let entry_size = elf64hdr.ph_tbl_entry_size() as usize;
            let entry_num = elf64hdr.ph_tbl_entry_num() as usize;

            let mut ph_entries = Vec::with_capacity(entry_num);

            for i in 0..entry_num {
                let ph_entry: E64Phdr = config.deserialize(
                    &mmap
                        [phoff + i * entry_size..phoff + (i + 1) * entry_size],
                )?;
                ph_entries.push(ph_entry);
            }

            E64PhEntries(Some(ph_entries))
        } else {
            E64PhEntries(None)
        };

        println!("{:#?}", elf64hdr);

        println!("Program Header Table: {:#?}", ph);

        Ok(())
    }
}
