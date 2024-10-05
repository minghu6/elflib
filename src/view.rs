use std::fmt::Debug;
use std::mem::transmute;

use getset::{CopyGetters, Getters};

use crate::data::{E64Hdr, E64Phdr, StrTab};


////////////////////////////////////////////////////////////////////////////////
//// EIdent View

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct MagicNums(pub [u8; 4]);

#[derive(Default, Debug, Clone, Copy)]
pub enum EIClass {
    #[default]
    Invalid,
    Bit32,
    Bit64,
}

#[derive(Default, Debug, Clone, Copy)]
pub enum EIData {
    #[default]
    Invalid,
    LSB,
    MSB,
}

#[derive(Debug, CopyGetters, Clone)]
#[getset(get_copy = "pub")]
pub struct EIdentView {
    pub(crate) magic_nums: MagicNums,
    pub(crate) class: EIClass,
    pub(crate) data: EIData,
    pub(crate) version: u8,
    pub(crate) osabi: u8,
    pub(crate) abiversion: u8,
    pub(crate) nident: u8,
}


////////////////////////////////////////////////////////////////////////////////
//// ElfHeader View

#[derive(Default, Debug, Clone)]
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

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Hex64(pub u64);

#[derive(Default, Debug, Clone)]
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

/// Section Id
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum SID {
    /// 0
    Undef,

    /// 0xff00, = LoReserve - 0xff1f
    Proc(u16),

    /// 0xff20 - 0xff3f
    OS(u16),

    /// 0xfff1
    /// Specify absolute values for corresponding reference.
    Abs,

    ///  0xfff2
    /// Symbols defined relative to the section are common symbols,
    /// such as external variables
    Common,

    /// 0xffff, = HiReserve
    /// It's an excape value. It indicates that the actual section section header index is too large
    /// and to be found another location.
    XIndex,

    Normal(u16),
}


#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct EHdrView {
    ident: EIdentView,
    ty: EType,
    machine: EMachine,
    version: u32,
    entry: Hex64,
    prog_hdr_offset: Hex64,
    section_hdr_offset: Hex64,
    flags: u32,
    elf_hdr_sz: u16,
    prog_hdr_tab_ent_sz: u16,
    prog_hdr_tab_ent_num: u16,
    section_hdr_ent_sz: u16,
    section_hdr_ent_num: u16,
    section_str_tab_idx: SID,
}


////////////////////////////////////////////////////////////////////////////////
//// Program Header View

#[derive(Getters, Debug)]
#[getset(get = "pub")]
pub struct PHdrView {
    ty: PhType,

    flags: PFLAGS,

    offset: u64,

    vaddr: Hex64,

    paddr: Hex64,

    filesz: u64,

    memsz: u64,

    align: u64
}

/// (Program header entry) Segemnt Type
#[derive(Default, Debug, Clone, Copy)]
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
#[derive(Debug, Clone, Copy)]
pub enum PFlagBit {
    X,
    W,
    R,
    OS(u8),
    Proc(u8),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PFLAGS(Vec<PFlagBit>);

pub struct E64PhEntries(Option<Vec<E64Phdr>>);


////////////////////////////////////////////////////////////////////////////////
//// Section Header View

#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct SHdrView {
    pub(crate) name: String,
    pub(crate) ty: SHType,
    pub(crate) flags: SHFLAGS,
    pub(crate) addr: Hex64,
    pub(crate) offset: Hex64,
    pub(crate) size: u64,
    pub(crate) link: u32,
    pub(crate) info: u32,
    pub(crate) addr_align: u64,
    pub(crate) ent_size: u64,
}


/// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html#sh_type
#[derive(Debug, Clone, Copy)]
pub enum SHType {
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
    SYMtab,

    /// Hold a string table
    STRtab,

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

    SYMtabSHNDX,

    SPECOS(u32),

    SPECPROC(u32),

    SPECUSER(u32),
}

#[derive(Debug, Clone, Copy)]
pub enum SHFlagBit {
    /// 0b1
    Write,

    /// The section occupies memory in process image
    /// 0b10
    Alloc,

    /// The Section contains Executable Instruction
    /// 0b100
    ExecInstr,

    /// 0b1_0000, = 0x10
    Merge,

    /// The section consist of null-terminated string.
    /// 0b10_0000, = 0x20
    StringS,

    /// The `info` field of this section header holds a section header table index
    /// 0b100_0000, = 0x40
    InfoLink,

    /// 0b1000_0000, = 0x80
    LinkOrder,

    /// 0b1_0000_0000, = 0x100
    OsNonconforming,

    /// 0b10_0000_0000, = 0x200
    Group,

    /// 0b100_0000_0000, = 0x400
    TLS,

    /// Mask 0x0ff0_0000
    OS(u8),

    /// Mask 0xf000_0000
    Proc(u8),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SHFLAGS(Vec<SHFlagBit>);

#[derive(Clone)]
pub struct SHEntries(pub(crate) Vec<SHdrView>);


////////////////////////////////////////////////////////////////////////////////
//// Symbol Table

#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct SymView {
    pub(crate) name: String,
    pub(crate) bind: SymBinding,
    pub(crate) ty: SymType,
    pub(crate) visi: SymVisi,
    pub(crate) shndx: SID,
    pub(crate) value: SymValue,
    pub(crate) size: u64
}

#[derive(Debug, Clone, Copy)]
pub enum SymBinding {
    /// 0
    Local,

    /// 1
    Global,

    /// 2
    Weak,

    /// 10-12
    OS(u8),

    /// 13-15
    Proc(u8),
}

#[derive(Debug, Clone, Copy)]
pub enum SymType {
    /// 0, type is unspecified
    NoType,

    /// 1, data object such as variable, an array and so on.
    Object,

    /// 2, function or other executable code
    Func,

    /// 3, The symbol is associated with a section. Symbol table entries of this type exist
    /// primarily for relocation and normally have STB_LOCAL binding.
    Section,

    /// 4, Conventionally, the symbol's name gives the name of the
    /// source file associated with the object file. A file symbol has
    /// STB_LOCAL binding, its section index is SHN_ABS, and it precedes
    /// the other STB_LOCAL symbols for the file, if it is present.
    File,

    /// 5, The symbol labels an uninitialized common block
    Common,

    /// 6, The symbol specifies a Thread-Local Storage entity.
    TLS,

    OS(u8),

    Proc(u8),
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SymVisi {
    Default = 0,
    Internal,
    Hidden,
    Protected,
}

#[derive(Debug, Clone, Copy)]
pub enum SymValue {
    Alignment(u64),
    SectionOffset(u64),
    VirAddr(Hex64)
}

#[derive(Clone)]
pub struct SymTab(pub(crate) Vec<SymView>);



////////////////////////////////////////////////////////////////////////////////
//// Debug Implements

impl Debug for Hex64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:04x}", &self.0)
    }
}


impl Debug for MagicNums {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:0x}, {:0x}, {:0x}, {:0x}",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
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
            flags.push(PFlagBit::OS(os_spec))
        }

        if proc_spec > 0 {
            flags.push(PFlagBit::Proc(proc_spec));
        }

        PFLAGS(flags)
    }
}

impl Debug for E64Phdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ptype: PhType = unsafe { std::mem::transmute(self.ty()) };
        let flags = PFLAGS::from(self.flags());

        f.debug_struct("E64Phdr")
            .field("ty", &ptype)
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
                writeln!(f, "{}: {:?}", i, entry)?;
            }
            Ok(())
        } else {
            write!(f, "None")
        }
    }
}

impl From<u32> for SHType {
    fn from(val: u32) -> Self {
        if val >= 0x6000_0000 && val <= 0x6fff_ffff {
            SHType::SPECOS(val)
        } else if val >= 0x7000_0000 && val <= 0x7fff_ffff {
            SHType::SPECPROC(val)
        } else if val >= 0x8000_0000 {
            SHType::SPECUSER(val)
        } else {
            unsafe { transmute::<u64, Self>(val as u64) }
        }
    }
}

impl From<u32> for SHFLAGS {
    fn from(val: u32) -> Self {
        let mut flags = vec![];

        if val & 0b1u32 > 0 {
            flags.push(SHFlagBit::Write);
        }

        if val & 0b10u32 > 0 {
            flags.push(SHFlagBit::Alloc)
        }

        if val & 0b100u32 > 0 {
            flags.push(SHFlagBit::ExecInstr)
        }

        if val & 0b1_0000u32 > 0 {
            flags.push(SHFlagBit::Merge)
        }

        if val & 0b10_0000u32 > 0 {
            flags.push(SHFlagBit::StringS)
        }

        if val & 0b100_0000u32 > 0 {
            flags.push(SHFlagBit::InfoLink)
        }

        if val & 0b1000_0000u32 > 0 {
            flags.push(SHFlagBit::LinkOrder)
        }

        if val & 0b1_0000_0000u32 > 0 {
            flags.push(SHFlagBit::OsNonconforming)
        }

        if val & 0b10_0000_0000u32 > 0 {
            flags.push(SHFlagBit::Group)
        }

        if val & 0b100_0000_0000u32 > 0 {
            flags.push(SHFlagBit::TLS)
        }

        let os_spec = (val & 0x0ff0_0000) as u8;
        let proc_spec = (val & 0xf000_0000) as u8;

        if os_spec > 0 {
            flags.push(SHFlagBit::OS(os_spec))
        }

        if proc_spec > 0 {
            flags.push(SHFlagBit::Proc(proc_spec));
        }

        SHFLAGS(flags)
    }
}

impl Debug for SHEntries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return write!(f, "None");
        }

        writeln!(f)?;
        for (i, entry) in self.0.iter().enumerate() {
            writeln!(f, "{}: {:?}", i, entry)?;
        }

        Ok(())
    }
}

impl Debug for StrTab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;

        for (i, s) in self.str_vec().into_iter().enumerate() {
            writeln!(f, "{}: {}", i, s)?;
        }
        Ok(())
    }
}

impl From<u16> for SID {
    fn from(val: u16) -> Self {
        match val {
            0 => SID::Undef,
            0xfff1 => SID::Abs,
            0xfff2 => SID::Common,
            0xffff => SID::XIndex,
            x => {
                if x >= 0xff00 && x <= 0xff1f {
                    SID::Proc(x)
                } else if x >= 0xff20 && x <= 0xff3f {
                    SID::OS(x)
                } else {
                    SID::Normal(x)
                }
            }
        }
    }
}

impl Into<usize> for SID {
    fn into(self) -> usize {
        match self {
            SID::Undef => 0,
            SID::Proc(x) => x as usize,
            SID::OS(x) => x as usize,
            SID::Abs => 0xfff1,
            SID::Common => 0xfff2,
            SID::XIndex => 0xffff,
            SID::Normal(x) => x as usize,
        }
    }
}


impl Into<EHdrView> for E64Hdr {
    fn into(self) -> EHdrView {
        let ident = self.ident().into();
        let ty: EType = unsafe { std::mem::transmute(self.ty()) };
        let machine: EMachine = unsafe { std::mem::transmute(self.machine()) };
        let section_str_tab_idx = self.sh_strtab_idx().into();

        EHdrView {
            ident,
            ty,
            machine,
            version: self.version(),
            entry: Hex64(self.entry()),
            prog_hdr_offset: Hex64(self.phoff()),
            section_hdr_offset: Hex64(self.shoff()),
            flags: self.flags(),
            elf_hdr_sz: self.ehsize(),
            prog_hdr_tab_ent_sz: self.ph_tab_entry_size(),
            prog_hdr_tab_ent_num: self.ph_tab_entry_num(),
            section_hdr_ent_sz: self.sh_tab_entry_size(),
            section_hdr_ent_num: self.sh_tab_entry_num(),
            section_str_tab_idx,
        }
    }
}

impl SHEntries {
    pub fn get(&self, name: &str) -> Option<&SHdrView> {
        for entry in self.0.iter() {
            if entry.name() == name {
                return Some(entry);
            }
        }

        None
    }
}

impl SymBinding {
    pub fn load_from_info(info: u8) -> Self {
        let val = info >> 4;

        match val {
            0 => Self::Local,
            1 => Self::Global,
            2 => Self::Weak,
            x => {
                if 10 <= x && x <= 12 {
                    Self::OS(x)
                } else {
                    Self::Proc(x)
                }
            }
        }
    }
}

impl SymType {
    pub fn load_from_info(info: u8) -> Self {
        let val = info & 0xf;

        match val {
            0 => Self::NoType,
            1 => Self::Object,
            2 => Self::Func,
            3 => Self::Section,
            4 => Self::File,
            5 => Self::Common,
            6 => Self::TLS,
            x => {
                if 10 <= x && x <= 12 {
                    Self::OS(x)
                } else {
                    Self::Proc(x)
                }
            }
        }
    }
}

impl SymVisi {
    pub fn load_from_other(other: u8) -> Self {
        let val = other & 0x3;

        unsafe { std::mem::transmute(val) }
    }
}

impl Debug for SymTab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        for (i, entry) in self.0.iter().enumerate() {
            writeln!(f, "{}: {:?}", i, entry)?;
        }

        Ok(())
    }
}
