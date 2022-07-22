#![feature(arbitrary_enum_discriminant)]

pub mod view;
pub mod data;
pub mod ctrl;

pub use crate::ctrl::Elf;


#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::Elf;

    #[test]
    fn it_works() -> Result<(), Box<dyn Error>> {
        let elf = Elf::load("./draft/arr")?;

        println!("{:#?}", elf);

        Ok(())
    }
}