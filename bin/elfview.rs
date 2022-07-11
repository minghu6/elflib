use std::path::PathBuf;

use clap::Parser;
use clap_complete::Shell;

use elflib::Elf;

/// Bas Lang Compiler
#[derive(Parser)]
#[clap()]
struct Cli {
    /// Genrerate completion for bin
    #[clap(long = "generate", arg_enum)]
    generator: Option<Shell>,

    src: PathBuf,
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let elf = Elf::load(cli.src)?;

    println!("{:#?}", elf);

    Ok(())
}
