use anyhow::Result;
use trace::{record::Arch, RuntimeError};

pub fn get_reg_translate_map(arch: Arch) -> Result<&'static phf::Map<&'static str, &'static str>> {
    let map = match arch {
        Arch::X86 => &X86_REG,
        Arch::X86_64 => &X86_64_REG,
        Arch::X86_64Compat32 => &X86_64_REG, // TODO: double check this
        Arch::PowerPc => &PPC_BE_32_REG,
        Arch::PowerPc64 => &PPC_BE_64_REG,
        Arch::Arm => &ARM32_REG,
        Arch::Arm64 => &AARCH64_REG,
        Arch::M68k => todo!(),
        Arch::Mips => todo!(),
        Arch::Mips64 => todo!(),
        Arch::Mipsel => todo!(),
        Arch::Mipsel64 => todo!(),
        Arch::Sparc => todo!(),
        Arch::Sparc64 => todo!(),
        Arch::RiscV => todo!(),
        Arch::RiscV64 => todo!(),
        Arch::Unknown(_) => {
            return Err(RuntimeError::UnknownArch)?;
        }
    };
    Ok(map)
}

mod x86;
pub use x86::X86_REG;

mod x86_64;
pub use x86_64::X86_64_REG;

mod aarch64;
pub use aarch64::AARCH64_REG;

mod arm32;
pub use arm32::ARM32_REG;

mod ppc_32_be;
pub use ppc_32_be::PPC_BE_32_REG;

mod ppc_64_be;
pub use ppc_64_be::PPC_BE_64_REG;
