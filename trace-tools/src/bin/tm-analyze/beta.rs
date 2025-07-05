use anyhow::Result;
use dataflow::{lifter::GhidraLifter, prelude::Architecture};
use trace::{reader::{cont, try_break, TraceReader}, record::{parse_unknown, Record}, RuntimeError};
use std::{io::Read, ops::ControlFlow};

pub fn analyze(input: Box<dyn Read>) -> Result<()> {
    let mut trace = TraceReader::new(input);

    let raw_magic_record = trace.next().ok_or(RuntimeError::MissingMagic)?;
    if Record::Magic != raw_magic_record.parse(parse_unknown)? {
        return Err(RuntimeError::MissingMagic)?;
    }
    
    let raw_arch_record = trace.next().ok_or(RuntimeError::MissingArch)?;
    // NOTE: 'arch' variable gets assigned here!
    let Record::Arch(arch) = raw_arch_record.parse(parse_unknown)? else {
        return Err(RuntimeError::MissingArch)?;
    };

    // Setup ghidra lifter for looking up native register names
    let df_arch: Architecture = match arch {
        trace::Arch::X86 => dataflow::architecture::X86.into(),
        trace::Arch::X86_64 => dataflow::architecture::X86_64.into(),
        trace::Arch::X86_64Compat32 => dataflow::architecture::X86_64Compat32.into(),
        trace::Arch::PowerPc => dataflow::architecture::PPCBE32.into(),
        trace::Arch::PowerPc64 => anyhow::bail!("dataflow does not currently support PPC64"),
        trace::Arch::Arm => dataflow::architecture::ARM32.into(),
        trace::Arch::Arm64 => dataflow::architecture::AARCH64.into(),
        trace::Arch::M68k => dataflow::architecture::M68K.into(),
        trace::Arch::Mips => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Mips64 => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Mipsel => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Mipsel64 => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Sparc => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Sparc64 => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::RiscV => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::RiscV64 => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Unknown(n) => anyhow::bail!("unknown architecture: {n}"),
    };
    let _ghidra_lifter = GhidraLifter::new(df_arch)?;

    let mut tick = 0u64;
    
    trace.for_each(|raw| {
        if tick >= 50_000 {
            return ControlFlow::Break(anyhow::anyhow!("done"));
        }
        let record = try_break!(arch.parse_record(raw));
        match record {
            Record::Instruction(ins) => {
                println!("{:#x?}", ins.pc());
                tick += 1;
            }
            _ => {}
        }
        cont!();
    }).map_or(Ok(()), |err| Err(err.into()))
}
