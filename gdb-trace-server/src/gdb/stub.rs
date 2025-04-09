use trace::index::spacetime_index::SpacetimeRTree;

use gdbstub::arch::Arch;
use gdbstub::stub::BaseStopReason;
use gdbstub::target::ext::base::reverse_exec::{
    ReverseCont, ReverseContOps, ReverseStep, ReverseStepOps,
};
use gdbstub::target::ext::base::singlethread::SingleThreadBase;
use gdbstub::target::ext::base::singlethread::{SingleThreadResume, SingleThreadResumeOps};
use gdbstub::target::ext::base::singlethread::{SingleThreadSingleStep, SingleThreadSingleStepOps};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::breakpoints::{Breakpoints, BreakpointsOps};
use gdbstub::target::ext::breakpoints::{SwBreakpoint, SwBreakpointOps};
use gdbstub::target::{Target, TargetError, TargetResult};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::mappings;

enum ExecMode {
    Contiunue,
    Step,
    ReverseContinue,
    ReverseStep,
}

impl Default for ExecMode {
    fn default() -> Self {
        ExecMode::Contiunue
    }
}

// TODO: Rename trait to something like SpacetimeAwareTarget? This
// trait is supposed to say, you support reading/writing registers
// if you give me a reg_space (SpacetimeRTree) and a point in time
// (Tick|u64) then I can give you back register values in an arch
// specific way.
pub trait DynamicTarget {
    type Arch: Arch;
    fn new() -> Self;
    fn read_registers(
        &self,
        reg_space: &mut SpacetimeRTree,
        tick: u64,
        pc: u64,
        regs: &mut <Self::Arch as Arch>::Registers,
    );
    fn write_registers(
        &self,
        reg_space: &mut SpacetimeRTree,
        tick: u64,
        regs: &<Self::Arch as Arch>::Registers,
    );
}

pub struct TraceState<T: DynamicTarget> {
    current_tick: u64,
    pc_ticks_map: HashMap<u64, BTreeSet<u64>>,
    tick_pc_map: BTreeMap<u64, u64>,
    reg_space: SpacetimeRTree,
    mem_space: SpacetimeRTree,
    vmem: Vec<(u64, Vec<u8>)>,
    breakpoints: BTreeSet<u64>,
    target: T,
    exec_mode: ExecMode,
}

impl<T: DynamicTarget> TraceState<T> {
    // TODO: switch to the builder pattern?
    pub fn new(
        pc_ticks_map: HashMap<u64, BTreeSet<u64>>,
        tick_pc_map: BTreeMap<u64, u64>,
        reg_space: SpacetimeRTree,
        mem_space: SpacetimeRTree,
        maps_file: String,
        sysroot: String,
    ) -> Self {
        // TODO: Convert this to only taking in the index/trace file

        // TODO: This should take a sysroot + maps and open up the files and things.
        tracing::info!("Parsing mappings file: {maps_file}");
        let parsed_mappings = match mappings::parse_mappings_from_sysroot(maps_file) {
            Ok(mappings) => mappings,
            Err(e) => {
                tracing::error!("{e}");
                tracing::warn!("Proceeding without loading any mapped in libraries!");
                Vec::new()
            }
        };

        let sysroot = std::path::PathBuf::from(sysroot);
        tracing::debug!("Sysroot Base (before loop): {}", sysroot.display());

        let mut vmem = Vec::with_capacity(parsed_mappings.len() * 4); // 4: .text, .data, .bss, .rodata
        for mapping in parsed_mappings.iter() {
            tracing::debug!("Parsed from maps file: {mapping:0x?}");

            let sysroot_path = sysroot
                .clone()
                .join(match mapping.path().strip_prefix("/") {
                    Ok(path) => path,
                    Err(_) => mapping.path(), // TODO: better way to not call m.path() here again?
                }); // TODO: better way to do this in a the loop?
            tracing::debug!("Sysroot Base: {}", sysroot_path.display());

            let buffer = match std::fs::read(&sysroot_path) {
                Ok(buffer) => buffer,
                Err(e) => {
                    tracing::warn!("Couldn't read file '{}': {e:?}", sysroot_path.display());
                    continue;
                }
            };

            let elf = match goblin::Object::parse(&buffer) {
                Ok(goblin::Object::Elf(elf)) => elf,
                Ok(_) => {
                    tracing::warn!(
                        "File type not supported when loading {}",
                        sysroot_path.display()
                    );
                    continue;
                }
                Err(e) => {
                    tracing::error!("Unable to parse '{}': {e}", sysroot_path.display());
                    continue;
                }
            };

            // Calculate load address and add them to `vmem`
            let loadable_segments = elf
                .program_headers
                .iter()
                .filter_map(|phdr| match phdr.p_type {
                    goblin::elf::program_header::PT_LOAD => Some(phdr),
                    _ => None,
                })
                .collect::<Vec<&goblin::elf::ProgramHeader>>();

            if loadable_segments.len() == 0 {
                tracing::debug!("No PT_LOAD headers in '{}'!", sysroot_path.display());
                continue;
            }

            let static_base_addr = loadable_segments[0].p_vaddr;
            let dynami_base_addr = mapping.base();
            for phdr in loadable_segments {
                let segment_addr = phdr.p_vaddr - static_base_addr + dynami_base_addr;

                let mut segment_data: Vec<u8> = Vec::with_capacity(phdr.p_memsz as usize);
                let (start, end) = (
                    phdr.p_offset as usize,
                    phdr.p_offset as usize + phdr.p_filesz as usize,
                );
                segment_data.extend_from_slice(&buffer[start..end]);

                // p_memsz will never be less than p_filesz. If greater, then the extra space
                // is defined to be all zeros:
                //  - https://man7.org/linux/man-pages/man5/elf.5.html
                if phdr.p_memsz > phdr.p_filesz {
                    segment_data.extend_from_slice(&vec![
                        0;
                        phdr.p_memsz as usize
                            - phdr.p_filesz as usize
                    ]);
                }

                vmem.push((segment_addr, segment_data));
            }
        }

        Self {
            pc_ticks_map,
            tick_pc_map,
            reg_space,
            mem_space,
            vmem,
            // Start at 1 because tick 0 should represent time before the trace started.
            current_tick: 1,
            breakpoints: Default::default(),
            target: T::new(),
            exec_mode: Default::default(),
        }
    }

    pub fn run(&mut self) -> MyTargetEvent<T> {
        // NOTE: For the BaseStopReason::SwBreak(()) returned below, the inner empty set
        // '()' represents the current thread since we are single threaded. Handling multiple
        // threads will require a larger refactor probably..
        match self.exec_mode {
            ExecMode::Contiunue => {
                let next_bp = self.breakpoints.iter().find(|bp| self.current_tick < **bp);
                match next_bp {
                    Some(bp) => {
                        self.current_tick = *bp;
                        MyTargetEvent::StopReason(BaseStopReason::SwBreak(()))
                    }
                    None => {
                        // There isn't a breakpoint that will get hit after the current
                        // tick so we just go to the end of the trace.
                        let Some((last_tick, _)) = self.tick_pc_map.last_key_value() else {
                            unreachable!()
                        };
                        self.current_tick = *last_tick;
                        MyTargetEvent::StopReason(BaseStopReason::Signal(
                            gdbstub::common::Signal::SIGUSR1,
                        ))
                    }
                }
            }
            ExecMode::Step => {
                let Some((last_tick, _)) = self.tick_pc_map.last_key_value() else {
                    unreachable!()
                };
                self.current_tick = std::cmp::min(self.current_tick + 1, *last_tick);
                MyTargetEvent::StopReason(BaseStopReason::DoneStep)
            }
            ExecMode::ReverseContinue => {
                let prev_bp = self
                    .breakpoints
                    .iter()
                    .rev()
                    .find(|bp| **bp < self.current_tick);
                match prev_bp {
                    Some(bp) => {
                        self.current_tick = *bp;
                        MyTargetEvent::StopReason(BaseStopReason::SwBreak(()))
                    }
                    None => {
                        // There isn't a breakpoing before the current tick so we will just
                        // go to the start of the trace.
                        let Some((first_tick, _)) = self.tick_pc_map.first_key_value() else {
                            unreachable!()
                        };
                        self.current_tick = *first_tick;
                        MyTargetEvent::StopReason(BaseStopReason::Signal(
                            gdbstub::common::Signal::SIGUSR1,
                        ))
                    }
                }
            }
            ExecMode::ReverseStep => {
                let Some((first_tick, _)) = self.tick_pc_map.first_key_value() else {
                    unreachable!()
                };
                self.current_tick = std::cmp::max(self.current_tick - 1, *first_tick);
                MyTargetEvent::StopReason(BaseStopReason::DoneStep)
            }
        }
    }

    pub fn interrupt(&mut self) {
        todo!()
    }

    // TODO: Maybe instead of creating a new Vec<u8> here we could just return a
    // Box<[u8]> which the caller could copy_from_slice() with?
    pub fn read_from_addr(&self, addr: u64, len: usize) -> Result<Vec<u8>, TraceTargetError> {
        let (segment_start, bytes) = self
            .vmem
            .iter()
            .find(|(segment_start, bytes)| {
                let start = *segment_start;
                // FIXME: "(*segment_start as usize) + bytes.len()" is not compiling for me!
                let mut end = *segment_start as usize;
                end += bytes.len();
                start <= addr && (addr as usize) < end
            })
            .ok_or(TraceTargetError::InvalidMemoryLocation(addr))?;
        tracing::debug!(
            "Found loaded segment containing address! (0x{:08x} - 0x{:08x})",
            segment_start,
            bytes.len(),
        );

        let start = (addr - segment_start) as usize;

        let segment_end = *segment_start as usize + bytes.len();
        let addr_end = addr as usize + len;
        let end = std::cmp::min(addr_end, segment_end) - *segment_start as usize;

        let mut data = vec![0; end - start];
        data.copy_from_slice(&bytes[start..end]);
        Ok(data)
    }
}

pub enum MyTargetEvent<T: DynamicTarget> {
    StopReason(BaseStopReason<(), <<T as DynamicTarget>::Arch as Arch>::Usize>),
}

#[derive(thiserror::Error, Debug)]
pub enum TraceTargetError {
    #[error("unable to read memory from location 0x{0:08x}")]
    InvalidMemoryLocation(u64),
    #[error("unknown trace server error")]
    Unknown,
}

impl From<TraceTargetError> for TargetError<TraceTargetError> {
    fn from(value: TraceTargetError) -> Self {
        match value {
            // TODO: Arch specific error code 11 is maybe 'Page Fault'?
            // See https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=gdb/stubs/i386-stub.c;h=74fe4767c8315cd83468a30db6c1b9859af7e790;hb=HEAD
            // TraceTargetError::InvalidMemoryLocation(_) => Self::Errno(11),
            _ => {
                tracing::debug!("TraceTargetError: {}", value);
                Self::NonFatal
            }
        }
    }
}

impl<T: DynamicTarget> Target for TraceState<T> {
    type Arch = <T as DynamicTarget>::Arch;
    type Error = TraceTargetError;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    // Support for breakpoints
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }
}

impl<T: DynamicTarget> SingleThreadBase for TraceState<T> {
    fn read_registers(
        &mut self,
        regs: &mut <T::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        let pc = self.tick_pc_map.get(&self.current_tick).expect(&format!(
            "Should not happen! No pc associated with tick: {}",
            self.current_tick
        ));
        self.target
            .read_registers(&mut self.reg_space, self.current_tick, *pc, regs);
        Ok(())
    }

    fn write_registers(&mut self, regs: &<T::Arch as Arch>::Registers) -> TargetResult<(), Self> {
        self.target
            .write_registers(&mut self.reg_space, self.current_tick, regs);
        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: <T::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let addr_start: u64 = num_traits::cast(start_addr).unwrap();
        tracing::debug!("Reading {} bytes from 0x{addr_start:08X}", data.len());

        // Read from spacetime index:
        let blocks = self.mem_space.find(
            self.current_tick,
            addr_start,
            (addr_start as usize + data.len()) as u64,
        );

        if blocks.len() > 0 {
            for block in blocks {
                tracing::trace!(
                    "Block: {:?} {:?} - {:?}",
                    block.address,
                    block.len,
                    block.data
                );
            }
            // TODO: parse block information to actual data
            data.fill(0);
            return Ok(data.len());
        }

        // Search through loaded libraries for address if not found in
        // spacetime index
        let bytes = self.read_from_addr(addr_start, data.len())?;
        data.copy_from_slice(&bytes);
        Ok(bytes.len())

        // NOTE: We return bytes.len() above in case the amount of bytes we read
        // ended up being smaller than what was asked for.
    }

    fn write_addrs(
        &mut self,
        _start_addr: <T::Arch as Arch>::Usize,
        _data: &[u8],
    ) -> TargetResult<(), Self> {
        // NOTE: We do not write any data becuase this is a static trace.
        Ok(())
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<Self>> {
        Some(self)
    }
}

impl<T: DynamicTarget> SingleThreadResume for TraceState<T> {
    fn resume(&mut self, signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
        if let Some(signal) = signal {
            tracing::debug!("Received signal: {signal}");
        }

        self.exec_mode = ExecMode::Contiunue;
        Ok(())
    }

    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<Self>> {
        Some(self)
    }

    fn support_reverse_step(&mut self) -> Option<ReverseStepOps<(), Self>> {
        Some(self)
    }

    fn support_reverse_cont(&mut self) -> Option<ReverseContOps<(), Self>> {
        Some(self)
    }
}

impl<T: DynamicTarget> Breakpoints for TraceState<T> {
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<Self>> {
        Some(self)
    }
}

impl<T: DynamicTarget> SwBreakpoint for TraceState<T> {
    fn add_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        let addr = num_traits::cast(addr).unwrap();
        tracing::debug!("Setting breakpoint at 0x{addr:08X}");
        match self.pc_ticks_map.get(&addr) {
            Some(tick_set) => {
                for tick in tick_set {
                    self.breakpoints.insert(*tick);
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        let addr = num_traits::cast(addr).unwrap();
        tracing::debug!("Removing breakpoint at 0x{addr:08X}");
        match self.pc_ticks_map.get(&addr) {
            Some(tick_set) => {
                for tick in tick_set {
                    if !self.breakpoints.remove(tick) {
                        // TODO: tracing::warn!("Did not remove a tick ({tick}) from the set!")
                        // This means the tick wasn't present in the set (which should never happen)
                    }
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl<T: DynamicTarget> SingleThreadSingleStep for TraceState<T> {
    fn step(&mut self, signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
        if let Some(signal) = signal {
            tracing::debug!("Received signal: {signal}");
        }
        self.exec_mode = ExecMode::Step;
        Ok(())
    }
}

impl<T: DynamicTarget> ReverseStep<()> for TraceState<T> {
    fn reverse_step(&mut self, _tid: ()) -> Result<(), Self::Error> {
        self.exec_mode = ExecMode::ReverseStep;
        Ok(())
    }
}

impl<T: DynamicTarget> ReverseCont<()> for TraceState<T> {
    fn reverse_cont(&mut self) -> Result<(), Self::Error> {
        self.exec_mode = ExecMode::ReverseContinue;
        Ok(())
    }
}
