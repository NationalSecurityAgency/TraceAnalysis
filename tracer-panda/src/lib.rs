use panda::prelude::*;

use trace::record::{
    Record,
    MemWrite,
    MemRead,
    Pc,
    Instruction,
    RegisterNameMap,
    RegWriteNative,
    ProcessId,
    ThreadId,
};

use std::sync::{OnceLock, RwLock};
use std::io::{BufWriter, Write};
use std::fs::{self, File};

pub mod arch;
use arch::RegsExt as _;

#[derive(Debug, PandaArgs)]
#[name = "tracer_panda"]
pub struct PluginArgs {
    #[arg(default = "trace.out")]
    pub out: String,
}

static TRACE: OnceLock<RwLock<Trace>> = OnceLock::new();

pub struct Trace {
    writer: BufWriter<File>,
    buffer: Vec<u8>,
    last_pc: Option<u64>,
    last_insbytes: Vec<u8>,
    last_pid: u64,
    last_tid: u32,
    last_regs: arch::Regs,
    next_regs: arch::Regs,
}

impl Drop for Trace {
    fn drop(&mut self) {
        let _ = self.writer.write_all(self.buffer.as_slice());
        let _ = self.writer.flush();
    }
}

impl Trace {
    pub fn initialize(args: &PluginArgs) -> bool {
        let Ok(file) = fs::File::options()
            .write(true)
            .create(true)
            .open(args.out.as_str()) else {
                return false;
            };

        let mut buffer = Vec::new();
        Record::Magic.emit(&mut buffer, arch::varfmt);
        Record::from(arch::ARCH).emit(&mut buffer, arch::varfmt);
        Record::from(RegisterNameMap::new(arch::Regs::register_names()
                .into_iter()
                .enumerate()
                .map(|(i, name)| (i as u16, name.as_bytes()))
        )).emit(&mut buffer, arch::varfmt);

        let _ = TRACE.set(RwLock::new(Self {
            writer: BufWriter::new(file),
            buffer,
            last_pc: None,
            last_insbytes: Vec::new(),
            last_pid: 0,
            last_tid: 0,
            last_regs: arch::Regs::new(),
            next_regs: arch::Regs::new(),
        }));

        true
    }

    pub fn flush() {
        Self::with(|trace| {
            let _ = trace.writer.write_all(trace.buffer.as_slice());
            trace.buffer.clear();
            let _ = trace.writer.flush();
        });
    }

    pub fn emit_instruction_exec(_cpu: &mut CPUState) {
        Self::with(move |trace| {
            if let Some(last_pc) = trace.last_pc.take() {
                let last_insbytes = trace.last_insbytes.as_slice();
                let record: Record = Instruction::new(last_pc, last_insbytes).into();
                record.emit(&mut trace.buffer, arch::varfmt);
                trace.last_insbytes.clear();
            }
        });
    }

    pub fn emit_instruction_fetch(cpu: &mut CPUState, pc: u64) {
        Self::with(move |trace| {
            trace.last_pc = Some(pc);
            arch::get_instruction(cpu, pc, &mut trace.last_insbytes);
            let record: Record = Pc::new(pc).into();
            record.emit(&mut trace.buffer, arch::varfmt);
            if trace.writer.write_all(&trace.buffer).is_err() {
                eprintln!("[ERROR] Failed to flush trace buffer");
                std::process::exit(1);
            }
            trace.buffer.clear();
        });
    }

    pub fn emit_reg_writes(cpu: &mut CPUState) {
        Self::with(move |trace| {
            trace.next_regs.update(cpu);
            for (regnum, regval) in trace.last_regs.diff(&trace.next_regs) {
                Record::from(RegWriteNative::new(regnum, regval)).emit(
                    &mut trace.buffer,
                    arch::varfmt
                    );
            }
            let _ = trace.writer.write_all(trace.buffer.as_slice());
            trace.buffer.clear();
            std::mem::swap(&mut trace.next_regs, &mut trace.last_regs);
        });
    }

    pub fn emit_pc(addr: u64) {
        Self::emit_record(Pc::new(addr).into())
    }

    pub fn emit_mem_write(addr: u64, data: &[u8]) {
        Self::emit_record(MemWrite::new(addr, data).into())
    }

    pub fn emit_mem_read(addr: u64, data: &[u8]) {
        Self::emit_record(MemRead::new(addr, data).into())
    }

    pub fn emit_pid_tid(cpu: &mut CPUState) {
        let pid = panda::current_asid(cpu) as u64;
        let tid = arch::current_tid(cpu);
        Self::with(move |trace| {
            if trace.last_pid != pid {
                Record::from(ProcessId::new(pid)).emit(&mut trace.buffer, arch::varfmt); 
                trace.last_pid = pid;
            }
            if trace.last_tid != tid {
                Record::from(ThreadId::new(tid)).emit(&mut trace.buffer, arch::varfmt);
                trace.last_tid = tid;
            }
            // We just buffer these records b/c it can safely be ignore if no record follows it.
        })
    }

    #[inline]
    fn emit_record(record: Record) {
        Self::with(move |trace| {
            record.emit(&mut trace.buffer, arch::varfmt);
            if trace.writer.write_all(&trace.buffer).is_err() {
                eprintln!("[ERROR] Failed to flush buffer");
                std::process::exit(1);
            }
            trace.buffer.clear();
        });
    }

    #[inline]
    fn with<F, R>(f: F) -> R
        where F: for<'a> FnOnce(&'a mut Trace) -> R
    {
        let Some(trace) = TRACE.get() else {
            // TODO: log this
            std::process::exit(1);
        };
        let Ok(mut trace) = trace.write() else {
            // TODO: log this
            std::process::exit(1);
        };
        f(&mut *trace)
    }
}

#[panda::init]
pub fn init(_: &mut PluginHandle) -> bool {
    unsafe {
        panda::sys::panda_do_flush_tb();
        panda::sys::panda_disable_tb_chaining();
        panda::sys::panda_enable_precise_pc();
        panda::sys::panda_enable_memcb();
    }
    let args = PluginArgs::from_panda_args();
    Trace::initialize(&args)
}

#[panda::virt_mem_after_read]
pub fn on_mem_read(cpu: &mut CPUState,
    _pc: target_ptr_t,
    addr: target_ptr_t,
    size: usize,
    buf: *mut u8) 
{
    Trace::emit_pid_tid(cpu);
    if buf.is_null() {
        // TODO: log this
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(buf, size) };
    Trace::emit_mem_read(addr as _, data);
}

#[panda::virt_mem_after_write]
pub fn on_mem_write(cpu: &mut CPUState,
    _pc: target_ptr_t,
    addr: target_ptr_t,
    size: usize,
    buf: *mut u8)
{
    Trace::emit_pid_tid(cpu);
    if buf.is_null() {
        // TODO: log this
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(buf, size) };
    Trace::emit_mem_write(addr as _, data);
}

#[panda::insn_exec]
pub fn on_insn(cpu: &mut CPUState, pc: target_ptr_t) {
    Trace::emit_reg_writes(cpu);
    Trace::emit_instruction_exec(cpu);
    Trace::emit_pid_tid(cpu);
    Trace::emit_instruction_fetch(cpu, pc as _);
}

#[panda::insn_translate]
pub fn enable_insn(_: &mut CPUState, _: target_ptr_t) -> bool {
    true
}

#[panda::uninit]
pub fn uninit(_: &mut PluginHandle) {
    Trace::flush();
}


#[cfg(feature = "tracer-panda-bin")]
pub fn driver(arch: panda::Arch) {
    use clap::Parser as _;
    
    let args = cli::Args::parse();
    let plugin_args = args.plugin_args();
    Panda::run_after_init(move || {
        unsafe {
            panda::sys::panda_do_flush_tb();
            panda::sys::panda_disable_tb_chaining();
            panda::sys::panda_enable_precise_pc();
            panda::sys::panda_enable_memcb();
        }
        Trace::initialize(&plugin_args);
    });
    let mut panda = Panda::new();
    panda.arch(arch);
    panda.mem(args.mem.as_str());
    panda.replay(args.replay.as_str());
    if args.graphics {
        panda.enable_graphics();
    }
    panda.args(args.additional.iter());
    panda.run();
    Trace::flush();
}

#[cfg(feature = "tracer-panda-bin")]
mod cli {
    use super::PluginArgs;

    #[derive(Debug, Clone)]
    #[derive(clap::Parser)]
    pub struct Args {
        #[arg(short, long, default_value="trace.out")]
        pub outfile: String,

        #[arg(short, long, default_value="128M")]
        #[arg(help="Amount of memory allocated to the guest (should match the recording)")]
        pub mem: String,

        #[arg(long, help="Enable graphics")]
        pub graphics: bool,

        #[arg(long, help="Name of recording to trace")]
        pub replay: String,

        #[arg(trailing_var_arg=true, allow_hyphen_values=true)]
        #[arg(help="Additional arguments to pass to PANDA/QEMU")]
        pub additional: Vec<String>,
    }

    impl Args {
        pub fn plugin_args(&self) -> PluginArgs {
            PluginArgs {
                out: self.outfile.clone()
            }
        }
    }
}
