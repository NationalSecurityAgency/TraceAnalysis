use std::{
    fs::File,
    io::{BufWriter, Write},
    sync::{Mutex, OnceLock},
};

use trace::{
    record::{emit_be32, emit_be64, emit_le32, emit_le64, Record, ThreadId},
    Arch,
};

static TRACE_FILE: OnceLock<Mutex<TraceFile>> = OnceLock::new();

pub struct TraceFile {
    writer: BufWriter<File>,
    record: Vec<u8>,
    varfmt: fn(u64, &mut [u8]) -> &[u8],
    last_tid: i32,
}

impl TraceFile {
    pub fn write(&mut self, record: Record) {
        record.emit(&mut self.record, self.varfmt);
        if self.writer.write(self.record.as_slice()).is_err() {
            tracing::error!("failed to write record to trace file");
            panic!()
        }
        self.record.clear();
    }

    pub fn last_tid(&self) -> i32 {
        self.last_tid
    }
}

pub(crate) fn initialize(file: File, arch: Arch) {
    TRACE_FILE.get_or_init(move || {
        let varfmt = match arch {
            Arch::X86 => emit_le32,
            Arch::X86_64 => emit_le64,
            Arch::X86_64Compat32 => emit_le64,
            Arch::PowerPc => emit_be32,
            Arch::PowerPc64 => emit_be64,
            Arch::Arm => emit_le32,
            Arch::Arm64 => emit_le64,
            Arch::M68k => emit_be32,
            Arch::Mips => emit_be32,
            Arch::Mips64 => emit_be64,
            Arch::Mipsel => emit_le32,
            Arch::Mipsel64 => emit_le64,
            Arch::Sparc => emit_be32,
            Arch::Sparc64 => emit_be64,
            Arch::RiscV => emit_le32,
            Arch::RiscV64 => emit_le64,
            Arch::Unknown(_) => unreachable!(),
        };

        let last_tid = unsafe { libc::gettid() };

        let mut record = Vec::new();
        Record::Magic.emit(&mut record, varfmt);
        Record::Arch(arch).emit(&mut record, varfmt);
        Record::from(ThreadId::new(last_tid as _)).emit(&mut record, varfmt);

        let mut writer = BufWriter::new(file);
        writer
            .write(record.as_slice())
            .expect("failed to write to trace file");
        record.clear();

        Mutex::new(TraceFile {
            writer,
            record,
            varfmt,
            last_tid,
        })
    });
}

pub(crate) fn with<F: FnOnce(&mut TraceFile)>(f: F) {
    let Some(trace) = TRACE_FILE.get() else {
        tracing::error!("attempted to acquire trace file before initialization");
        panic!()
    };

    let Ok(mut trace) = trace.lock() else {
        tracing::error!("trace file lock is poisoned");
        panic!()
    };

    f(&mut *trace)
}
