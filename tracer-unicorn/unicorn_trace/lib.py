from enum import IntEnum
from typing import Dict, List, Optional, Tuple
from io import BytesIO, IOBase, UnsupportedOperation
from unicorn import *
import struct

MAGIC_BYTES = b"\x65\x78\x00\x3c\x7f"

class RecordKind(IntEnum):
    MAGIC = 0xf0
    ARCH = 0x00
    FILE_META = 0x04
    MAP = 0x10
    UNMAP = 0x1c
    INSTRUCTION = 0x20
    PC = 0x24
    META = 0x30
    INTERRUPT = 0x38
    REG_READ = 0x40
    REG_WRITE = 0x44
    REG_WRITE_NATIVE = 0x54
    MEM_READ = 0x80
    MEM_WRITE = 0x84

RecordKind.MAGIC.__doc__ = """Record type used to identify the file as a trace."""
RecordKind.ARCH.__doc__ = """Record type used to specify the architecture of the program being
traced."""
RecordKind.FILE_META.__doc__ = """Record type used to provide meta data that applies to the entire
trace."""
RecordKind.MAP.__doc__ = """Record type that indicates that a new region of memory has been mapped
in."""
RecordKind.UNMAP.__doc__ = """Record type that indicates that a region of memory has been unmapped.
"""
RecordKind.INSTRUCTION.__doc__ = """Record type that indicates that an instruction has been
executed."""
RecordKind.PC.__doc__ = """Record type that indicates that a new instruction has been fetched."""
RecordKind.META.__doc__ = """Record type that provides metadata to the following record(s)."""
RecordKind.REG_READ.__doc__ = """Record type that indicates that a register has been read from."""
RecordKind.REG_WRITE.__doc__ = """Record type that indicates that a register has been written to."""
RecordKind.REG_WRITE_NATIVE.__doc__ = """Record type that indicates that a register has been written
to using the register number provided by the RegisterNameMap record."""
RecordKind.MEM_READ.__doc__ = """Record type that indicates that a memory address has been read
from."""
RecordKind.MEM_WRITE.__doc__ = """Record type that indicates that a memory address has been written
to."""

    #ThreadMetaTag = 0x01




def u8(val: int) -> bytes:
    return struct.pack("<B", val)

def u16(val: int) -> bytes:
    return struct.pack("<H", val)

def u32(val: int) -> bytes:
    return struct.pack("<I", val)

def u64(val: int) -> bytes:
    return struct.pack("<Q", val)

def calculate_vlen_rlen(sz: int) -> Tuple[bytes, bytes]:
    if sz < (0xff - 1):
        return (u8(sz + 1), u8(1 + 1 + sz))
    elif (0xff - 1) <= sz < (0xffff - 4):
        return (u16(sz + 4 + 1), u32(1 + 2 + sz) + b"\x00")
    elif (0xffff - 4) <= sz < (0xffff_ffff - 4):
        return (u32(sz + 4 + 1), u32(1 + 4 + sz) + b"\x00")
    else:
        raise RuntimeError("Data is too large for record")

def vlenlen_to_lenlen(v: int) -> int:
    return ((v - (v >> 2)) & 0b0000_0011)

class Arch:
    """Base class for providing architecture-specific information"""

    REGISTER_NAMES: Dict[int, str] = {}
    TRACKED_REGISTERS: List[Tuple[int, str]] = []
    ARCH_ID: int = 0
    VARFMT = ""

    def arch_id(self) -> int:
        """
        Return the architecture-specific identifier.

        :return: Integer that is unique to each architecture.
        """
        return self.ARCH_ID

    def dump_registers(self, emu: Uc) -> List[Tuple[int, bytes]]:
        """
        Return the current value of each tracked register.

        :param emu: **unicorn** instance with a matching architecture.
        :return: List of tracked register numbers and their corresponding current values.
        """
        return [
            (regnum, struct.pack(fmt, emu._trace_orig_reg_read(regnum)))
            for (regnum, fmt) in self.TRACKED_REGISTERS
        ]

    def emit_varfmt(self, v: int) -> bytes:
        """
        Convert an integer into an architecture-specific format.

        :param v: Value (usually an address) to be encoded.
        :return: Encoded result based on the architecture's endianness and address size.
        """
        return struct.pack(self.VARFMT, v)

    def regmap(self) -> Dict[int, str]:
        """
        Return the mapping from unicorn register number to friendly name.

        :return: Dictionary mapping unicorn register numbers to register names.
        """
        return self.REGISTER_NAMES

    def install_additional_before_hooks(self, emu: Uc, trace: "Trace"):
        """
        Install additional hooks immediately before the first set of hooks installed by the trace.

        :param emu: **unicorn** instance that is being traced
        :param trace: Program execution trace instance
        """
        pass

    def install_additional_after_hooks(self, emu: Uc, trace: "Trace"):
        """
        Install additional hooks immediately after the last set of hooks installed by the trace.

        :param emu: **unicorn** instance that is being traced
        :param trace: Program execution trace instance
        """
        pass


def emit_le32(v: int) -> bytes:
    struct.pack("<I", v)

def emit_le64(v: int) -> bytes:
    struct.pack("<Q", v)

def emit_be32(v: int) -> bytes:
    struct.pack(">I", v)

def emit_be64(v: int) -> bytes:
    struct.pack(">Q", v)

class Trace:
    """
    A class for managing program execution traces.

    :param arch: The CPU architecture of the emulator associated with this trace
    :output: Optional destination for the trace data (defaults to an in-memory buffer).
    """
    
    """
    Attributes
    ----------
    state : dict
        a collection of information about the state of the emulator between callbacks
    arch : Arch
        the cpu architecture of the emulator associated with this trace
    output : IOBase
        the destination of the trace data, can be a file or in-memory buffer
    """

    

    def __init__(self, arch: Arch, output: Optional[IOBase] = None):
        self.state = {}
        self.arch = arch
        if output is not None:
            self.output = output
        else:
            self.output = BytesIO()

        self.write_record(RecordKind.MAGIC, MAGIC_BYTES)
        self.write_record(RecordKind.ARCH, u32(self.arch.arch_id()))
        self.emit_regmap()

    def emit_pc(self, pc: int):
        """
        Emit a Pc (instruction fetched) record.

        :param pc: Program counter for the instruction that was fetched
        """
        self.write_record(RecordKind.PC, self.arch.emit_varfmt(pc))

    def emit_regmap(self):
        """
        Emit a series of RegisterNameMap records.

        .. note::
        
            A RegisterNameMap record has a maximum count of 255, so architectures with very large
            register sets will emit multiple RegisterNameMap records.
        """
        regmap = list(self.arch.regmap().items())
        for i in range(0, len(regmap), 255):
            chunk = regmap[i:i+255]
            b = b"\x00" + u8(len(chunk))
            for (regnum, regname) in chunk:
                b += u16(regnum) + u8(len(regname)) + regname.encode()
            self.write_record(RecordKind.FILE_META, b)

    def emit_ins(self, pc: int, insbytes: bytes):
        """
        Emit an Instruction (instruction executed/retired) record.

        :param pc: Program counter for the instruction that was most recently retired
        :param insbytes: Instruction bytes for the instruction that was most recently retired
        """
        self.write_record(RecordKind.INSTRUCTION, self.arch.emit_varfmt(pc) + insbytes)

    def emit_mem_write(self, addr: int, contents: bytes):
        """
        Emit a series of MemWrite records.

        .. note::
        
            To avoid a potential issue with record length calculations, MemWrite records have a
            maximum size of 4096 bytes. If a larger memory write event occurs, it will be broken ip
            into multiple records.

        :param addr: Memory address that was written to.
        :param contents: Bytes that were written.
        """
        for i in range(0, len(contents), 4096):
            rec = self.arch.emit_varfmt(addr + i) + contents[i:i+4096]
            self.write_record(RecordKind.MEM_WRITE, rec)

    def emit_mem_read(self, addr: int, contents: bytes):
        """
        Emit a series of MemRead records.

        .. note::
        
            To avoid a potential issue with record length calculations, MemRead records have a
            maximum size of 4096 bytes. If a larger memory read event occurs, it will be broken ip
            into multiple records.

        :param addr: Memory address that was read from.
        :param contents: Bytes that were read.
        """
        for i in range(0, len(contents), 4096):
            rec = self.arch.emit_varfmt(addr + i) + contents[i:i+4096]
            self.write_record(RecordKind.MEM_READ, rec)

    def emit_reg_write_native(self, regnum: int, value: bytes):
        """Emit a  RegWriteNative (native == unicorn register numbering) record."""
        self.write_record(RecordKind.REG_WRITE_NATIVE, u16(regnum) + value)

    def install_before_hooks(self, emu: Uc):
        """
        Install hooks for tracing

        .. note::
        
            In order to maintain consistency, these hooks should be installed before any other
            hook. This method also hooks API calls for reading/writing memory/registers, so these
            hooks need to be installed before any manual initialization that should be captured in
            the trace.

        :param emu: **unicorn** instance that is being traced.
        """
        emu._trace_orig_mem_write = emu.mem_write
        emu._trace_orig_mem_read = emu.mem_read
        emu._trace_orig_reg_write = emu.reg_write
        emu._trace_orig_reg_read = emu.reg_read

        self.state["regs"] = self.arch.dump_registers(emu)

        def on_mem_write(uc, access, addr: int, size: int, value: int, trace: Trace):
            try:
                buf = bytearray(size)
                for i in range(0, size):
                    buf[i] = value & 0xff
                    value >>= 8
                value = buf
            except TypeError:
                pass
            finally:
                trace.emit_mem_write(addr, value)

        def on_mem_read(uc, access, addr: int, size: int, value: int, trace: Trace):
            try:
                buf = bytearray(size)
                for i in range(0, size):
                    buf[i] = value & 0xff
                    value >>= 8
                value = buf
            except TypeError:
                pass
            finally:
                trace.emit_mem_read(addr, value)

        def on_code(uc, addr: int, size: int, trace: Trace):
            trace.diff_registers(emu=uc)

            if trace.state.get("pc") is not None and trace.state.get("inst") is not None:
                trace.emit_ins(trace.state["pc"], trace.state["inst"])
                del trace.state["pc"]
                del trace.state["inst"]

        emu.hook_add(UC_HOOK_MEM_WRITE, on_mem_write, self)
        emu.hook_add(UC_HOOK_MEM_READ_AFTER, on_mem_read, self)
        
        self.arch.install_additional_before_hooks(emu, self)
        
        emu.hook_add(UC_HOOK_CODE, on_code, self)

        def mem_write_hook(addr: int, buf: bytes):
            on_mem_write(emu, UC_MEM_WRITE, addr, len(buf), buf, self)
            return emu._trace_orig_mem_write(addr, buf)

        def mem_read_hook(addr: int, sz: int) -> bytes:
            buf = emu._trace_orig_mem_read(addr, sz)
            on_mem_read(emu, UC_MEM_READ, addr, len(buf), buf, self)
            return buf

        def reg_write_hook(regnum: int, value: int):
            retval = emu._trace_orig_reg_write(regnum, value)
            self.diff_registers(emu=emu)
            return retval

        emu.mem_write = mem_write_hook
        emu.mem_read = mem_read_hook
        emu.reg_write = reg_write_hook


    def install_after_hooks(self, emu: Uc):
        """
        Install hooks for tracing

        .. note::
        
            In order to maintain consistency, these hooks should be installed after all other
            hooks.

        :param emu: **unicorn** instance that is being traced.
        """
        def on_code(uc: Uc, addr: int, size: int, trace: Trace):
            inst = uc._trace_orig_mem_read(addr, size)
            trace.state["pc"] = addr
            trace.state["inst"] = inst
            trace.emit_pc(addr)

        emu.hook_add(UC_HOOK_CODE, on_code, self)
        
        self.arch.install_additional_after_hooks(emu, self)

    def write_record(self, kind: RecordKind, rec: bytes):
        """
        Writes a raw record to the output.

        :param kind: Type of record to be written.
        :param rec: Record data to be written.
        """
        (vlen,rlen) = calculate_vlen_rlen(len(rec))
        self.output.write(u8(kind | vlenlen_to_lenlen(len(vlen))))
        self.output.write(vlen)
        self.output.write(rec)
        self.output.write(rlen)

    def diff_registers(self, emu: Uc):
        """
        Compares current register values with last known values, emitting records when they differ.

        :param emu: **unicorn** instance containing the current register values.
        """
        current_regs = self.arch.dump_registers(emu)
        for (i, (regnum, value)) in enumerate(current_regs):
            if self.state["regs"][i][1] != value:
                self.emit_reg_write_native(regnum, value)
        self.state["regs"] = current_regs

    def flush(self, uc: Optional[Uc] = None):
        """
        Flushes currently stored state to output and performs a register diff if uc is provided.

        :param uc: Optional **unicorn** instance to diff registers.
        """
        if uc is not None:
            self.diff_registers(uc)
        if self.state.get("pc") is not None and self.state.get("inst") is not None:
            self.emit_ins(self.state["pc"], self.state["inst"])
            del self.state["pc"]
            del self.state["inst"]
        self.output.flush()

    def contents(self) -> bytes:
        """
        Returns the contents of the in-memory trace if a file was not passed in as the output.

        :return: Contents of the in-memory buffer.
        """
        self.flush()
        if hasattr(self.output, 'getvalue'):
            return self.output.getvalue()
        raise UnsupportedOperation
