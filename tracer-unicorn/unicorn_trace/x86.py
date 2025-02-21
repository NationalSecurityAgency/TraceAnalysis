"""Architecture definitions for x86 (i386)"""

from unicorn.x86_const import *

from .lib import Arch
from . import x86_64

class X86(Arch):
    ARCH_ID = 0x20

    TRACKED_REGISTERS = [
        (UC_X86_REG_EAX, "<I"),
        (UC_X86_REG_EBP, "<I"),
        (UC_X86_REG_EBX, "<I"),
        (UC_X86_REG_ECX, "<I"),
        (UC_X86_REG_EDI, "<I"),
        (UC_X86_REG_EDX, "<I"),
        #(UC_X86_REG_EIP, "<I"),
        (UC_X86_REG_ESI, "<I"),
        (UC_X86_REG_ESP, "<I"),
    ]

    REGISTER_NAMES = x86_64.X64.REGISTER_NAMES

    VARFMT = "<I"
