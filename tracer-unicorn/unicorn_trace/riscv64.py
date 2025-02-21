from unicorn.riscv_const import *

from . import riscv32
from .lib import Arch

class Riscv64(Arch):
    ARCH_ID = 0x71

    TRACKED_REGISTERS = list(map(lambda x: (x[0], '<Q'), riscv32.Riscv32.TRACKED_REGISTERS))

    REGISTER_NAMES = riscv32.Riscv32.REGISTER_NAMES

    VARFMT = "<Q"
