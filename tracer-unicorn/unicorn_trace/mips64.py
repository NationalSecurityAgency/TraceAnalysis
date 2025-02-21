from unicorn.mips_const import *

from . import mips
from .lib import Arch

class Mips64(Arch):
    ARCH_ID = 0x61
    
    TRACKED_REGISTERS = list(map(lambda x: (x[0], ">Q"), mips.Mips.TRACKED_REGISTERS))
    
    REGISTER_NAMES = mips.Mips.REGISTER_NAMES
    
    VARFMT = ">Q"

