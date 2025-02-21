from unicorn.mips_const import *

from . import mips
from .lib import Arch

class Mipsel(Arch):
    ARCH_ID = 0x62

    TRACKED_REGISTERS = list(map(lambda x: (x[0], "<I"), mips.Mips.TRACKED_REGISTERS))
    
    REGISTER_NAMES = mips.Mips.REGISTER_NAMES
    
    VARFMT = "<I"

