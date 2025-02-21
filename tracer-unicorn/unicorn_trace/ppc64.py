from unicorn.ppc_const import *

from .lib import Arch
from . import ppc

class Ppc64(Arch):
    ARCH_ID = 0x11
    
    TRACKED_REGISTERS = list(map(lambda x: (x[0], ">Q"), ppc.Ppc.TRACKED_REGISTERS))

    REGISTER_NAMES = ppc.Ppc.REGISTER_NAMES
    
    VARFMT = ">Q"

