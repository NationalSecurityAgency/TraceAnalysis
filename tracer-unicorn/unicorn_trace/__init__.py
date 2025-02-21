"""Library for generating program execution traces with unicorn-engine"""

__version__ = "0.1.0"
__all__ = [
        'Arch',
        'Trace',
        'RecordKind',
        'X86',
        'X64',
        'PPC',
        'PPC64',
        'ARM',
        'AARCH64',
        'MIPS',
        'MIPS64',
        'MIPSEL',
        'MIPS64EL',
        'RISCV32',
        'RISCV64'
]


from .lib import (Arch, Trace, RecordKind)
from . import x86
from . import x86_64
from . import ppc
from . import ppc64
from . import arm
from . import aarch64
from . import mips
from . import mips64
from . import mipsel
from . import mips64el
from . import riscv32
from . import riscv64

X86 = x86.X86()
X64 = x86_64.X64()
PPC = ppc.Ppc()
PPC64 = ppc64.Ppc64()
ARM = arm.Arm()
AARCH64 = aarch64.Aarch64()
MIPS = mips.Mips()
MIPS64 = mips64.Mips64()
MIPSEL = mipsel.Mipsel()
MIPS64EL = mips64el.Mips64el()
RISCV32 = riscv32.Riscv32()
RISCV64 = riscv64.Riscv64()

del globals()['lib']
del globals()['x86']
del globals()['x86_64']
del globals()['ppc']
del globals()['ppc64']
del globals()['arm']
del globals()['aarch64']
del globals()['mips']
del globals()['mips64']
del globals()['mipsel']
del globals()['mips64el']
del globals()['riscv32']
del globals()['riscv64']


