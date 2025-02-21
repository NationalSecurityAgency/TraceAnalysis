from unicorn.ppc_const import *

from .lib import Arch

class Ppc(Arch):
    ARCH_ID = 0x10
    
    TRACKED_REGISTERS = [
        (UC_PPC_REG_0, '>I'),
        (UC_PPC_REG_1, '>I'),
        (UC_PPC_REG_2, '>I'),
        (UC_PPC_REG_3, '>I'),
        (UC_PPC_REG_4, '>I'),
        (UC_PPC_REG_5, '>I'),
        (UC_PPC_REG_6, '>I'),
        (UC_PPC_REG_7, '>I'),
        (UC_PPC_REG_8, '>I'),
        (UC_PPC_REG_9, '>I'),
        (UC_PPC_REG_10, '>I'),
        (UC_PPC_REG_11, '>I'),
        (UC_PPC_REG_12, '>I'),
        (UC_PPC_REG_13, '>I'),
        (UC_PPC_REG_14, '>I'),
        (UC_PPC_REG_15, '>I'),
        (UC_PPC_REG_16, '>I'),
        (UC_PPC_REG_17, '>I'),
        (UC_PPC_REG_18, '>I'),
        (UC_PPC_REG_19, '>I'),
        (UC_PPC_REG_20, '>I'),
        (UC_PPC_REG_21, '>I'),
        (UC_PPC_REG_22, '>I'),
        (UC_PPC_REG_23, '>I'),
        (UC_PPC_REG_24, '>I'),
        (UC_PPC_REG_25, '>I'),
        (UC_PPC_REG_26, '>I'),
        (UC_PPC_REG_27, '>I'),
        (UC_PPC_REG_28, '>I'),
        (UC_PPC_REG_29, '>I'),
        (UC_PPC_REG_30, '>I'),
        (UC_PPC_REG_31, '>I'),
        (UC_PPC_REG_LR, '>I'),
        (UC_PPC_REG_CTR, '>I'),
        (UC_PPC_REG_MSR, '>I'),
    ]
    
    REGISTER_NAMES = {
        UC_PPC_REG_PC: 'PC', # 1
        UC_PPC_REG_0: 'R0', # 2
        UC_PPC_REG_1: 'R1', # 3
        UC_PPC_REG_2: 'R2', # 4
        UC_PPC_REG_3: 'R3', # 5
        UC_PPC_REG_4: 'R4', # 6
        UC_PPC_REG_5: 'R5', # 7
        UC_PPC_REG_6: 'R6', # 8
        UC_PPC_REG_7: 'R7', # 9
        UC_PPC_REG_8: 'R8', # 10
        UC_PPC_REG_9: 'R9', # 11
        UC_PPC_REG_10: 'R10', # 12
        UC_PPC_REG_11: 'R11', # 13
        UC_PPC_REG_12: 'R12', # 14
        UC_PPC_REG_13: 'R13', # 15
        UC_PPC_REG_14: 'R14', # 16
        UC_PPC_REG_15: 'R15', # 17
        UC_PPC_REG_16: 'R16', # 18
        UC_PPC_REG_17: 'R17', # 19
        UC_PPC_REG_18: 'R18', # 20
        UC_PPC_REG_19: 'R19', # 21
        UC_PPC_REG_20: 'R20', # 22
        UC_PPC_REG_21: 'R21', # 23
        UC_PPC_REG_22: 'R22', # 24
        UC_PPC_REG_23: 'R23', # 25
        UC_PPC_REG_24: 'R24', # 26
        UC_PPC_REG_25: 'R25', # 27
        UC_PPC_REG_26: 'R26', # 28
        UC_PPC_REG_27: 'R27', # 29
        UC_PPC_REG_28: 'R28', # 30
        UC_PPC_REG_29: 'R29', # 31
        UC_PPC_REG_30: 'R30', # 32
        UC_PPC_REG_31: 'R31', # 33
        UC_PPC_REG_CR0: 'CR0', # 34
        UC_PPC_REG_CR1: 'CR1', # 35
        UC_PPC_REG_CR2: 'CR2', # 36
        UC_PPC_REG_CR3: 'CR3', # 37
        UC_PPC_REG_CR4: 'CR4', # 38
        UC_PPC_REG_CR5: 'CR5', # 39
        UC_PPC_REG_CR6: 'CR6', # 40
        UC_PPC_REG_CR7: 'CR7', # 41
        UC_PPC_REG_FPR0: 'FPR0', # 42
        UC_PPC_REG_FPR1: 'FPR1', # 43
        UC_PPC_REG_FPR2: 'FPR2', # 44
        UC_PPC_REG_FPR3: 'FPR3', # 45
        UC_PPC_REG_FPR4: 'FPR4', # 46
        UC_PPC_REG_FPR5: 'FPR5', # 47
        UC_PPC_REG_FPR6: 'FPR6', # 48
        UC_PPC_REG_FPR7: 'FPR7', # 49
        UC_PPC_REG_FPR8: 'FPR8', # 50
        UC_PPC_REG_FPR9: 'FPR9', # 51
        UC_PPC_REG_FPR10: 'FPR10', # 52
        UC_PPC_REG_FPR11: 'FPR11', # 53
        UC_PPC_REG_FPR12: 'FPR12', # 54
        UC_PPC_REG_FPR13: 'FPR13', # 55
        UC_PPC_REG_FPR14: 'FPR14', # 56
        UC_PPC_REG_FPR15: 'FPR15', # 57
        UC_PPC_REG_FPR16: 'FPR16', # 58
        UC_PPC_REG_FPR17: 'FPR17', # 59
        UC_PPC_REG_FPR18: 'FPR18', # 60
        UC_PPC_REG_FPR19: 'FPR19', # 61
        UC_PPC_REG_FPR20: 'FPR20', # 62
        UC_PPC_REG_FPR21: 'FPR21', # 63
        UC_PPC_REG_FPR22: 'FPR22', # 64
        UC_PPC_REG_FPR23: 'FPR23', # 65
        UC_PPC_REG_FPR24: 'FPR24', # 66
        UC_PPC_REG_FPR25: 'FPR25', # 67
        UC_PPC_REG_FPR26: 'FPR26', # 68
        UC_PPC_REG_FPR27: 'FPR27', # 69
        UC_PPC_REG_FPR28: 'FPR28', # 70
        UC_PPC_REG_FPR29: 'FPR29', # 71
        UC_PPC_REG_FPR30: 'FPR30', # 72
        UC_PPC_REG_FPR31: 'FPR31', # 73
        UC_PPC_REG_LR: 'LR', # 74
        UC_PPC_REG_XER: 'XER', # 75
        UC_PPC_REG_CTR: 'CTR', # 76
        UC_PPC_REG_MSR: 'MSR', # 77
        UC_PPC_REG_FPSCR: 'FPSCR', # 78
        UC_PPC_REG_CR: 'CR', # 79
    }
    
    VARFMT = ">I"
