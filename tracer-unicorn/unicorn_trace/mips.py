from unicorn.mips_const import *

from .lib import Arch

class Mips(Arch):
    ARCH_ID = 0x60
    
    TRACKED_REGISTERS = [
        (UC_MIPS_REG_0, '>I'),
        (UC_MIPS_REG_1, '>I'),
        (UC_MIPS_REG_2, '>I'),
        (UC_MIPS_REG_3, '>I'),
        (UC_MIPS_REG_4, '>I'),
        (UC_MIPS_REG_5, '>I'),
        (UC_MIPS_REG_6, '>I'),
        (UC_MIPS_REG_7, '>I'),
        (UC_MIPS_REG_8, '>I'),
        (UC_MIPS_REG_9, '>I'),
        (UC_MIPS_REG_10, '>I'),
        (UC_MIPS_REG_11, '>I'),
        (UC_MIPS_REG_12, '>I'),
        (UC_MIPS_REG_13, '>I'),
        (UC_MIPS_REG_14, '>I'),
        (UC_MIPS_REG_15, '>I'),
        (UC_MIPS_REG_16, '>I'),
        (UC_MIPS_REG_17, '>I'),
        (UC_MIPS_REG_18, '>I'),
        (UC_MIPS_REG_19, '>I'),
        (UC_MIPS_REG_20, '>I'),
        (UC_MIPS_REG_21, '>I'),
        (UC_MIPS_REG_22, '>I'),
        (UC_MIPS_REG_23, '>I'),
        (UC_MIPS_REG_24, '>I'),
        (UC_MIPS_REG_25, '>I'),
        (UC_MIPS_REG_26, '>I'),
        (UC_MIPS_REG_27, '>I'),
        (UC_MIPS_REG_28, '>I'),
        (UC_MIPS_REG_29, '>I'),
        (UC_MIPS_REG_30, '>I'),
        (UC_MIPS_REG_31, '>I'),
    ]
    
    REGISTER_NAMES = {
        UC_MIPS_REG_PC: 'PC', # 1
        UC_MIPS_REG_0: 'R0', # 2
        #UC_MIPS_REG_ZERO: 'ZERO', # 2, alias
        UC_MIPS_REG_1: 'R1', # 3
        #UC_MIPS_REG_AT: 'AT', # 3, alias
        UC_MIPS_REG_2: 'R2', # 4
        #UC_MIPS_REG_V0: 'V0', # 4
        UC_MIPS_REG_3: 'R3', # 5
        #UC_MIPS_REG_V1: 'V1', # 5
        UC_MIPS_REG_4: 'R4', # 6
        #UC_MIPS_REG_A0: 'A0', # 6
        UC_MIPS_REG_5: 'R5', # 7
        #UC_MIPS_REG_A1: 'A1', # 7
        UC_MIPS_REG_6: 'R6', # 8
        #UC_MIPS_REG_A2: 'A2', # 8
        UC_MIPS_REG_7: 'R7', # 9
        #UC_MIPS_REG_A3: 'A3', # 9
        UC_MIPS_REG_8: 'R8', # 10
        #UC_MIPS_REG_T0: 'T0', # 10
        UC_MIPS_REG_9: 'R9', # 11
        #UC_MIPS_REG_T1: 'T1', # 11
        UC_MIPS_REG_10: 'R10', # 12
        #UC_MIPS_REG_T2: 'T2', # 12
        UC_MIPS_REG_11: 'R11', # 13
        #UC_MIPS_REG_T3: 'T3', # 13
        UC_MIPS_REG_12: 'R12', # 14
        #UC_MIPS_REG_T4: 'T4', # 14
        UC_MIPS_REG_13: 'R13', # 15
        #UC_MIPS_REG_T5: 'T5', # 15
        UC_MIPS_REG_14: 'R14', # 16
        #UC_MIPS_REG_T6: 'T6', # 16
        UC_MIPS_REG_15: 'R15', # 17
        #UC_MIPS_REG_T7: 'T7', # 17
        UC_MIPS_REG_16: 'R16', # 18
        #UC_MIPS_REG_S0: 'S0', # 18
        UC_MIPS_REG_17: 'R17', # 19
        #UC_MIPS_REG_S1: 'S1', # 19
        UC_MIPS_REG_18: 'R18', # 20
        #UC_MIPS_REG_S2: 'S2', # 20
        UC_MIPS_REG_19: 'R19', # 21
        #UC_MIPS_REG_S3: 'S3', # 21
        UC_MIPS_REG_20: 'R20', # 22
        #UC_MIPS_REG_S4: 'S4', # 22
        UC_MIPS_REG_21: 'R21', # 23
        #UC_MIPS_REG_S5: 'S5', # 23
        UC_MIPS_REG_22: 'R22', # 24
        #UC_MIPS_REG_S6: 'S6', # 24
        UC_MIPS_REG_23: 'R23', # 25
        #UC_MIPS_REG_S7: 'S7', # 25
        UC_MIPS_REG_24: 'R24', # 26
        #UC_MIPS_REG_T8: 'T8', # 26
        UC_MIPS_REG_25: 'R25', # 27
        #UC_MIPS_REG_T9: 'T9', # 27
        UC_MIPS_REG_26: 'R26', # 28
        #UC_MIPS_REG_K0: 'K0', # 28
        UC_MIPS_REG_27: 'R27', # 29
        #UC_MIPS_REG_K1: 'K1', # 29
        UC_MIPS_REG_28: 'R28', # 30
        #UC_MIPS_REG_GP: 'GP', # 30
        UC_MIPS_REG_29: 'R29', # 31
        #UC_MIPS_REG_SP: 'SP', # 31
        UC_MIPS_REG_30: 'R30', # 32
        #UC_MIPS_REG_FP: 'FP', # 32
        #UC_MIPS_REG_S8: 'S8', # 32
        UC_MIPS_REG_31: 'R31', # 33
        #UC_MIPS_REG_RA: 'RA', # 33
        UC_MIPS_REG_DSPCCOND: 'DSPCCOND', # 34
        UC_MIPS_REG_DSPCARRY: 'DSPCARRY', # 35
        UC_MIPS_REG_DSPEFI: 'DSPEFI', # 36
        UC_MIPS_REG_DSPOUTFLAG: 'DSPOUTFLAG', # 37
        UC_MIPS_REG_DSPOUTFLAG16_19: 'DSPOUTFLAG16_19', # 38
        UC_MIPS_REG_DSPOUTFLAG20: 'DSPOUTFLAG20', # 39
        UC_MIPS_REG_DSPOUTFLAG21: 'DSPOUTFLAG21', # 40
        UC_MIPS_REG_DSPOUTFLAG22: 'DSPOUTFLAG22', # 41
        UC_MIPS_REG_DSPOUTFLAG23: 'DSPOUTFLAG23', # 42
        UC_MIPS_REG_DSPPOS: 'DSPPOS', # 43
        UC_MIPS_REG_DSPSCOUNT: 'DSPSCOUNT', # 44
        UC_MIPS_REG_AC0: 'AC0', # 45
        #UC_MIPS_REG_HI0: 'HI0', # 45
        #UC_MIPS_REG_LO0: 'LO0', # 45
        UC_MIPS_REG_AC1: 'AC1', # 46
        #UC_MIPS_REG_HI1: 'HI1', # 46
        #UC_MIPS_REG_LO1: 'LO1', # 46
        UC_MIPS_REG_AC2: 'AC2', # 47
        #UC_MIPS_REG_HI2: 'HI2', # 47
        #UC_MIPS_REG_LO2: 'LO2', # 47
        UC_MIPS_REG_AC3: 'AC3', # 48
        #UC_MIPS_REG_HI3: 'HI3', # 48
        #UC_MIPS_REG_LO3: 'LO3', # 48
        UC_MIPS_REG_CC0: 'CC0', # 49
        UC_MIPS_REG_CC1: 'CC1', # 50
        UC_MIPS_REG_CC2: 'CC2', # 51
        UC_MIPS_REG_CC3: 'CC3', # 52
        UC_MIPS_REG_CC4: 'CC4', # 53
        UC_MIPS_REG_CC5: 'CC5', # 54
        UC_MIPS_REG_CC6: 'CC6', # 55
        UC_MIPS_REG_CC7: 'CC7', # 56
        UC_MIPS_REG_F0: 'F0', # 57
        UC_MIPS_REG_F1: 'F1', # 58
        UC_MIPS_REG_F2: 'F2', # 59
        UC_MIPS_REG_F3: 'F3', # 60
        UC_MIPS_REG_F4: 'F4', # 61
        UC_MIPS_REG_F5: 'F5', # 62
        UC_MIPS_REG_F6: 'F6', # 63
        UC_MIPS_REG_F7: 'F7', # 64
        UC_MIPS_REG_F8: 'F8', # 65
        UC_MIPS_REG_F9: 'F9', # 66
        UC_MIPS_REG_F10: 'F10', # 67
        UC_MIPS_REG_F11: 'F11', # 68
        UC_MIPS_REG_F12: 'F12', # 69
        UC_MIPS_REG_F13: 'F13', # 70
        UC_MIPS_REG_F14: 'F14', # 71
        UC_MIPS_REG_F15: 'F15', # 72
        UC_MIPS_REG_F16: 'F16', # 73
        UC_MIPS_REG_F17: 'F17', # 74
        UC_MIPS_REG_F18: 'F18', # 75
        UC_MIPS_REG_F19: 'F19', # 76
        UC_MIPS_REG_F20: 'F20', # 77
        UC_MIPS_REG_F21: 'F21', # 78
        UC_MIPS_REG_F22: 'F22', # 79
        UC_MIPS_REG_F23: 'F23', # 80
        UC_MIPS_REG_F24: 'F24', # 81
        UC_MIPS_REG_F25: 'F25', # 82
        UC_MIPS_REG_F26: 'F26', # 83
        UC_MIPS_REG_F27: 'F27', # 84
        UC_MIPS_REG_F28: 'F28', # 85
        UC_MIPS_REG_F29: 'F29', # 86
        UC_MIPS_REG_F30: 'F30', # 87
        UC_MIPS_REG_F31: 'F31', # 88
        UC_MIPS_REG_FCC0: 'FCC0', # 89
        UC_MIPS_REG_FCC1: 'FCC1', # 90
        UC_MIPS_REG_FCC2: 'FCC2', # 91
        UC_MIPS_REG_FCC3: 'FCC3', # 92
        UC_MIPS_REG_FCC4: 'FCC4', # 93
        UC_MIPS_REG_FCC5: 'FCC5', # 94
        UC_MIPS_REG_FCC6: 'FCC6', # 95
        UC_MIPS_REG_FCC7: 'FCC7', # 96
        UC_MIPS_REG_W0: 'W0', # 97
        UC_MIPS_REG_W1: 'W1', # 98
        UC_MIPS_REG_W2: 'W2', # 99
        UC_MIPS_REG_W3: 'W3', # 100
        UC_MIPS_REG_W4: 'W4', # 101
        UC_MIPS_REG_W5: 'W5', # 102
        UC_MIPS_REG_W6: 'W6', # 103
        UC_MIPS_REG_W7: 'W7', # 104
        UC_MIPS_REG_W8: 'W8', # 105
        UC_MIPS_REG_W9: 'W9', # 106
        UC_MIPS_REG_W10: 'W10', # 107
        UC_MIPS_REG_W11: 'W11', # 108
        UC_MIPS_REG_W12: 'W12', # 109
        UC_MIPS_REG_W13: 'W13', # 110
        UC_MIPS_REG_W14: 'W14', # 111
        UC_MIPS_REG_W15: 'W15', # 112
        UC_MIPS_REG_W16: 'W16', # 113
        UC_MIPS_REG_W17: 'W17', # 114
        UC_MIPS_REG_W18: 'W18', # 115
        UC_MIPS_REG_W19: 'W19', # 116
        UC_MIPS_REG_W20: 'W20', # 117
        UC_MIPS_REG_W21: 'W21', # 118
        UC_MIPS_REG_W22: 'W22', # 119
        UC_MIPS_REG_W23: 'W23', # 120
        UC_MIPS_REG_W24: 'W24', # 121
        UC_MIPS_REG_W25: 'W25', # 122
        UC_MIPS_REG_W26: 'W26', # 123
        UC_MIPS_REG_W27: 'W27', # 124
        UC_MIPS_REG_W28: 'W28', # 125
        UC_MIPS_REG_W29: 'W29', # 126
        UC_MIPS_REG_W30: 'W30', # 127
        UC_MIPS_REG_W31: 'W31', # 128
        UC_MIPS_REG_HI: 'HI', # 129
        UC_MIPS_REG_LO: 'LO', # 130
        UC_MIPS_REG_P0: 'P0', # 131
        UC_MIPS_REG_P1: 'P1', # 132
        UC_MIPS_REG_P2: 'P2', # 133
        UC_MIPS_REG_MPL0: 'MPL0', # 134
        UC_MIPS_REG_MPL1: 'MPL1', # 135
        UC_MIPS_REG_MPL2: 'MPL2', # 136
        UC_MIPS_REG_CP0_CONFIG3: 'CP0_CONFIG3', # 137
        UC_MIPS_REG_CP0_USERLOCAL: 'CP0_USERLOCAL', # 138
        UC_MIPS_REG_CP0_STATUS: 'CP0_STATUS', # 139
    }

    VARFMT = ">I"
