from unicorn import Uc, UC_HOOK_CODE
from unicorn.arm_const import *

from .lib import Arch, Trace

class Arm(Arch):
    ARCH_ID = 0x120
    
    TRACKED_REGISTERS = [
        (UC_ARM_REG_R0, "<I"),
        (UC_ARM_REG_R1, "<I"),
        (UC_ARM_REG_R2, "<I"),
        (UC_ARM_REG_R3, "<I"),
        (UC_ARM_REG_R4, "<I"),
        (UC_ARM_REG_R5, "<I"),
        (UC_ARM_REG_R6, "<I"),
        (UC_ARM_REG_R7, "<I"),
        (UC_ARM_REG_R8, "<I"),
        (UC_ARM_REG_R9, "<I"),
        (UC_ARM_REG_R10, "<I"),
        (UC_ARM_REG_R11, "<I"),
        (UC_ARM_REG_R12, "<I"),
        (UC_ARM_REG_R13, "<I"),
        (UC_ARM_REG_R14, "<I"),
        #(UC_ARM_REG_R15, "<I"),
    ]
    
    REGISTER_NAMES = {
        UC_ARM_REG_APSR: 'APSR', # 1
        UC_ARM_REG_APSR_NZCV: 'APSR_NZCV', # 2
        UC_ARM_REG_CPSR: 'CPSR', # 3
        UC_ARM_REG_FPEXC: 'FPEXC', # 4
        UC_ARM_REG_FPINST: 'FPINST', # 5
        UC_ARM_REG_FPSCR: 'FPSCR', # 6
        UC_ARM_REG_FPSCR_NZCV: 'FPSCR_NZCV', # 7
        UC_ARM_REG_FPSID: 'FPSID', # 8
        UC_ARM_REG_ITSTATE: 'ITSTATE', # 9
        #UC_ARM_REG_LR: 'LR', # 10, alias
        UC_ARM_REG_R14: 'R14', # 10
        #UC_ARM_REG_PC: 'PC', # 11, alias
        UC_ARM_REG_R15: 'R15', # 11
        UC_ARM_REG_R13: 'R13', # 12
        #UC_ARM_REG_SP: 'SP', # 12, alias
        UC_ARM_REG_SPSR: 'SPSR', # 13
        UC_ARM_REG_D0: 'D0', # 14
        UC_ARM_REG_D1: 'D1', # 15
        UC_ARM_REG_D2: 'D2', # 16
        UC_ARM_REG_D3: 'D3', # 17
        UC_ARM_REG_D4: 'D4', # 18
        UC_ARM_REG_D5: 'D5', # 19
        UC_ARM_REG_D6: 'D6', # 20
        UC_ARM_REG_D7: 'D7', # 21
        UC_ARM_REG_D8: 'D8', # 22
        UC_ARM_REG_D9: 'D9', # 23
        UC_ARM_REG_D10: 'D10', # 24
        UC_ARM_REG_D11: 'D11', # 25
        UC_ARM_REG_D12: 'D12', # 26
        UC_ARM_REG_D13: 'D13', # 27
        UC_ARM_REG_D14: 'D14', # 28
        UC_ARM_REG_D15: 'D15', # 29
        UC_ARM_REG_D16: 'D16', # 30
        UC_ARM_REG_D17: 'D17', # 31
        UC_ARM_REG_D18: 'D18', # 32
        UC_ARM_REG_D19: 'D19', # 33
        UC_ARM_REG_D20: 'D20', # 34
        UC_ARM_REG_D21: 'D21', # 35
        UC_ARM_REG_D22: 'D22', # 36
        UC_ARM_REG_D23: 'D23', # 37
        UC_ARM_REG_D24: 'D24', # 38
        UC_ARM_REG_D25: 'D25', # 39
        UC_ARM_REG_D26: 'D26', # 40
        UC_ARM_REG_D27: 'D27', # 41
        UC_ARM_REG_D28: 'D28', # 42
        UC_ARM_REG_D29: 'D29', # 43
        UC_ARM_REG_D30: 'D30', # 44
        UC_ARM_REG_D31: 'D31', # 45
        UC_ARM_REG_FPINST2: 'FPINST2', # 46
        UC_ARM_REG_MVFR0: 'MVFR0', # 47
        UC_ARM_REG_MVFR1: 'MVFR1', # 48
        UC_ARM_REG_MVFR2: 'MVFR2', # 49
        UC_ARM_REG_Q0: 'Q0', # 50
        UC_ARM_REG_Q1: 'Q1', # 51
        UC_ARM_REG_Q2: 'Q2', # 52
        UC_ARM_REG_Q3: 'Q3', # 53
        UC_ARM_REG_Q4: 'Q4', # 54
        UC_ARM_REG_Q5: 'Q5', # 55
        UC_ARM_REG_Q6: 'Q6', # 56
        UC_ARM_REG_Q7: 'Q7', # 57
        UC_ARM_REG_Q8: 'Q8', # 58
        UC_ARM_REG_Q9: 'Q9', # 59
        UC_ARM_REG_Q10: 'Q10', # 60
        UC_ARM_REG_Q11: 'Q11', # 61
        UC_ARM_REG_Q12: 'Q12', # 62
        UC_ARM_REG_Q13: 'Q13', # 63
        UC_ARM_REG_Q14: 'Q14', # 64
        UC_ARM_REG_Q15: 'Q15', # 65
        UC_ARM_REG_R0: 'R0', # 66
        UC_ARM_REG_R1: 'R1', # 67
        UC_ARM_REG_R2: 'R2', # 68
        UC_ARM_REG_R3: 'R3', # 69
        UC_ARM_REG_R4: 'R4', # 70
        UC_ARM_REG_R5: 'R5', # 71
        UC_ARM_REG_R6: 'R6', # 72
        UC_ARM_REG_R7: 'R7', # 73
        UC_ARM_REG_R8: 'R8', # 74
        UC_ARM_REG_R9: 'R9', # 75
        #UC_ARM_REG_SB: 'SB', # 75, alias
        UC_ARM_REG_R10: 'R10', # 76
        #UC_ARM_REG_SL: 'SL', # 76, alias
        #UC_ARM_REG_FP: 'FP', # 77, alias
        UC_ARM_REG_R11: 'R11', # 77
        #UC_ARM_REG_IP: 'IP', # 78, alias
        UC_ARM_REG_R12: 'R12', # 78
        UC_ARM_REG_S0: 'S0', # 79
        UC_ARM_REG_S1: 'S1', # 80
        UC_ARM_REG_S2: 'S2', # 81
        UC_ARM_REG_S3: 'S3', # 82
        UC_ARM_REG_S4: 'S4', # 83
        UC_ARM_REG_S5: 'S5', # 84
        UC_ARM_REG_S6: 'S6', # 85
        UC_ARM_REG_S7: 'S7', # 86
        UC_ARM_REG_S8: 'S8', # 87
        UC_ARM_REG_S9: 'S9', # 88
        UC_ARM_REG_S10: 'S10', # 89
        UC_ARM_REG_S11: 'S11', # 90
        UC_ARM_REG_S12: 'S12', # 91
        UC_ARM_REG_S13: 'S13', # 92
        UC_ARM_REG_S14: 'S14', # 93
        UC_ARM_REG_S15: 'S15', # 94
        UC_ARM_REG_S16: 'S16', # 95
        UC_ARM_REG_S17: 'S17', # 96
        UC_ARM_REG_S18: 'S18', # 97
        UC_ARM_REG_S19: 'S19', # 98
        UC_ARM_REG_S20: 'S20', # 99
        UC_ARM_REG_S21: 'S21', # 100
        UC_ARM_REG_S22: 'S22', # 101
        UC_ARM_REG_S23: 'S23', # 102
        UC_ARM_REG_S24: 'S24', # 103
        UC_ARM_REG_S25: 'S25', # 104
        UC_ARM_REG_S26: 'S26', # 105
        UC_ARM_REG_S27: 'S27', # 106
        UC_ARM_REG_S28: 'S28', # 107
        UC_ARM_REG_S29: 'S29', # 108
        UC_ARM_REG_S30: 'S30', # 109
        UC_ARM_REG_S31: 'S31', # 110
        UC_ARM_REG_C1_C0_2: 'C1_C0_2', # 111
        UC_ARM_REG_C13_C0_2: 'C13_C0_2', # 112
        UC_ARM_REG_C13_C0_3: 'C13_C0_3', # 113
        UC_ARM_REG_IPSR: 'IPSR', # 114
        UC_ARM_REG_MSP: 'MSP', # 115
        UC_ARM_REG_PSP: 'PSP', # 116
        UC_ARM_REG_CONTROL: 'CONTROL', # 117
        UC_ARM_REG_IAPSR: 'IAPSR', # 118
        UC_ARM_REG_EAPSR: 'EAPSR', # 119
        UC_ARM_REG_XPSR: 'XPSR', # 120
        UC_ARM_REG_EPSR: 'EPSR', # 121
        UC_ARM_REG_IEPSR: 'IEPSR', # 122
        UC_ARM_REG_PRIMASK: 'PRIMASK', # 123
        UC_ARM_REG_BASEPRI: 'BASEPRI', # 124
        UC_ARM_REG_BASEPRI_MAX: 'BASEPRI_MAX', # 125
        UC_ARM_REG_FAULTMASK: 'FAULTMASK', # 126
        UC_ARM_REG_APSR_NZCVQ: 'APSR_NZCVQ', # 127
        UC_ARM_REG_APSR_G: 'APSR_G', # 128
        UC_ARM_REG_APSR_NZCVQG: 'APSR_NZCVQG', # 129
        UC_ARM_REG_IAPSR_NZCVQ: 'IAPSR_NZCVQ', # 130
        UC_ARM_REG_IAPSR_G: 'IAPSR_G', # 131
        UC_ARM_REG_IAPSR_NZCVQG: 'IAPSR_NZCVQG', # 132
        UC_ARM_REG_EAPSR_NZCVQ: 'EAPSR_NZCVQ', # 133
        UC_ARM_REG_EAPSR_G: 'EAPSR_G', # 134
        UC_ARM_REG_EAPSR_NZCVQG: 'EAPSR_NZCVQG', # 135
        UC_ARM_REG_XPSR_NZCVQ: 'XPSR_NZCVQ', # 136
        UC_ARM_REG_XPSR_G: 'XPSR_G', # 137
        UC_ARM_REG_XPSR_NZCVQG: 'XPSR_NZCVQG', # 138
        UC_ARM_REG_CP_REG: 'CP_REG', # 139
    }

    VARFMT = "<I"

    # TODO: Replace LSB of PC w/ a separate meta-record upon change
    def install_additional_after_hooks(self, emu: Uc, trace: Trace):
        def on_code(uc: Uc, addr: int, size: int, trace: Trace):
            cpsr =  uc._trace_orig_reg_read(UC_ARM_REG_CPSR)
            thumb = (cpsr >> 5) & 0b1
            trace.state["pc"] |= thumb

        emu.hook_add(UC_HOOK_CODE, on_code, trace)
