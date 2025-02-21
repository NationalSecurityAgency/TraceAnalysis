from unicorn.x86_const import *

from .lib import Arch

class X64(Arch):
    ARCH_ID = 0x40

    TRACKED_REGISTERS = [
        (UC_X86_REG_RAX, "<Q"),
        (UC_X86_REG_RBP, "<Q"),
        (UC_X86_REG_RBX, "<Q"),
        (UC_X86_REG_RCX, "<Q"),
        (UC_X86_REG_RDI, "<Q"),
        (UC_X86_REG_RDX, "<Q"),
        #(UC_X86_REG_RIP, "<Q"),
        (UC_X86_REG_RSI, "<Q"),
        (UC_X86_REG_RSP, "<Q"),
        (UC_X86_REG_R8, "<Q"),
        (UC_X86_REG_R9, "<Q"),
        (UC_X86_REG_R10, "<Q"),
        (UC_X86_REG_R11, "<Q"),
        (UC_X86_REG_R12, "<Q"),
        (UC_X86_REG_R13, "<Q"),
        (UC_X86_REG_R14, "<Q"),
        (UC_X86_REG_R15, "<Q"),
    ]

    REGISTER_NAMES = {
        UC_X86_REG_AH: 'AH', # 1
        UC_X86_REG_AL: 'AL', # 2
        UC_X86_REG_AX: 'AX', # 3
        UC_X86_REG_BH: 'BH', # 4
        UC_X86_REG_BL: 'BL', # 5
        UC_X86_REG_BP: 'BP', # 6
        UC_X86_REG_BPL: 'BPL', # 7
        UC_X86_REG_BX: 'BX', # 8
        UC_X86_REG_CH: 'CH', # 9
        UC_X86_REG_CL: 'CL', # 10
        UC_X86_REG_CS: 'CS', # 11
        UC_X86_REG_CX: 'CX', # 12
        UC_X86_REG_DH: 'DH', # 13
        UC_X86_REG_DI: 'DI', # 14
        UC_X86_REG_DIL: 'DIL', # 15
        UC_X86_REG_DL: 'DL', # 16
        UC_X86_REG_DS: 'DS', # 17
        UC_X86_REG_DX: 'DX', # 18
        UC_X86_REG_EAX: 'EAX', # 19
        UC_X86_REG_EBP: 'EBP', # 20
        UC_X86_REG_EBX: 'EBX', # 21
        UC_X86_REG_ECX: 'ECX', # 22
        UC_X86_REG_EDI: 'EDI', # 23
        UC_X86_REG_EDX: 'EDX', # 24
        UC_X86_REG_EFLAGS: 'EFLAGS', # 25
        UC_X86_REG_EIP: 'EIP', # 26
        UC_X86_REG_ES: 'ES', # 28
        UC_X86_REG_ESI: 'ESI', # 29
        UC_X86_REG_ESP: 'ESP', # 30
        UC_X86_REG_FPSW: 'FPSW', # 31
        UC_X86_REG_FS: 'FS', # 32
        UC_X86_REG_GS: 'GS', # 33
        UC_X86_REG_IP: 'IP', # 34
        UC_X86_REG_RAX: 'RAX', # 35
        UC_X86_REG_RBP: 'RBP', # 36
        UC_X86_REG_RBX: 'RBX', # 37
        UC_X86_REG_RCX: 'RCX', # 38
        UC_X86_REG_RDI: 'RDI', # 39
        UC_X86_REG_RDX: 'RDX', # 40
        UC_X86_REG_RIP: 'RIP', # 41
        UC_X86_REG_RSI: 'RSI', # 43
        UC_X86_REG_RSP: 'RSP', # 44
        UC_X86_REG_SI: 'SI', # 45
        UC_X86_REG_SIL: 'SIL', # 46
        UC_X86_REG_SP: 'SP', # 47
        UC_X86_REG_SPL: 'SPL', # 48
        UC_X86_REG_SS: 'SS', # 49
        UC_X86_REG_CR0: 'CR0', # 50
        UC_X86_REG_CR1: 'CR1', # 51
        UC_X86_REG_CR2: 'CR2', # 52
        UC_X86_REG_CR3: 'CR3', # 53
        UC_X86_REG_CR4: 'CR4', # 54
        UC_X86_REG_CR8: 'CR8', # 58
        UC_X86_REG_DR0: 'DR0', # 66
        UC_X86_REG_DR1: 'DR1', # 67
        UC_X86_REG_DR2: 'DR2', # 68
        UC_X86_REG_DR3: 'DR3', # 69
        UC_X86_REG_DR4: 'DR4', # 70
        UC_X86_REG_DR5: 'DR5', # 71
        UC_X86_REG_DR6: 'DR6', # 72
        UC_X86_REG_DR7: 'DR7', # 73
        UC_X86_REG_FP0: 'FP0', # 82
        UC_X86_REG_FP1: 'FP1', # 83
        UC_X86_REG_FP2: 'FP2', # 84
        UC_X86_REG_FP3: 'FP3', # 85
        UC_X86_REG_FP4: 'FP4', # 86
        UC_X86_REG_FP5: 'FP5', # 87
        UC_X86_REG_FP6: 'FP6', # 88
        UC_X86_REG_FP7: 'FP7', # 89
        UC_X86_REG_K0: 'K0', # 90
        UC_X86_REG_K1: 'K1', # 91
        UC_X86_REG_K2: 'K2', # 92
        UC_X86_REG_K3: 'K3', # 93
        UC_X86_REG_K4: 'K4', # 94
        UC_X86_REG_K5: 'K5', # 95
        UC_X86_REG_K6: 'K6', # 96
        UC_X86_REG_K7: 'K7', # 97
        UC_X86_REG_MM0: 'MM0', # 98
        UC_X86_REG_MM1: 'MM1', # 99
        UC_X86_REG_MM2: 'MM2', # 100
        UC_X86_REG_MM3: 'MM3', # 101
        UC_X86_REG_MM4: 'MM4', # 102
        UC_X86_REG_MM5: 'MM5', # 103
        UC_X86_REG_MM6: 'MM6', # 104
        UC_X86_REG_MM7: 'MM7', # 105
        UC_X86_REG_R8: 'R8', # 106
        UC_X86_REG_R9: 'R9', # 107
        UC_X86_REG_R10: 'R10', # 108
        UC_X86_REG_R11: 'R11', # 109
        UC_X86_REG_R12: 'R12', # 110
        UC_X86_REG_R13: 'R13', # 111
        UC_X86_REG_R14: 'R14', # 112
        UC_X86_REG_R15: 'R15', # 113
        UC_X86_REG_ST0: 'ST0', # 114
        UC_X86_REG_ST1: 'ST1', # 115
        UC_X86_REG_ST2: 'ST2', # 116
        UC_X86_REG_ST3: 'ST3', # 117
        UC_X86_REG_ST4: 'ST4', # 118
        UC_X86_REG_ST5: 'ST5', # 119
        UC_X86_REG_ST6: 'ST6', # 120
        UC_X86_REG_ST7: 'ST7', # 121
        UC_X86_REG_XMM0: 'XMM0', # 122
        UC_X86_REG_XMM1: 'XMM1', # 123
        UC_X86_REG_XMM2: 'XMM2', # 124
        UC_X86_REG_XMM3: 'XMM3', # 125
        UC_X86_REG_XMM4: 'XMM4', # 126
        UC_X86_REG_XMM5: 'XMM5', # 127
        UC_X86_REG_XMM6: 'XMM6', # 128
        UC_X86_REG_XMM7: 'XMM7', # 129
        UC_X86_REG_XMM8: 'XMM8', # 130
        UC_X86_REG_XMM9: 'XMM9', # 131
        UC_X86_REG_XMM10: 'XMM10', # 132
        UC_X86_REG_XMM11: 'XMM11', # 133
        UC_X86_REG_XMM12: 'XMM12', # 134
        UC_X86_REG_XMM13: 'XMM13', # 135
        UC_X86_REG_XMM14: 'XMM14', # 136
        UC_X86_REG_XMM15: 'XMM15', # 137
        UC_X86_REG_XMM16: 'XMM16', # 138
        UC_X86_REG_XMM17: 'XMM17', # 139
        UC_X86_REG_XMM18: 'XMM18', # 140
        UC_X86_REG_XMM19: 'XMM19', # 141
        UC_X86_REG_XMM20: 'XMM20', # 142
        UC_X86_REG_XMM21: 'XMM21', # 143
        UC_X86_REG_XMM22: 'XMM22', # 144
        UC_X86_REG_XMM23: 'XMM23', # 145
        UC_X86_REG_XMM24: 'XMM24', # 146
        UC_X86_REG_XMM25: 'XMM25', # 147
        UC_X86_REG_XMM26: 'XMM26', # 148
        UC_X86_REG_XMM27: 'XMM27', # 149
        UC_X86_REG_XMM28: 'XMM28', # 150
        UC_X86_REG_XMM29: 'XMM29', # 151
        UC_X86_REG_XMM30: 'XMM30', # 152
        UC_X86_REG_XMM31: 'XMM31', # 153
        UC_X86_REG_YMM0: 'YMM0', # 154
        UC_X86_REG_YMM1: 'YMM1', # 155
        UC_X86_REG_YMM2: 'YMM2', # 156
        UC_X86_REG_YMM3: 'YMM3', # 157
        UC_X86_REG_YMM4: 'YMM4', # 158
        UC_X86_REG_YMM5: 'YMM5', # 159
        UC_X86_REG_YMM6: 'YMM6', # 160
        UC_X86_REG_YMM7: 'YMM7', # 161
        UC_X86_REG_YMM8: 'YMM8', # 162
        UC_X86_REG_YMM9: 'YMM9', # 163
        UC_X86_REG_YMM10: 'YMM10', # 164
        UC_X86_REG_YMM11: 'YMM11', # 165
        UC_X86_REG_YMM12: 'YMM12', # 166
        UC_X86_REG_YMM13: 'YMM13', # 167
        UC_X86_REG_YMM14: 'YMM14', # 168
        UC_X86_REG_YMM15: 'YMM15', # 169
        UC_X86_REG_YMM16: 'YMM16', # 170
        UC_X86_REG_YMM17: 'YMM17', # 171
        UC_X86_REG_YMM18: 'YMM18', # 172
        UC_X86_REG_YMM19: 'YMM19', # 173
        UC_X86_REG_YMM20: 'YMM20', # 174
        UC_X86_REG_YMM21: 'YMM21', # 175
        UC_X86_REG_YMM22: 'YMM22', # 176
        UC_X86_REG_YMM23: 'YMM23', # 177
        UC_X86_REG_YMM24: 'YMM24', # 178
        UC_X86_REG_YMM25: 'YMM25', # 179
        UC_X86_REG_YMM26: 'YMM26', # 180
        UC_X86_REG_YMM27: 'YMM27', # 181
        UC_X86_REG_YMM28: 'YMM28', # 182
        UC_X86_REG_YMM29: 'YMM29', # 183
        UC_X86_REG_YMM30: 'YMM30', # 184
        UC_X86_REG_YMM31: 'YMM31', # 185
        UC_X86_REG_ZMM0: 'ZMM0', # 186
        UC_X86_REG_ZMM1: 'ZMM1', # 187
        UC_X86_REG_ZMM2: 'ZMM2', # 188
        UC_X86_REG_ZMM3: 'ZMM3', # 189
        UC_X86_REG_ZMM4: 'ZMM4', # 190
        UC_X86_REG_ZMM5: 'ZMM5', # 191
        UC_X86_REG_ZMM6: 'ZMM6', # 192
        UC_X86_REG_ZMM7: 'ZMM7', # 193
        UC_X86_REG_ZMM8: 'ZMM8', # 194
        UC_X86_REG_ZMM9: 'ZMM9', # 195
        UC_X86_REG_ZMM10: 'ZMM10', # 196
        UC_X86_REG_ZMM11: 'ZMM11', # 197
        UC_X86_REG_ZMM12: 'ZMM12', # 198
        UC_X86_REG_ZMM13: 'ZMM13', # 199
        UC_X86_REG_ZMM14: 'ZMM14', # 200
        UC_X86_REG_ZMM15: 'ZMM15', # 201
        UC_X86_REG_ZMM16: 'ZMM16', # 202
        UC_X86_REG_ZMM17: 'ZMM17', # 203
        UC_X86_REG_ZMM18: 'ZMM18', # 204
        UC_X86_REG_ZMM19: 'ZMM19', # 205
        UC_X86_REG_ZMM20: 'ZMM20', # 206
        UC_X86_REG_ZMM21: 'ZMM21', # 207
        UC_X86_REG_ZMM22: 'ZMM22', # 208
        UC_X86_REG_ZMM23: 'ZMM23', # 209
        UC_X86_REG_ZMM24: 'ZMM24', # 210
        UC_X86_REG_ZMM25: 'ZMM25', # 211
        UC_X86_REG_ZMM26: 'ZMM26', # 212
        UC_X86_REG_ZMM27: 'ZMM27', # 213
        UC_X86_REG_ZMM28: 'ZMM28', # 214
        UC_X86_REG_ZMM29: 'ZMM29', # 215
        UC_X86_REG_ZMM30: 'ZMM30', # 216
        UC_X86_REG_ZMM31: 'ZMM31', # 217
        UC_X86_REG_R8B: 'R8B', # 218
        UC_X86_REG_R9B: 'R9B', # 219
        UC_X86_REG_R10B: 'R10B', # 220
        UC_X86_REG_R11B: 'R11B', # 221
        UC_X86_REG_R12B: 'R12B', # 222
        UC_X86_REG_R13B: 'R13B', # 223
        UC_X86_REG_R14B: 'R14B', # 224
        UC_X86_REG_R15B: 'R15B', # 225
        UC_X86_REG_R8D: 'R8D', # 226
        UC_X86_REG_R9D: 'R9D', # 227
        UC_X86_REG_R10D: 'R10D', # 228
        UC_X86_REG_R11D: 'R11D', # 229
        UC_X86_REG_R12D: 'R12D', # 230
        UC_X86_REG_R13D: 'R13D', # 231
        UC_X86_REG_R14D: 'R14D', # 232
        UC_X86_REG_R15D: 'R15D', # 233
        UC_X86_REG_R8W: 'R8W', # 234
        UC_X86_REG_R9W: 'R9W', # 235
        UC_X86_REG_R10W: 'R10W', # 236
        UC_X86_REG_R11W: 'R11W', # 237
        UC_X86_REG_R12W: 'R12W', # 238
        UC_X86_REG_R13W: 'R13W', # 239
        UC_X86_REG_R14W: 'R14W', # 240
        UC_X86_REG_R15W: 'R15W', # 241
        UC_X86_REG_IDTR: 'IDTR', # 242
        UC_X86_REG_GDTR: 'GDTR', # 243
        UC_X86_REG_LDTR: 'LDTR', # 244
        UC_X86_REG_TR: 'TR', # 245
        UC_X86_REG_FPCW: 'FPCW', # 246
        UC_X86_REG_FPTAG: 'FPTAG', # 247
        UC_X86_REG_MSR: 'MSR', # 248
        UC_X86_REG_MXCSR: 'MXCSR', # 249
        UC_X86_REG_FS_BASE: 'FS_BASE', # 250
        UC_X86_REG_GS_BASE: 'GS_BASE', # 251
        UC_X86_REG_FLAGS: 'FLAGS', # 252
        UC_X86_REG_RFLAGS: 'RFLAGS', # 253
        UC_X86_REG_FIP: 'FIP', # 254
        UC_X86_REG_FCS: 'FCS', # 255
        UC_X86_REG_FDP: 'FDP', # 256
        UC_X86_REG_FDS: 'FDS', # 257
        UC_X86_REG_FOP: 'FOP' # 258
    }

    VARFMT = "<Q"
