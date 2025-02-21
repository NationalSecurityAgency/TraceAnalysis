from unicorn.arm64_const import *

from .lib import Arch

class Aarch64(Arch):
    ARCH_ID = 0x121

    TRACKED_REGISTERS = [
        (UC_ARM64_REG_X0, "<Q"),
        (UC_ARM64_REG_X1, "<Q"),
        (UC_ARM64_REG_X2, "<Q"),
        (UC_ARM64_REG_X3, "<Q"),
        (UC_ARM64_REG_X4, "<Q"),
        (UC_ARM64_REG_X5, "<Q"),
        (UC_ARM64_REG_X6, "<Q"),
        (UC_ARM64_REG_X7, "<Q"),
        (UC_ARM64_REG_X8, "<Q"),
        (UC_ARM64_REG_X9, "<Q"),
        (UC_ARM64_REG_X10, "<Q"),
        (UC_ARM64_REG_X11, "<Q"),
        (UC_ARM64_REG_X12, "<Q"),
        (UC_ARM64_REG_X13, "<Q"),
        (UC_ARM64_REG_X14, "<Q"),
        (UC_ARM64_REG_X15, "<Q"),
        (UC_ARM64_REG_X16, "<Q"),
        (UC_ARM64_REG_X17, "<Q"),
        (UC_ARM64_REG_X18, "<Q"),
        (UC_ARM64_REG_X19, "<Q"),
        (UC_ARM64_REG_X20, "<Q"),
        (UC_ARM64_REG_X21, "<Q"),
        (UC_ARM64_REG_X22, "<Q"),
        (UC_ARM64_REG_X23, "<Q"),
        (UC_ARM64_REG_X24, "<Q"),
        (UC_ARM64_REG_X25, "<Q"),
        (UC_ARM64_REG_X26, "<Q"),
        (UC_ARM64_REG_X27, "<Q"),
        (UC_ARM64_REG_X28, "<Q"),
        (UC_ARM64_REG_X29, "<Q"),
        (UC_ARM64_REG_X30, "<Q"),
        (UC_ARM64_REG_PC, "<Q"),
        (UC_ARM64_REG_SP, "<Q"),
    ]
    
    REGISTER_NAMES = {
        #UC_ARM64_REG_FP: 'FP', # 1, alias
        UC_ARM64_REG_X29: 'X29', # 1
        #UC_ARM64_REG_LR: 'LR', # 2, alias
        UC_ARM64_REG_X30: 'X30', # 2
        UC_ARM64_REG_NZCV: 'NZCV', # 3
        UC_ARM64_REG_SP: 'SP', # 4
        UC_ARM64_REG_WSP: 'WSP', # 5
        UC_ARM64_REG_WZR: 'WZR', # 6
        UC_ARM64_REG_XZR: 'XZR', # 7
        UC_ARM64_REG_B0: 'B0', # 8
        UC_ARM64_REG_B1: 'B1', # 9
        UC_ARM64_REG_B2: 'B2', # 10
        UC_ARM64_REG_B3: 'B3', # 11
        UC_ARM64_REG_B4: 'B4', # 12
        UC_ARM64_REG_B5: 'B5', # 13
        UC_ARM64_REG_B6: 'B6', # 14
        UC_ARM64_REG_B7: 'B7', # 15
        UC_ARM64_REG_B8: 'B8', # 16
        UC_ARM64_REG_B9: 'B9', # 17
        UC_ARM64_REG_B10: 'B10', # 18
        UC_ARM64_REG_B11: 'B11', # 19
        UC_ARM64_REG_B12: 'B12', # 20
        UC_ARM64_REG_B13: 'B13', # 21
        UC_ARM64_REG_B14: 'B14', # 22
        UC_ARM64_REG_B15: 'B15', # 23
        UC_ARM64_REG_B16: 'B16', # 24
        UC_ARM64_REG_B17: 'B17', # 25
        UC_ARM64_REG_B18: 'B18', # 26
        UC_ARM64_REG_B19: 'B19', # 27
        UC_ARM64_REG_B20: 'B20', # 28
        UC_ARM64_REG_B21: 'B21', # 29
        UC_ARM64_REG_B22: 'B22', # 30
        UC_ARM64_REG_B23: 'B23', # 31
        UC_ARM64_REG_B24: 'B24', # 32
        UC_ARM64_REG_B25: 'B25', # 33
        UC_ARM64_REG_B26: 'B26', # 34
        UC_ARM64_REG_B27: 'B27', # 35
        UC_ARM64_REG_B28: 'B28', # 36
        UC_ARM64_REG_B29: 'B29', # 37
        UC_ARM64_REG_B30: 'B30', # 38
        UC_ARM64_REG_B31: 'B31', # 39
        UC_ARM64_REG_D0: 'D0', # 40
        UC_ARM64_REG_D1: 'D1', # 41
        UC_ARM64_REG_D2: 'D2', # 42
        UC_ARM64_REG_D3: 'D3', # 43
        UC_ARM64_REG_D4: 'D4', # 44
        UC_ARM64_REG_D5: 'D5', # 45
        UC_ARM64_REG_D6: 'D6', # 46
        UC_ARM64_REG_D7: 'D7', # 47
        UC_ARM64_REG_D8: 'D8', # 48
        UC_ARM64_REG_D9: 'D9', # 49
        UC_ARM64_REG_D10: 'D10', # 50
        UC_ARM64_REG_D11: 'D11', # 51
        UC_ARM64_REG_D12: 'D12', # 52
        UC_ARM64_REG_D13: 'D13', # 53
        UC_ARM64_REG_D14: 'D14', # 54
        UC_ARM64_REG_D15: 'D15', # 55
        UC_ARM64_REG_D16: 'D16', # 56
        UC_ARM64_REG_D17: 'D17', # 57
        UC_ARM64_REG_D18: 'D18', # 58
        UC_ARM64_REG_D19: 'D19', # 59
        UC_ARM64_REG_D20: 'D20', # 60
        UC_ARM64_REG_D21: 'D21', # 61
        UC_ARM64_REG_D22: 'D22', # 62
        UC_ARM64_REG_D23: 'D23', # 63
        UC_ARM64_REG_D24: 'D24', # 64
        UC_ARM64_REG_D25: 'D25', # 65
        UC_ARM64_REG_D26: 'D26', # 66
        UC_ARM64_REG_D27: 'D27', # 67
        UC_ARM64_REG_D28: 'D28', # 68
        UC_ARM64_REG_D29: 'D29', # 69
        UC_ARM64_REG_D30: 'D30', # 70
        UC_ARM64_REG_D31: 'D31', # 71
        UC_ARM64_REG_H0: 'H0', # 72
        UC_ARM64_REG_H1: 'H1', # 73
        UC_ARM64_REG_H2: 'H2', # 74
        UC_ARM64_REG_H3: 'H3', # 75
        UC_ARM64_REG_H4: 'H4', # 76
        UC_ARM64_REG_H5: 'H5', # 77
        UC_ARM64_REG_H6: 'H6', # 78
        UC_ARM64_REG_H7: 'H7', # 79
        UC_ARM64_REG_H8: 'H8', # 80
        UC_ARM64_REG_H9: 'H9', # 81
        UC_ARM64_REG_H10: 'H10', # 82
        UC_ARM64_REG_H11: 'H11', # 83
        UC_ARM64_REG_H12: 'H12', # 84
        UC_ARM64_REG_H13: 'H13', # 85
        UC_ARM64_REG_H14: 'H14', # 86
        UC_ARM64_REG_H15: 'H15', # 87
        UC_ARM64_REG_H16: 'H16', # 88
        UC_ARM64_REG_H17: 'H17', # 89
        UC_ARM64_REG_H18: 'H18', # 90
        UC_ARM64_REG_H19: 'H19', # 91
        UC_ARM64_REG_H20: 'H20', # 92
        UC_ARM64_REG_H21: 'H21', # 93
        UC_ARM64_REG_H22: 'H22', # 94
        UC_ARM64_REG_H23: 'H23', # 95
        UC_ARM64_REG_H24: 'H24', # 96
        UC_ARM64_REG_H25: 'H25', # 97
        UC_ARM64_REG_H26: 'H26', # 98
        UC_ARM64_REG_H27: 'H27', # 99
        UC_ARM64_REG_H28: 'H28', # 100
        UC_ARM64_REG_H29: 'H29', # 101
        UC_ARM64_REG_H30: 'H30', # 102
        UC_ARM64_REG_H31: 'H31', # 103
        UC_ARM64_REG_Q0: 'Q0', # 104
        UC_ARM64_REG_Q1: 'Q1', # 105
        UC_ARM64_REG_Q2: 'Q2', # 106
        UC_ARM64_REG_Q3: 'Q3', # 107
        UC_ARM64_REG_Q4: 'Q4', # 108
        UC_ARM64_REG_Q5: 'Q5', # 109
        UC_ARM64_REG_Q6: 'Q6', # 110
        UC_ARM64_REG_Q7: 'Q7', # 111
        UC_ARM64_REG_Q8: 'Q8', # 112
        UC_ARM64_REG_Q9: 'Q9', # 113
        UC_ARM64_REG_Q10: 'Q10', # 114
        UC_ARM64_REG_Q11: 'Q11', # 115
        UC_ARM64_REG_Q12: 'Q12', # 116
        UC_ARM64_REG_Q13: 'Q13', # 117
        UC_ARM64_REG_Q14: 'Q14', # 118
        UC_ARM64_REG_Q15: 'Q15', # 119
        UC_ARM64_REG_Q16: 'Q16', # 120
        UC_ARM64_REG_Q17: 'Q17', # 121
        UC_ARM64_REG_Q18: 'Q18', # 122
        UC_ARM64_REG_Q19: 'Q19', # 123
        UC_ARM64_REG_Q20: 'Q20', # 124
        UC_ARM64_REG_Q21: 'Q21', # 125
        UC_ARM64_REG_Q22: 'Q22', # 126
        UC_ARM64_REG_Q23: 'Q23', # 127
        UC_ARM64_REG_Q24: 'Q24', # 128
        UC_ARM64_REG_Q25: 'Q25', # 129
        UC_ARM64_REG_Q26: 'Q26', # 130
        UC_ARM64_REG_Q27: 'Q27', # 131
        UC_ARM64_REG_Q28: 'Q28', # 132
        UC_ARM64_REG_Q29: 'Q29', # 133
        UC_ARM64_REG_Q30: 'Q30', # 134
        UC_ARM64_REG_Q31: 'Q31', # 135
        UC_ARM64_REG_S0: 'S0', # 136
        UC_ARM64_REG_S1: 'S1', # 137
        UC_ARM64_REG_S2: 'S2', # 138
        UC_ARM64_REG_S3: 'S3', # 139
        UC_ARM64_REG_S4: 'S4', # 140
        UC_ARM64_REG_S5: 'S5', # 141
        UC_ARM64_REG_S6: 'S6', # 142
        UC_ARM64_REG_S7: 'S7', # 143
        UC_ARM64_REG_S8: 'S8', # 144
        UC_ARM64_REG_S9: 'S9', # 145
        UC_ARM64_REG_S10: 'S10', # 146
        UC_ARM64_REG_S11: 'S11', # 147
        UC_ARM64_REG_S12: 'S12', # 148
        UC_ARM64_REG_S13: 'S13', # 149
        UC_ARM64_REG_S14: 'S14', # 150
        UC_ARM64_REG_S15: 'S15', # 151
        UC_ARM64_REG_S16: 'S16', # 152
        UC_ARM64_REG_S17: 'S17', # 153
        UC_ARM64_REG_S18: 'S18', # 154
        UC_ARM64_REG_S19: 'S19', # 155
        UC_ARM64_REG_S20: 'S20', # 156
        UC_ARM64_REG_S21: 'S21', # 157
        UC_ARM64_REG_S22: 'S22', # 158
        UC_ARM64_REG_S23: 'S23', # 159
        UC_ARM64_REG_S24: 'S24', # 160
        UC_ARM64_REG_S25: 'S25', # 161
        UC_ARM64_REG_S26: 'S26', # 162
        UC_ARM64_REG_S27: 'S27', # 163
        UC_ARM64_REG_S28: 'S28', # 164
        UC_ARM64_REG_S29: 'S29', # 165
        UC_ARM64_REG_S30: 'S30', # 166
        UC_ARM64_REG_S31: 'S31', # 167
        UC_ARM64_REG_W0: 'W0', # 168
        UC_ARM64_REG_W1: 'W1', # 169
        UC_ARM64_REG_W2: 'W2', # 170
        UC_ARM64_REG_W3: 'W3', # 171
        UC_ARM64_REG_W4: 'W4', # 172
        UC_ARM64_REG_W5: 'W5', # 173
        UC_ARM64_REG_W6: 'W6', # 174
        UC_ARM64_REG_W7: 'W7', # 175
        UC_ARM64_REG_W8: 'W8', # 176
        UC_ARM64_REG_W9: 'W9', # 177
        UC_ARM64_REG_W10: 'W10', # 178
        UC_ARM64_REG_W11: 'W11', # 179
        UC_ARM64_REG_W12: 'W12', # 180
        UC_ARM64_REG_W13: 'W13', # 181
        UC_ARM64_REG_W14: 'W14', # 182
        UC_ARM64_REG_W15: 'W15', # 183
        UC_ARM64_REG_W16: 'W16', # 184
        UC_ARM64_REG_W17: 'W17', # 185
        UC_ARM64_REG_W18: 'W18', # 186
        UC_ARM64_REG_W19: 'W19', # 187
        UC_ARM64_REG_W20: 'W20', # 188
        UC_ARM64_REG_W21: 'W21', # 189
        UC_ARM64_REG_W22: 'W22', # 190
        UC_ARM64_REG_W23: 'W23', # 191
        UC_ARM64_REG_W24: 'W24', # 192
        UC_ARM64_REG_W25: 'W25', # 193
        UC_ARM64_REG_W26: 'W26', # 194
        UC_ARM64_REG_W27: 'W27', # 195
        UC_ARM64_REG_W28: 'W28', # 196
        UC_ARM64_REG_W29: 'W29', # 197
        UC_ARM64_REG_W30: 'W30', # 198
        UC_ARM64_REG_X0: 'X0', # 199
        UC_ARM64_REG_X1: 'X1', # 200
        UC_ARM64_REG_X2: 'X2', # 201
        UC_ARM64_REG_X3: 'X3', # 202
        UC_ARM64_REG_X4: 'X4', # 203
        UC_ARM64_REG_X5: 'X5', # 204
        UC_ARM64_REG_X6: 'X6', # 205
        UC_ARM64_REG_X7: 'X7', # 206
        UC_ARM64_REG_X8: 'X8', # 207
        UC_ARM64_REG_X9: 'X9', # 208
        UC_ARM64_REG_X10: 'X10', # 209
        UC_ARM64_REG_X11: 'X11', # 210
        UC_ARM64_REG_X12: 'X12', # 211
        UC_ARM64_REG_X13: 'X13', # 212
        UC_ARM64_REG_X14: 'X14', # 213
        UC_ARM64_REG_X15: 'X15', # 214
        #UC_ARM64_REG_IP0: 'IP0', # 215, alias
        UC_ARM64_REG_X16: 'X16', # 215
        #UC_ARM64_REG_IP1: 'IP1', # 216, alias
        UC_ARM64_REG_X17: 'X17', # 216
        UC_ARM64_REG_X18: 'X18', # 217
        UC_ARM64_REG_X19: 'X19', # 218
        UC_ARM64_REG_X20: 'X20', # 219
        UC_ARM64_REG_X21: 'X21', # 220
        UC_ARM64_REG_X22: 'X22', # 221
        UC_ARM64_REG_X23: 'X23', # 222
        UC_ARM64_REG_X24: 'X24', # 223
        UC_ARM64_REG_X25: 'X25', # 224
        UC_ARM64_REG_X26: 'X26', # 225
        UC_ARM64_REG_X27: 'X27', # 226
        UC_ARM64_REG_X28: 'X28', # 227
        UC_ARM64_REG_V0: 'V0', # 228
        UC_ARM64_REG_V1: 'V1', # 229
        UC_ARM64_REG_V2: 'V2', # 230
        UC_ARM64_REG_V3: 'V3', # 231
        UC_ARM64_REG_V4: 'V4', # 232
        UC_ARM64_REG_V5: 'V5', # 233
        UC_ARM64_REG_V6: 'V6', # 234
        UC_ARM64_REG_V7: 'V7', # 235
        UC_ARM64_REG_V8: 'V8', # 236
        UC_ARM64_REG_V9: 'V9', # 237
        UC_ARM64_REG_V10: 'V10', # 238
        UC_ARM64_REG_V11: 'V11', # 239
        UC_ARM64_REG_V12: 'V12', # 240
        UC_ARM64_REG_V13: 'V13', # 241
        UC_ARM64_REG_V14: 'V14', # 242
        UC_ARM64_REG_V15: 'V15', # 243
        UC_ARM64_REG_V16: 'V16', # 244
        UC_ARM64_REG_V17: 'V17', # 245
        UC_ARM64_REG_V18: 'V18', # 246
        UC_ARM64_REG_V19: 'V19', # 247
        UC_ARM64_REG_V20: 'V20', # 248
        UC_ARM64_REG_V21: 'V21', # 249
        UC_ARM64_REG_V22: 'V22', # 250
        UC_ARM64_REG_V23: 'V23', # 251
        UC_ARM64_REG_V24: 'V24', # 252
        UC_ARM64_REG_V25: 'V25', # 253
        UC_ARM64_REG_V26: 'V26', # 254
        UC_ARM64_REG_V27: 'V27', # 255
        UC_ARM64_REG_V28: 'V28', # 256
        UC_ARM64_REG_V29: 'V29', # 257
        UC_ARM64_REG_V30: 'V30', # 258
        UC_ARM64_REG_V31: 'V31', # 259
        UC_ARM64_REG_PC: 'PC', # 260
        UC_ARM64_REG_CPACR_EL1: 'CPACR_EL1', # 261
        UC_ARM64_REG_TPIDR_EL0: 'TPIDR_EL0', # 262
        UC_ARM64_REG_TPIDRRO_EL0: 'TPIDRRO_EL0', # 263
        UC_ARM64_REG_TPIDR_EL1: 'TPIDR_EL1', # 264
        UC_ARM64_REG_PSTATE: 'PSTATE', # 265
        UC_ARM64_REG_ELR_EL0: 'ELR_EL0', # 266
        UC_ARM64_REG_ELR_EL1: 'ELR_EL1', # 267
        UC_ARM64_REG_ELR_EL2: 'ELR_EL2', # 268
        UC_ARM64_REG_ELR_EL3: 'ELR_EL3', # 269
        UC_ARM64_REG_SP_EL0: 'SP_EL0', # 270
        UC_ARM64_REG_SP_EL1: 'SP_EL1', # 271
        UC_ARM64_REG_SP_EL2: 'SP_EL2', # 272
        UC_ARM64_REG_SP_EL3: 'SP_EL3', # 273
        UC_ARM64_REG_TTBR0_EL1: 'TTBR0_EL1', # 274
        UC_ARM64_REG_TTBR1_EL1: 'TTBR1_EL1', # 275
        UC_ARM64_REG_ESR_EL0: 'ESR_EL0', # 276
        UC_ARM64_REG_ESR_EL1: 'ESR_EL1', # 277
        UC_ARM64_REG_ESR_EL2: 'ESR_EL2', # 278
        UC_ARM64_REG_ESR_EL3: 'ESR_EL3', # 279
        UC_ARM64_REG_FAR_EL0: 'FAR_EL0', # 280
        UC_ARM64_REG_FAR_EL1: 'FAR_EL1', # 281
        UC_ARM64_REG_FAR_EL2: 'FAR_EL2', # 282
        UC_ARM64_REG_FAR_EL3: 'FAR_EL3', # 283
        UC_ARM64_REG_PAR_EL1: 'PAR_EL1', # 284
        UC_ARM64_REG_MAIR_EL1: 'MAIR_EL1', # 285
        UC_ARM64_REG_VBAR_EL0: 'VBAR_EL0', # 286
        UC_ARM64_REG_VBAR_EL1: 'VBAR_EL1', # 287
        UC_ARM64_REG_VBAR_EL2: 'VBAR_EL2', # 288
        UC_ARM64_REG_VBAR_EL3: 'VBAR_EL3', # 289
        UC_ARM64_REG_CP_REG: 'CP_REG', # 290
        UC_ARM64_REG_FPCR: 'FPCR', # 291
        UC_ARM64_REG_FPSR: 'FPSR' # 292
    }
    
    VARFMT = "<Q"
