#ifndef REGS_INTEL64_H
#define REGS_INTEL64_H

#include "pin.H"
#include <unordered_map>
#include <utility>

/*
 * TODO: Documentation
 */
const std::unordered_map<REG, UINT32> REG_TO_SLEIGH = {
    std::pair<REG, UINT32>(REG::REG_RAX, 0),    std::pair<REG, UINT32>(REG::REG_RCX, 8),
    std::pair<REG, UINT32>(REG::REG_RDX, 16),   std::pair<REG, UINT32>(REG::REG_RBX, 24),
    std::pair<REG, UINT32>(REG::REG_RSP, 32),   std::pair<REG, UINT32>(REG::REG_RBP, 40),
    std::pair<REG, UINT32>(REG::REG_RSI, 48),   std::pair<REG, UINT32>(REG::REG_RDI, 56),
    std::pair<REG, UINT32>(REG::REG_EAX, 0),    std::pair<REG, UINT32>(REG::REG_ECX, 8),
    std::pair<REG, UINT32>(REG::REG_EDX, 16),   std::pair<REG, UINT32>(REG::REG_EBX, 24),
    std::pair<REG, UINT32>(REG::REG_ESP, 32),   std::pair<REG, UINT32>(REG::REG_EBP, 40),
    std::pair<REG, UINT32>(REG::REG_ESI, 48),   std::pair<REG, UINT32>(REG::REG_EDI, 56),
    std::pair<REG, UINT32>(REG::REG_AX, 0),     std::pair<REG, UINT32>(REG::REG_CX, 8),
    std::pair<REG, UINT32>(REG::REG_DX, 16),    std::pair<REG, UINT32>(REG::REG_BX, 24),
    std::pair<REG, UINT32>(REG::REG_SP, 32),    std::pair<REG, UINT32>(REG::REG_BP, 40),
    std::pair<REG, UINT32>(REG::REG_SI, 48),    std::pair<REG, UINT32>(REG::REG_DI, 56),
    std::pair<REG, UINT32>(REG::REG_AL, 0),     std::pair<REG, UINT32>(REG::REG_AH, 1),
    std::pair<REG, UINT32>(REG::REG_CL, 8),     std::pair<REG, UINT32>(REG::REG_CH, 9),
    std::pair<REG, UINT32>(REG::REG_DL, 16),    std::pair<REG, UINT32>(REG::REG_DH, 17),
    std::pair<REG, UINT32>(REG::REG_BL, 24),    std::pair<REG, UINT32>(REG::REG_BH, 25),
    std::pair<REG, UINT32>(REG::REG_R8, 128),   std::pair<REG, UINT32>(REG::REG_R9, 136),
    std::pair<REG, UINT32>(REG::REG_R10, 144),  std::pair<REG, UINT32>(REG::REG_R11, 152),
    std::pair<REG, UINT32>(REG::REG_R12, 160),  std::pair<REG, UINT32>(REG::REG_R13, 168),
    std::pair<REG, UINT32>(REG::REG_R14, 176),  std::pair<REG, UINT32>(REG::REG_R15, 184),
    std::pair<REG, UINT32>(REG::REG_R8D, 128),  std::pair<REG, UINT32>(REG::REG_R9D, 136),
    std::pair<REG, UINT32>(REG::REG_R10D, 144), std::pair<REG, UINT32>(REG::REG_R11D, 152),
    std::pair<REG, UINT32>(REG::REG_R12D, 160), std::pair<REG, UINT32>(REG::REG_R13D, 168),
    std::pair<REG, UINT32>(REG::REG_R14D, 176), std::pair<REG, UINT32>(REG::REG_R15D, 184),
    std::pair<REG, UINT32>(REG::REG_R8W, 128),  std::pair<REG, UINT32>(REG::REG_R9W, 136),
    std::pair<REG, UINT32>(REG::REG_R10W, 144), std::pair<REG, UINT32>(REG::REG_R11W, 152),
    std::pair<REG, UINT32>(REG::REG_R12W, 160), std::pair<REG, UINT32>(REG::REG_R13W, 168),
    std::pair<REG, UINT32>(REG::REG_R14W, 176), std::pair<REG, UINT32>(REG::REG_R15W, 184),
    std::pair<REG, UINT32>(REG::REG_R8B, 128),  std::pair<REG, UINT32>(REG::REG_R9B, 136),
    std::pair<REG, UINT32>(REG::REG_R10B, 144), std::pair<REG, UINT32>(REG::REG_R11B, 152),
    std::pair<REG, UINT32>(REG::REG_R12B, 160), std::pair<REG, UINT32>(REG::REG_R13B, 168),
    std::pair<REG, UINT32>(REG::REG_R14B, 176), std::pair<REG, UINT32>(REG::REG_R15B, 184),
};

#endif
