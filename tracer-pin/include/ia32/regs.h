#ifndef REGS_IA32_H
#define REGS_IA32_H

#include "pin.H"
#include <unordered_map>
#include <utility>

/*
 * TODO: Documentation
 */
const std::unordered_map<REG, UINT32> REG_TO_SLEIGH = {
    std::pair<REG, UINT32>(REG::REG_EAX, 0),  std::pair<REG, UINT32>(REG::REG_ECX, 4),
    std::pair<REG, UINT32>(REG::REG_EDX, 8),  std::pair<REG, UINT32>(REG::REG_EBX, 12),
    std::pair<REG, UINT32>(REG::REG_ESP, 16), std::pair<REG, UINT32>(REG::REG_EBP, 20),
    std::pair<REG, UINT32>(REG::REG_ESI, 24), std::pair<REG, UINT32>(REG::REG_EDI, 28),
    std::pair<REG, UINT32>(REG::REG_AX, 0),   std::pair<REG, UINT32>(REG::REG_CX, 4),
    std::pair<REG, UINT32>(REG::REG_DX, 8),   std::pair<REG, UINT32>(REG::REG_BX, 12),
    std::pair<REG, UINT32>(REG::REG_SP, 16),  std::pair<REG, UINT32>(REG::REG_BP, 20),
    std::pair<REG, UINT32>(REG::REG_SI, 24),  std::pair<REG, UINT32>(REG::REG_DI, 28),
    std::pair<REG, UINT32>(REG::REG_AL, 0),   std::pair<REG, UINT32>(REG::REG_AH, 1),
    std::pair<REG, UINT32>(REG::REG_CL, 4),   std::pair<REG, UINT32>(REG::REG_CH, 5),
    std::pair<REG, UINT32>(REG::REG_DL, 8),   std::pair<REG, UINT32>(REG::REG_DH, 9),
    std::pair<REG, UINT32>(REG::REG_BL, 12),  std::pair<REG, UINT32>(REG::REG_BH, 13),
};

#endif
