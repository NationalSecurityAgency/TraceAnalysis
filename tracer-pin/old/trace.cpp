// clang-format off
#include <stdio.h>
#include "pin.H"

// Output Format:
//
// All records are type-value pairs. Type is always a one-byte value, values may have varible
// length.
//
// Types:
// 11xx xxxx - Extended type, lower 6 bits determined by subsequent byte
// 10xx xxxx - Register write (register number is encoded in the lower 6 bits, length is implied)
// 0100 xxxx - Memory read, length is stored in lower 4 bits
// 0110 xxxx - Memory write, length is stored in lower 4 bits
// 0101 xxxx - Memory read, length is in extended format (described below)
// 0111 xxxx - Memory write, length is in extended format (described below)
// 001x xxxx - Instruction, pc + insbytes (insbytes length stored in lower 5 bits)
//
// Extended format:
//
// For memory reads/writes whose length cannot be encoded in 4 bits, the length will be encoded in
// a twelve bit format as follows:
//
// +-----------+-----------+----------+
// | 01x1 hhhh | llll llll | bytes[0] |
// +-----------+-----------+----------+
//
// Resulting in the following length: 0xHLL. Zero-sized memory accesses must have their length
// encoded in the type byte and an extended memory access with a length of 0x000 should be
// interpreted as a length of 0x1000.
//
// Register Numbers:
//
// 0 - RDI
// 1 - RSI
// 2 - RBP
// 3 - RSP
// 4 - RBX
// 5 - RDX
// 6 - RCX
// 7 - RAX
// 8 - R8
// 9 - R9
// 10 - R10
// 11 - R11
// 12 - R12
// 13 - R13
// 14 - R14
// 15 - R15
//

#undef LOG
#define LOG

typedef struct tracer {
  OS_THREAD_ID tid;
  INT pid;
  UINT64 inscnt;
  FILE* trace;
} tracer_t;

tracer_t **tracers;
unsigned int num_tracers;
tracer_t *current_tracer;

static ADDRINT REGISTERS[16] = { 0 };
static const char * REGISTER_NAMES[16] = {
    "RDI",
    "RSI",
    "RBP",
    "RSP",
    "RBX",
    "RDX",
    "RCX",
    "RAX",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
};

static VOID* MEM_WRITE_ADDR = 0;
static UINT32 MEM_WRITE_SIZE = 0;

static UINT64 EVENTCNT = 0;


VOID SetCurrentTracer(OS_THREAD_ID tid, INT pid) {
  for(unsigned int i = 0; i < num_tracers; i++) {
    if(tracers[i] != NULL && tracers[i]->tid == tid && tracers[i]->pid == pid) {
      current_tracer = tracers[i];
      LOG( "[TRACE] tracing existing tid " + decstr(current_tracer->tid) + "\n" );
      return;
    }
  }
  if(num_tracers >= 65536) {
    current_tracer = NULL;
    return;
  }
  LOG( "[TRACE] tracing new tid " + decstr(tid) + "\n" );
  current_tracer = (tracer_t *)malloc(sizeof(tracer_t));
  current_tracer->tid = tid;
  current_tracer->pid = pid;
  current_tracer->inscnt = 0;
  char* fn = (char*)malloc(100);
  sprintf(fn, "trace_%d_%d.out", pid, tid);
  current_tracer->trace = fopen(fn, "w");
  tracers[num_tracers++] = current_tracer;
}

// Do nothing

VOID RecordPC(VOID* ip, UINT32 sz, const CONTEXT *ctx) {
    UINT8 type;

  OS_THREAD_ID tid = PIN_GetTid();
  INT pid = PIN_GetPid();
  if(!current_tracer || current_tracer->tid != tid || current_tracer->pid != pid) {
    SetCurrentTracer(tid, pid);
  }
  FILE* trace = current_tracer->trace;
  current_tracer->inscnt++;
  if((current_tracer->inscnt + 1)%100 == 0) fflush(current_tracer->trace);

    for (UINT8 reg = 0; reg < 16; reg++) {
        ADDRINT val;
        PIN_GetContextRegval(ctx, (REG)(reg + (int)REG_GR_BASE), reinterpret_cast<UINT8*>(&val));
        if (REGISTERS[reg] != val) {
            type = 0x80 | reg;
            LOG( "[TRACE] " + decstr(EVENTCNT++) + " REGWRITE " + REGISTER_NAMES[reg] + " = " + hexstr(val) + "\n" );
            fwrite(&type, sizeof(UINT8), 1, trace);
            fwrite(&val, sizeof(val), 1, trace);
            //fprintf(trace, "[REGWRITE] %s = %zx\n", REGISTER_NAMES[reg], val);
            REGISTERS[reg] = val;
        }
    }

    const UINT32 MAX_SIZE = 15;
    if (sz > MAX_SIZE) {
        LOG( "[ERROR] instruction size at " + hexstr(ip) + " exceeded 15 bytes: " + decstr(sz) + "\n" );
        return;
    }
    char bytes[15];
    UINT32 copied = PIN_SafeCopy(bytes, ip, sz);
    if (copied != sz) {
        LOG( "[ERROR] instruction at " + hexstr(ip) + " failed to copy " + decstr(sz) + " bytes\n" );
        return;
    }

    type = 0x20 | (sz & 0x1f);
    LOG( "[TRACE] " + decstr(EVENTCNT++) + " INS " + hexstr(ip) + "\n" );
    fwrite(&type, sizeof(UINT8), 1, trace);
    fwrite(&ip, sizeof(VOID*), 1, trace);
    fwrite(bytes, sizeof(UINT8), sz, trace);
    return;

    //fprintf(trace, "[PC] %p", ip);
    //for (UINT32 i = 0; i < sz; i++) {
    //    fprintf(trace, " %02x", bytes[i] & 0xff);
    //}
    //fprintf(trace, "\n");
}

VOID RecordMemRead(VOID* pc, VOID* addr, UINT32 sz) {
    UINT8 type;

  OS_THREAD_ID tid = PIN_GetTid();
  INT pid = PIN_GetPid();
  if(!current_tracer || current_tracer->tid != tid || current_tracer->pid != pid) {
    SetCurrentTracer(tid, pid);
  }
  FILE* trace = current_tracer->trace;

    if (sz > 0x1000) {
        LOG( "[ERROR] memory read size for " + hexstr(addr) + " exceeded 4096 bytes: " + decstr(sz) + "\n" );
        return;
    }
    char * bytes = (char *)alloca(sz);
    UINT32 copied = PIN_SafeCopy(bytes, addr, sz);
    if (copied != sz) {
        LOG( "[ERROR] failed to copy " + decstr(sz) + " bytes for memory read at " + hexstr(addr) + "\n");
        return;
    }

    if (sz < 16) {
        type = 0x40 | (sz & 0x0f);
        LOG( "[TRACE] " + decstr(EVENTCNT++) + " MEMREADSHORT\n" );
        fwrite(&type, sizeof(UINT8), 1, trace);
        fwrite(&addr, sizeof(VOID*), 1, trace);
        fwrite(bytes, sizeof(UINT8), sz, trace);
    } else if (sz == 4096) {
        type = 0x50;
        LOG( "[TRACE] " + decstr(EVENTCNT++) + " MEMREADLONG\n" );
        fwrite(&type, sizeof(UINT8), 1, trace);
        fwrite(&addr, sizeof(VOID*), 1, trace);
        fwrite(bytes, sizeof(UINT8), sz, trace);
    } else {
        UINT8 h = (UINT8)((sz & 0x0f00) >> 8);
        UINT8 l = (sz & 0xff);
        type = 0x50 | h;
        LOG( "[TRACE] " + decstr(EVENTCNT++) + " MEMREADLONG\n" );
        fwrite(&type, sizeof(UINT8), 1, trace);
        fwrite(&l, sizeof(UINT8), 1, trace);
        fwrite(&addr, sizeof(VOID*), 1, trace);
        fwrite(bytes, sizeof(UINT8), sz, trace);
    }

    return;

    //fprintf(trace, "[MEMREAD] PC:%p ADDR:%p", pc, addr);
    //for (UINT32 i = 0; i < sz; i++) {
    //    fprintf(trace, " %02x", bytes[i] & 0xff);
    //}
    //fprintf(trace, "\n");
}


VOID RecordMemWriteAddr(VOID* pc, VOID* addr, UINT32 sz) {
    MEM_WRITE_ADDR = addr;
    MEM_WRITE_SIZE = sz;
}

VOID RecordMemWriteData(VOID* pc) {
    VOID* addr = MEM_WRITE_ADDR;
    UINT32 sz = MEM_WRITE_SIZE;
    UINT8 type;


  OS_THREAD_ID tid = PIN_GetTid();
  INT pid = PIN_GetPid();
  if(!current_tracer || current_tracer->tid != tid || current_tracer->pid != pid) {
    SetCurrentTracer(tid, pid);
  }
  FILE* trace = current_tracer->trace;

    if (sz > 0x1000) {
        LOG( "[ERROR] memory write size for " + hexstr(addr) + " exceeded 4096 bytes: " + decstr(sz) + "\n" );
        return;
    }
    char * bytes = (char *)alloca(sz);
    UINT32 copied = PIN_SafeCopy(bytes, addr, sz);
    if (copied != sz) {
        LOG( "[ERROR] failed to copy " + decstr(sz) + " bytes for memory write at " + hexstr(addr) + "\n");
        return;
    }

    if (sz < 16) {
        type = 0x60 | (sz & 0x0f);
        LOG( "[TRACE] " + decstr(EVENTCNT++) + " MEMWRITESHORT\n" );
        fwrite(&type, sizeof(UINT8), 1, trace);
        fwrite(&addr, sizeof(VOID*), 1, trace);
        fwrite(bytes, sizeof(UINT8), sz, trace);
    } else if (sz == 4096) {
        type = 0x70;
        LOG( "[TRACE] " + decstr(EVENTCNT++) + " MEMWRITELONG\n" );
        fwrite(&type, sizeof(UINT8), 1, trace);
        fwrite(&addr, sizeof(VOID*), 1, trace);
        fwrite(bytes, sizeof(UINT8), sz, trace);
    } else {
        UINT8 h = (UINT8)((sz & 0x0f00) >> 8);
        UINT8 l = (sz & 0xff);
        type = 0x70 | h;
        LOG( "[TRACE] " + decstr(EVENTCNT++) + " MEMRWRITELONG\n" );
        fwrite(&type, sizeof(UINT8), 1, trace);
        fwrite(&l, sizeof(UINT8), 1, trace);
        fwrite(&addr, sizeof(VOID*), 1, trace);
        fwrite(bytes, sizeof(UINT8), sz, trace);
    }

    return;

    //fprintf(trace, "[MEMWRITE] PC:%p ADDR:%p", pc, addr);
    //for (UINT32 i = 0; i < sz; i++) {
    //    fprintf(trace, " %02x", bytes[i] & 0xff);
    //}
    //fprintf(trace, "\n");
}

VOID Instruction(INS ins, VOID* v) {

    INS_InsertCall(
        ins,
        IPOINT_BEFORE,
        (AFUNPTR)RecordPC,
        IARG_INST_PTR,
        IARG_UINT32, INS_Size(ins),
        IARG_CONST_CONTEXT,
        IARG_END
    );

    UINT32 memOperands = INS_MemoryOperandCount(ins);

    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsRead(ins, memOp) && INS_IsStandardMemop(ins)) {
            INS_InsertPredicatedCall(
                ins,
                IPOINT_BEFORE,
                (AFUNPTR)RecordMemRead,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_MEMORYOP_SIZE, memOp,
                IARG_END
            );
        }
        if (INS_MemoryOperandIsWritten(ins, memOp) && INS_IsStandardMemop(ins)) {
            INS_InsertPredicatedCall(
                ins,
                IPOINT_BEFORE,
                (AFUNPTR)RecordMemWriteAddr,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_MEMORYOP_SIZE, memOp,
                IARG_END
            );
            if (INS_IsValidForIpointAfter(ins)) {
                INS_InsertCall(
                    ins,
                    IPOINT_AFTER,
                    (AFUNPTR)RecordMemWriteData,
                    IARG_INST_PTR,
                    IARG_END
                );
            }
            if (INS_IsValidForIpointTakenBranch(ins)) {
                INS_InsertCall(
                    ins,
                    IPOINT_TAKEN_BRANCH,
                    (AFUNPTR)RecordMemWriteData,
                    IARG_INST_PTR,
                    IARG_END
                );
            }
        }
    }
}

VOID ImageLoad(IMG img, VOID* arg) {
    ADDRINT high = IMG_HighAddress(img);
    ADDRINT low = IMG_LowAddress(img);
    const std::string& name = IMG_Name(img);
    char fn[100];
    snprintf(fn, 100, "maps%d.out", PIN_GetPid());
    FILE *maps = fopen(fn, "a");
    fprintf(maps, "%s %p %p\n", name.c_str(), (VOID*)low, (VOID*)high);
    fflush(maps);
}

VOID Fini(INT32 code, VOID* v) {
  for(int i = 0; i < 65536; i++) {
    if (tracers[i] != NULL) {
      fclose(tracers[i]->trace);
    }
  }
}

INT32 Usage() {
    PIN_ERROR("This pintool produces an execution trace to be used with dataflow\n" +
            KNOB_BASE::StringKnobSummary() +
            "\n");
    return -1;
}


VOID instrument() {
  tracers = (tracer_t **)malloc(sizeof(tracer_t*)*65536);
  num_tracers = 0;

    char fn[100];
    snprintf(fn, 100, "maps%d.out", PIN_GetPid());
    FILE *maps = fopen(fn, "a");


  for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
    ADDRINT high = IMG_HighAddress(img);
    ADDRINT low = IMG_LowAddress(img);
    const std::string& name = IMG_Name(img);
    fprintf(maps, "%s %p %p\n", name.c_str(), (VOID*)low, (VOID*)high);
  }
  fclose(maps);
  IMG_AddInstrumentFunction(ImageLoad, (VOID*)0);
  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddFiniFunction(Fini, 0);
}

BOOL FollowChild(CHILD_PROCESS cProcess, VOID* userData) {
  //instrument();
  LOG("child proc: " + decstr(CHILD_PROCESS_GetId(cProcess)) + "\n");
  return TRUE;
}

int main(int argc, char **argv) {

  if (PIN_Init(argc, argv)) return Usage();

  PIN_AddFollowChildProcessFunction(FollowChild, 0);

  instrument();

  PIN_StartProgram();
  return 0;
}
// clang-format on
