#include "pintool.h"     /* OutFile, MapFile, TickLock, WriteMap*, Emit<...>*/
#include "pin.H"         /* PIN_*, INS_*, UINT8, ADDRINT, etc...            */
#include "regs.h"        /* REG_TO_SLEIGH                                   */
#include "tool_macros.h" /* LOG                                             */
#include "trace.h"       /* MAGIC, ARCH_MAGIC, X86, X86_64, WriteRecordTo.. */
#include <iostream>      /* std::{cerr, endl}                               */
#include <stdio.h>       /* FILE, fopen, fwrite, fflush, fclose             */
#include <string>        /* std::string                                     */

using std::cerr;
using std::endl;
using std::string;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,
                            "pintool",
                            "o",
                            "trace",
                            "Output file to write trace data");

/* Globals */

// Write to OutFile, since stdout and stderr may be closed by the application.
static FILE* OutFile;
static FILE* MapFile;

/*
 * Global LOCK to synchronize instructions across threads.
 *
 * The lock should be held from an the first instrumentation hook (EmitPc) until
 * the final instrumentation hook (EmitInstruction), which should guarantee that
 * all memory operations emited match what was seen at the time the instruction
 * was executed. It is called 'TickLock' because under dataflow analysis,
 * 'ticks' correspond to instructions.
 */
static PIN_LOCK TickLock;

/*
 * Size of the current instruction. Only used to emit the final instruction
 * record when a fatal exception occurs. Should always be protected by TickLock.
 */
static USIZE CurInstSize;

INT32
Usage()
{
    cerr << "This tool emits a trace of the instrumented program." << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int
main(int argc, char** argv)
{
    // Initialize the pin lock
    PIN_InitLock(&TickLock);

    if (PIN_Init(argc, argv))
        return Usage();

    string fname_base = KnobOutputFile.Value();
    string fname = (fname_base + "." + std::to_string(PIN_GetPid()));

    OutFile = fopen(fname.c_str(), "wb");
    MapFile = fopen("maps.jsonl", "wb");
    if (NULL == OutFile || NULL == MapFile) {
        cerr << "Error opening file: " << fname << "!" << endl;
        return -1;
    }
    cerr << "Writing trace data to " << fname << "..." << endl;

    // Start Emitting Trace Data
    WriteRecordToFile(RecordKind::MagicRecord, (UINT8*)MAGIC, sizeof(MAGIC), OutFile);

#ifdef INTEL64
    WriteRecordToFile(RecordKind::ArchRecord, (UINT8*)&ARCH_X64, sizeof(UINT32), OutFile);
#else
    WriteRecordToFile(RecordKind::ArchRecord, (UINT8*)&ARCH_X86, sizeof(UINT32), OutFile);
#endif

    for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
        WriteMapToJsonFile(img, (VOID*)0);
    }

    // Start pintool
    IMG_AddInstrumentFunction(WriteMapToJsonFile, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddContextChangeFunction(ContextChange, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddForkFunction(FPOINT_BEFORE, BeforeFork, 0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, AfterForkInParent, 0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */

VOID
Instruction(INS ins, VOID* _v)
{
    // Write Pc record to OutFile to indicate a new instruction
    // We force this callback to be first, using IARG_CALL_ORDER.
    INS_InsertCall(ins,
                   IPOINT_BEFORE,
                   (AFUNPTR)EmitPc,
                   IARG_THREAD_ID,
                   IARG_INST_PTR,
                   IARG_ADDRINT,
                   INS_Size(ins),
                   IARG_CALL_ORDER,
                   CALL_ORDER_FIRST,
                   IARG_END);

    UINT32 opCount = INS_OperandCount(ins);
    for (UINT32 op = 0; op < opCount; op++) {
        // TODO: Write Registers
        if (INS_OperandIsReg(ins, op)) {
            REG reg = INS_OperandReg(ins, op);

            if (REG_INVALID() == reg) {
                // TODO: Log error?
                continue;
            }

            // TODO: check for fs/gs registers?
            if (!REG_is_gr(reg)) {
                continue;
            }

            // Emit RegRead Record
            if (INS_RegRContain(ins, reg)) {
                INS_InsertCall(ins,
                               IPOINT_BEFORE,
                               (AFUNPTR)EmitRegRead,
                               IARG_THREAD_ID,
                               IARG_UINT32,
                               reg,
                               IARG_REG_VALUE,
                               reg,
                               IARG_END);
            }

            // Emit RegWrite Record
            if (INS_RegWContain(ins, reg) && INS_IsValidForIpointAfter(ins)) {
                INS_InsertCall(ins,
                               IPOINT_AFTER,
                               (AFUNPTR)EmitRegWrite,
                               IARG_THREAD_ID,
                               IARG_UINT32,
                               reg,
                               IARG_REG_VALUE,
                               reg,
                               IARG_END);
            }
        }
    }

    // Write Memory Reads/Writes
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        // Ignore unconventional memOps (vectorized memory ref)
        if (!INS_IsStandardMemop(ins)) {
            continue;
        }

        // Emit Memory Read Record
        if (INS_MemoryOperandIsRead(ins, memOp)) {
            INS_InsertPredicatedCall(ins,
                                     IPOINT_BEFORE,
                                     (AFUNPTR)EmitMemRead,
                                     IARG_THREAD_ID,
                                     IARG_MEMORYOP_EA,
                                     memOp,
                                     IARG_MEMORYOP_SIZE,
                                     memOp,
                                     IARG_END);
        }

        // Emit Memory Write Record
        if (INS_MemoryOperandIsWritten(ins, memOp)) {
            // Hook after memory is written to save exact bytes.
            if (INS_IsValidForIpointAfter(ins)) {
                INS_InsertCall(ins,
                               IPOINT_AFTER,
                               (AFUNPTR)EmitMemWrite,
                               IARG_THREAD_ID,
                               IARG_MEMORYOP_EA,
                               memOp,
                               IARG_MEMORYOP_SIZE,
                               memOp,
                               IARG_END);
            }

            // Handle branching case (Ex. cmov). Write record if branch is taken
            if (INS_IsValidForIpointTakenBranch(ins)) {
                INS_InsertCall(ins,
                               IPOINT_TAKEN_BRANCH,
                               (AFUNPTR)EmitMemWrite,
                               IARG_THREAD_ID,
                               IARG_MEMORYOP_EA,
                               memOp,
                               IARG_MEMORYOP_SIZE,
                               memOp,
                               IARG_END);
            }

            /*
             * NOTE:
             * Unsure if IPOINT_TAKEN_BRANCH and IPOINT_AFTER could overlap.
             * Maybe needs to be an `else-if`, but only if your expecting to run
             * non-standard / malicous code. For example, if you jumped to the
             * next instruction you might get a double write record.
             *
             * I would rather err on the side of emitting extra records rather than
             * missing some records.
             */
        }
    }

    // Emit instruction record for dataflow to process. Then dataflow will compare
    // the reads/writes above to the emulated results.
    if (INS_IsValidForIpointAfter(ins)) {
        INS_InsertCall(ins,
                       IPOINT_AFTER,
                       (AFUNPTR)EmitInstruction,
                       IARG_THREAD_ID,
                       IARG_INST_PTR,
                       IARG_ADDRINT,
                       INS_Size(ins),
                       IARG_CALL_ORDER,
                       CALL_ORDER_LAST,
                       IARG_END);
    }

    if (INS_IsValidForIpointTakenBranch(ins)) {
        INS_InsertCall(ins,
                       IPOINT_TAKEN_BRANCH,
                       (AFUNPTR)EmitInstruction,
                       IARG_THREAD_ID,
                       IARG_INST_PTR,
                       IARG_ADDRINT,
                       INS_Size(ins),
                       IARG_CALL_ORDER,
                       CALL_ORDER_LAST,
                       IARG_END);
    }

    if (!INS_IsValidForIpointAfter(ins) && !INS_IsValidForIpointTakenBranch(ins)) {
        // Insert a hook to EmitInstruction at the end of the IPOINT_BEFORE area
        // only if it is invalid to do so after the instruction. It seems like
        // this only happens on syscalls.
        INS_InsertCall(ins,
                       IPOINT_BEFORE,
                       (AFUNPTR)EmitInstruction,
                       IARG_THREAD_ID,
                       IARG_INST_PTR,
                       IARG_ADDRINT,
                       INS_Size(ins),
                       IARG_CALL_ORDER,
                       CALL_ORDER_LAST,
                       IARG_END);
    }
}

VOID
ContextChange(THREADID threadid,
              CONTEXT_CHANGE_REASON reason,
              const CONTEXT* from,
              CONTEXT* to,
              INT32 info,
              VOID* _v)
{
    /* Outsanding Questions:
     * - Should we only release the lock if there's an exception?
     * - Do we actually want to emit the instruction record?
     *   - Did the instruction execute and cause the exception? So yes?
     *   - We are also missing write records because Pin changed our context. Do
     *     we care about these?
     */
    string ctx_msg = "ContextChange(" + decstr(reason) + ")";
    switch (reason) {
        case CONTEXT_CHANGE_REASON_FATALSIGNAL:
            // Receipt of fatal Unix signal.
            LOG(ctx_msg + " received fatal Unix signal [" + decstr(info) + "].\n");

            if (from) {
                ADDRINT pc = PIN_GetContextReg(from, REG::REG_INST_PTR);
                EmitInstruction(threadid, pc, CurInstSize);
            }

            fflush(OutFile); // TODO: Check error
            fclose(OutFile); // TODO: Check error

            PIN_ReleaseLock(&TickLock);
            break;
        case CONTEXT_CHANGE_REASON_SIGNAL:
            // Receipt of handled Unix signal.
            LOG(ctx_msg + " received handled Unix signal [" + decstr(info) + "].\n");
            break;
        case CONTEXT_CHANGE_REASON_SIGRETURN:
            // Return from Unix signal handler.
            LOG(ctx_msg + " returned from Unix signal handler.\n");
            break;
        case CONTEXT_CHANGE_REASON_APC:
            // Receipt of Windows APC.
            LOG(ctx_msg + " received Windows APC signal.\n");
            break;
        case CONTEXT_CHANGE_REASON_EXCEPTION:
            // Receipt of Windows exception.
            LOG(ctx_msg + " received Windows exception signal [0x" + hexstr(info) + "].\n");

            if (from) {
                ADDRINT pc = PIN_GetContextReg(from, REG::REG_INST_PTR);
                EmitInstruction(threadid, pc, CurInstSize);
            }

            fflush(OutFile); // TODO: Check error
            fclose(OutFile); // TODO: Check error

            PIN_ReleaseLock(&TickLock);
            break;
        case CONTEXT_CHANGE_REASON_CALLBACK:
            // Receipt of Windows call-back.
            LOG(ctx_msg + " received Windows call-back signal.\n");
            break;
    }
}

VOID
ThreadStart(THREADID _threadid, CONTEXT* _ctxt, INT32 _flags, VOID* _v)
{
    LOG(decstr(_threadid) + "Thread Initialized\n");
}

VOID
BeforeFork(THREADID _threadid, const CONTEXT* _ctxt, VOID* _arg)
{
    LOG(decstr(_threadid) + " - Before fork, flushing OutFile...\n");
    fflush(OutFile); // TODO: Why do we need this load bearing fflush()..?
}

VOID
AfterForkInParent(THREADID _threadid, const CONTEXT* _ctxt, VOID* _arg)
{
    LOG(decstr(_threadid) + " - After fork in parent, flushing OutFile\n");
}

VOID
AfterForkInChild(THREADID threadid, const CONTEXT* _ctx, VOID* _v)
{
    // Close file descriptor assocaited with parent process
    fclose(OutFile);

    PIN_GetLock(&TickLock, threadid + 1);

    // Open a new file using the current pid in the file name
    // TODO: also reset maps file? Use global struct?
    string fname_base = KnobOutputFile.Value();
    string fname = (fname_base + "." + std::to_string(PIN_GetPid()));
    OutFile = fopen(fname.c_str(), "wb");

    // Emit trace header - TODO: put code into function
    WriteRecordToFile(RecordKind::MagicRecord, (UINT8*)MAGIC, sizeof(MAGIC), OutFile);

#ifdef INTEL64
    WriteRecordToFile(RecordKind::ArchRecord, (UINT8*)&ARCH_X64, sizeof(UINT32), OutFile);
#else
    WriteRecordToFile(RecordKind::ArchRecord, (UINT8*)&ARCH_X86, sizeof(UINT32), OutFile);
#endif

    cerr << "Writing trace data to " << fname << "..." << endl;
    // TODO: Maybe we want to emit register values from `_ctxt`? Also a current
    // InstructionCount?

    PIN_ReleaseLock(&TickLock);
}

VOID
Fini(INT32 code, VOID* _v)
{
    fflush(OutFile); // TODO: Check error
    fclose(OutFile); // TODO: Check error
}

/* ===================================================================== */

VOID
EmitPc(THREADID threadid, ADDRINT pc, USIZE ins_size)
{
    // Grab TickLock for the entire instruction
    PIN_GetLock(&TickLock, threadid + 1);

    // Save current instruction size in case of exception
    CurInstSize = ins_size;

    EmitThreadMeta();
    WriteRecordToFile(RecordKind::PcRecord, (UINT8*)&pc, sizeof(pc), OutFile);
}

VOID
EmitInstruction(THREADID threadid, ADDRINT pc, USIZE ins_size)
{
    USIZE data_size = sizeof(pc) + ins_size;
    UINT8* data = (UINT8*)alloca(data_size);

    *(ADDRINT*)data = pc;
    PIN_SafeCopy(data + sizeof(pc), (VOID*)pc, ins_size);

    WriteRecordToFile(RecordKind::InstructionRecord, data, data_size, OutFile);

    // Release TickLock because we are finishied writing records for this
    // instruction
    PIN_ReleaseLock(&TickLock);
}

VOID
EmitMemWrite(THREADID threadid, ADDRINT addr, UINT32 write_size)
{
    USIZE data_size = sizeof(addr) + write_size;
    UINT8* data = (UINT8*)alloca(data_size);

    *(ADDRINT*)data = addr;
    PIN_SafeCopy(data + sizeof(addr), (VOID*)addr, write_size);

    WriteRecordToFile(RecordKind::MemWriteRecord, data, data_size, OutFile);
}

VOID
EmitMemRead(THREADID threadid, ADDRINT addr, UINT32 read_size)
{
    USIZE data_size = sizeof(addr) + read_size;
    UINT8* data = (UINT8*)alloca(data_size);

    *(ADDRINT*)data = addr;
    PIN_SafeCopy(data + sizeof(addr), (VOID*)addr, read_size);

    WriteRecordToFile(RecordKind::MemReadRecord, data, data_size, OutFile);
}

VOID
EmitRegRW(THREADID threadid, RecordKind kind, REG reg, USIZE value)
{
    UINT32 reg_sz;
    UINT32 reg_num;
    auto iter = REG_TO_SLEIGH.find(reg);
    if (iter == REG_TO_SLEIGH.end()) {
        // Unspecified register, LOG?
        return;
    }
    reg_num = iter->second; // 'second' is v in (k, v) pairs of map.
    reg_sz = REG_Size(reg);

    USIZE data_size = sizeof(reg_num) + reg_sz;
    UINT8* data = (UINT8*)alloca(data_size);

    *(UINT32*)data = reg_num;
    *(USIZE*)(data + sizeof(reg_num)) = value;

    WriteRecordToFile(kind, data, data_size, OutFile);
}

// Wrapper function for EmitRegRW
inline VOID
EmitRegRead(THREADID threadid, REG reg, USIZE value)
{
    const RecordKind kind = RecordKind::RegReadRecord;
    EmitRegRW(threadid, kind, reg, value);
}

// Wrapper function for EmitRegRW
inline VOID
EmitRegWrite(THREADID threadid, REG reg, USIZE value)
{
    const RecordKind kind = RecordKind::RegWriteRecord;
    EmitRegRW(threadid, kind, reg, value);
}

inline VOID
EmitThreadMeta()
{
    /*
     * NOTE: rather than use the `THREADID` that the emit functions use,
     * I'm using pin's `OS_THREAD_ID`. Pin will re-use the `THREADID` value as
     * different threads are stopped and started which may confuse dataflow
     * analysis. Unfortunately though, this introduces a call to `PIN_GetTid()`
     * which will slow everything down even more.
     */
    OS_THREAD_ID threadid;

    if (INVALID_OS_THREAD_ID == (threadid = PIN_GetTid())) {
        LOG("PIN_GetTid() returned invalid tid." + decstr(threadid));
        return;
    }

    ThreadMeta tdata = { .threadid = threadid };
    WriteRecordToFile(RecordKind::MetaRecord, (UINT8*)&tdata, sizeof(tdata), OutFile);
}

VOID
WriteMapToJsonFile(IMG img, VOID* _v)
{
    ADDRINT high = IMG_HighAddress(img);
    ADDRINT low = IMG_LowAddress(img);
    const std::string& name = IMG_Name(img);
    fprintf(MapFile,
            "{\"name\":\"%s\",\"low\":\"%p\",\"high\":\"%p\"}\n",
            name.c_str(),
            (VOID*)low,
            (VOID*)high);
}
