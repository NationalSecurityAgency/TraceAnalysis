/*
 * TODO: Description
 */
#include "pin.H"
#include "trace.h"

/* Functions */

VOID
FreeWriteInfo(void * data);
  
// Pin Specific Emit Functions
VOID
EmitPc(THREADID threadid, ADDRINT pc, USIZE ins_size);
VOID
EmitInstruction(THREADID threadid, ADDRINT pc, USIZE ins_size);
VOID
PrepMemWrite(THREADID threadid, ADDRINT addr, UINT32 write_size);
VOID
EmitMemWrite(THREADID threadid);
VOID
EmitMemRead(THREADID threadid, ADDRINT addr, UINT32 read_size);
VOID
EmitRegRW(THREADID threadid, RecordKind kind, REG reg, USIZE value);
VOID
EmitRegRead(THREADID threadid, REG reg, USIZE value);
VOID
EmitRegWrite(THREADID threadid, REG reg, USIZE value);
VOID
EmitThreadMeta();

// Write Shared Libraries to 'maps.jsonl' when a new one is loaded.
VOID
WriteMapToJsonFile(IMG img, VOID* _v);

// Gets called at every instruction and insterst Pin instrumentation.
VOID
Instruction(INS ins, VOID* _v);

/* Gets called when Pin changes contexts. This could be returning from a signal
 * handler or right before switching to a signal handler.
 */
VOID
ContextChange(THREADID threadid,
              CONTEXT_CHANGE_REASON reason,
              const CONTEXT* from,
              CONTEXT* to,
              INT32 info,
              VOID* _v);

// Gets called on thread initialization.
VOID
ThreadStart(THREADID _threadid, CONTEXT* _ctxt, INT32 _flags, VOID* _v);

/* PIN call-backs arround fork() */

VOID
BeforeFork(THREADID _threadid, const CONTEXT* _ctxt, VOID* _arg);
VOID
AfterForkInParent(THREADID _threadid, const CONTEXT* _ctxt, VOID* _arg);
VOID
AfterForkInChild(THREADID threadid, const CONTEXT* _ctxt, VOID* _v);

// Gets called at the end of the trace
VOID
Fini(INT32 code, VOID* _v);

/* Type Definitions */

struct ThreadMeta
{
    UINT8 tag = MetaTag::ThreadID;
    OS_THREAD_ID threadid; // UINT32 == NATIVE_TID == OS_THREAD_ID
} __attribute__((packed));
typedef struct ThreadMeta ThreadMeta;
