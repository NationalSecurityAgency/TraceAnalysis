#ifndef TRACE_H
#define TRACE_H

#include <stdint.h> /* uint##_t                                               */
#include <stdio.h>  /* FILE                                                   */

// Magic value specifying a dataflow trace.
const uint8_t MAGIC[] = { 0x65, 0x78, 0x00, 0x3c, 0x7f };

// Constants representing the architecture of the underlying trace.
const uint32_t ARCH_X86 = 0x20;
const uint32_t ARCH_X64 = 0x40;

enum MetaTag
{
    InstructionCount = 0,
    ThreadID = 1,
};

/*
 * TODO: Documentation
 */
enum RecordKind
{
    MagicRecord = 0xf0,          /* 0b1111_0000 */
    ArchRecord = 0x00,           /* 0b0000_0000 */
    FileMetaRecord = 0x04,       /* 0b0000_0100 */
    MapRecord = 0x10,            /* 0b0001_0000 */
    UnmapRecord = 0x1c,          /* 0b0001_1100 */
    InstructionRecord = 0x20,    /* 0b0010_0000 */
    PcRecord = 0x24,             /* 0b0010_0100 */
    MetaRecord = 0x30,           /* 0b0011_0000 */
    InterruptRecord = 0x38,      /* 0b0011_1000 */
    RegReadRecord = 0x40,        /* 0b0100_0000 */
    RegWriteRecord = 0x44,       /* 0b0100_0100 */
    RegWriteNativeRecord = 0x54, /* 0b0101_0100 */
    MemReadRecord = 0x80,        /* 0b1000_0000 */
    MemWriteRecord = 0x84,       /* 0b1000_0100 */
};

typedef enum RecordKind RecordKind;

/*
 * TODO: Documentation
 */
void
WriteRecordToFile(RecordKind kind, uint8_t* data, size_t data_size, FILE* outfile);

/*
 * TODO: Documentation
 *
 * What is 'ty' here?
 */
size_t
lenlen(uint8_t ty);

/*
 * TODO: Documentation
 */
uint8_t
vlenlen_to_lenlen(size_t vlenlen);

/*
 * TODO: Documentation
 */
typedef struct
{
    size_t vlenlen;
    size_t rlenlen;
} LenLenPair;

/*
 * TODO: Documentation
 */
LenLenPair
calculate_vlen_rlen_sizes(size_t clen, uint8_t vlen[], uint8_t rlen[]);

#endif
