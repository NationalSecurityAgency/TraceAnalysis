#include "trace.h"          /* RecordKind                                   */
#include "pin.H"            /* LOG                                          */
#include <stdint.h>         /* uint##_t                                     */
#include <stdio.h>          /* FILE                                         */
#include <string.h>         /* memcpy                                       */

void
WriteRecordToFile(RecordKind kind, uint8_t* data, size_t data_size, FILE* outfile)
{
    uint8_t vlen[4], rlen[5];
    LenLenPair p = calculate_vlen_rlen_sizes(data_size, vlen, rlen);
    size_t vlenlen = p.vlenlen;
    size_t rlenlen = p.rlenlen;

    uint8_t magic = (uint8_t)kind | vlenlen_to_lenlen(vlenlen);

    size_t buf_size = sizeof(magic) + vlenlen + data_size + rlenlen;
    // sizeof(magic) + vlenlen + rlenlen cannot wrap,
    // so we only have to check for wrap on data_size
    if (buf_size < data_size) {
        LOG("data_size exceeds maximum record size");
        return;
    }
    uint8_t* buf = (uint8_t*)alloca(buf_size);
    size_t cursor = 0;

    // cursor
    //    ↓
    // [magic][...]
    buf[cursor] = magic;
    cursor++;

    //        cursor
    //          ↓
    // [magic][vlen][...]
    memcpy(buf + cursor, vlen, vlenlen);
    cursor += vlenlen;

    //              cursor
    //                ↓
    // [magic][vlen][data][...]
    //if (cursor > buf_size - 1 - vlenlen - data_size) return;
    memcpy(buf + cursor, data, data_size);
    cursor += data_size;

    //                    cursor
    //                      ↓
    // [magic][vlen][data][rlen]
    memcpy(buf + cursor, rlen, rlenlen);

    fwrite(buf, buf_size, 1, outfile);
}

size_t
lenlen(uint8_t ty)
{
    return 4 >> (3 - (ty & 0x03 /* 0b0000_0011 */));
}

uint8_t
vlenlen_to_lenlen(size_t vlenlen)
{
    return ((vlenlen - (vlenlen >> 2)) & 0x03 /* 0b00000011 */);
}

LenLenPair
calculate_vlen_rlen_sizes(size_t clen, uint8_t vlen[], uint8_t rlen[])
{
    size_t vlenlen, rlenlen;

    if (clen < 0xff - 1) {
        vlenlen = 1;
        rlenlen = 1;

        vlen[0] = (uint8_t)clen + rlenlen;
        rlen[0] = (uint8_t)clen + vlenlen + 1;

    } else if (clen >= 0xff - 1 && clen < (0xffff - 4)) {
        vlenlen = 2;
        rlenlen = 5;

        uint16_t vlen_bytes = (uint16_t)clen + rlenlen;
        *(uint16_t*)vlen = vlen_bytes;

        uint32_t rlen_bytes = (uint32_t)clen + vlenlen + 1;
        *(uint32_t*)rlen = rlen_bytes;

    } else if (clen >= (0xffff - 4) && clen < (0xffffffff - 4)) {
        vlenlen = 4;
        rlenlen = 5;

        uint32_t vlen_bytes = (uint32_t)clen + rlenlen;
        *(uint32_t*)vlen = vlen_bytes;

        uint32_t rlen_bytes = (uint32_t)clen + vlenlen + 1;
        *(uint32_t*)rlen = rlen_bytes;
    } else {
        return (LenLenPair){ 0, 0 }; // FIXME: panic?
    }

    return (LenLenPair){ vlenlen, rlenlen };
}
