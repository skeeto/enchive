#ifndef MACHINE_H
#define MACHINE_H
#include <stdint.h>

#define U8C(v)  (UINT8_C(v))
#define U16C(v) (UINT16_C(v))
#define U32C(v) (UINT32_C(v))

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int32_t s32;
typedef int64_t limb;

#endif /* MACHINE_H */
