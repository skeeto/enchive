#ifndef CONFIG_H
#define CONFIG_H

/* Compile-time configuration */

#ifndef ENCHIVE_VERSION
#  define ENCHIVE_VERSION 3.3
#endif

#ifndef ENCHIVE_FORMAT_VERSION
#  define ENCHIVE_FORMAT_VERSION 3
#endif

#ifndef ENCHIVE_KEY_DERIVE_ITERATIONS
#  define ENCHIVE_KEY_DERIVE_ITERATIONS 25  /* 32MB */
#endif

#ifndef ENCHIVE_SECKEY_DERIVE_ITERATIONS
#  define ENCHIVE_SECKEY_DERIVE_ITERATIONS 29 /* 512MB */
#endif

#ifndef ENCHIVE_OPTION_AGENT
#  if defined(__unix__) || defined(__APPLE__)
#    define ENCHIVE_OPTION_AGENT 1
#  else
#    define ENCHIVE_OPTION_AGENT 0
#  endif
#endif

#ifndef ENCHIVE_AGENT_TIMEOUT
#  define ENCHIVE_AGENT_TIMEOUT 900 /* 15 minutes */
#endif

#ifndef ENCHIVE_AGENT_DEFAULT_ENABLED
#  define ENCHIVE_AGENT_DEFAULT_ENABLED 0
#endif

#ifndef ENCHIVE_PASSPHRASE_MAX
#  define ENCHIVE_PASSPHRASE_MAX 1024
#endif

/* Required for correct builds */

#ifndef _POSIX_C_SOURCE
#  define _POSIX_C_SOURCE 1
#endif

#define OPTPARSE_IMPLEMENTATION

#define STR(a) XSTR(a)
#define XSTR(a) #a

/* Integer definitions needed by crypto */

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

#endif /* CONFIG_H */
