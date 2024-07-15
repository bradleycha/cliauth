/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/types.h - General types used throughout the program                    */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_TYPES_H
#define _CLIAUTH_TYPES_H
/*----------------------------------------------------------------------------*/

#include <stdint.h>

typedef uint8_t   CliAuthUInt8;
typedef uint16_t  CliAuthUInt16;
typedef uint32_t  CliAuthUInt32;
typedef uint64_t  CliAuthUInt64;
typedef int8_t    CliAuthSInt8;
typedef int16_t   CliAuthSInt16;
typedef int32_t   CliAuthSInt32;
typedef int64_t   CliAuthSInt64;

union CliAuthInt8 {
   CliAuthUInt8 uint;
   CliAuthSInt8 sint;
};
union CliAuthInt16 {
   CliAuthUInt16 uint;
   CliAuthSInt16 sint;
};
union CliAuthInt32 {
   CliAuthUInt32 uint;
   CliAuthSInt32 sint;
};
union CliAuthInt64 {
   CliAuthUInt64 uint;
   CliAuthSInt64 sint;
};

#define CLIAUTH_UINT8_MAX  ((CliAuthUInt8)(0xffu))
#define CLIAUTH_UINT16_MAX ((CliAuthUInt16)(0xffffu))
#define CLIAUTH_UINT32_MAX ((CliAuthUInt32)(0xffffffffu))
#define CLIAUTH_UINT64_MAX ((CliAuthUInt64)(0xffffffffffffffffu))
#define CLIAUTH_UINT8_MIN  ((CliAuthUInt8)(0x00u))
#define CLIAUTH_UINT16_MIN ((CliAuthUInt16)(0x0000u))
#define CLIAUTH_UINT32_MIN ((CliAuthUInt32)(0x00000000u))
#define CLIAUTH_UINT64_MIN ((CliAuthUInt64)(0x0000000000000000u))

#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_SIGN_MAGNITUDE
#define CLIAUTH_SINT8_MAX  ((CliAuthSInt8)(0x7f))
#define CLIAUTH_SINT16_MAX ((CliAuthSInt16)(0x7fff))
#define CLIAUTH_SINT32_MAX ((CliAuthSInt32)(0x7fffffff))
#define CLIAUTH_SINT64_MAX ((CliAuthSInt64)(0x7fffffffffffffff))
#define CLIAUTH_SINT8_MIN  ((CliAuthSInt8)(-0x7f))
#define CLIAUTH_SINT16_MIN ((CliAuthSInt16)(-0x7fff))
#define CLIAUTH_SINT32_MIN ((CliAuthSInt32)(-0x7fffffff))
#define CLIAUTH_SINT64_MIN ((CliAuthSInt64)(-0x7fffffffffffffff))
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_SIGN_MAGNITUDE */
#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_ONES_COMPLEMENT
#define CLIAUTH_SINT8_MAX  ((CliAuthSInt8)(0x7f))
#define CLIAUTH_SINT16_MAX ((CliAuthSInt16)(0x7fff))
#define CLIAUTH_SINT32_MAX ((CliAuthSInt32)(0x7fffffff))
#define CLIAUTH_SINT64_MAX ((CliAuthSInt64)(0x7fffffffffffffff))
#define CLIAUTH_SINT8_MIN  ((CliAuthSInt8)(-0x7f))
#define CLIAUTH_SINT16_MIN ((CliAuthSInt16)(-0x7fff))
#define CLIAUTH_SINT32_MIN ((CliAuthSInt32)(-0x7fffffff))
#define CLIAUTH_SINT64_MIN ((CliAuthSInt64)(-0x7fffffffffffffff))
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_ONES_COMPLEMENT */
#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_TWOS_COMPLEMENT
#define CLIAUTH_SINT8_MAX  ((CliAuthSInt8)(0x7f))
#define CLIAUTH_SINT16_MAX ((CliAuthSInt16)(0x7fff))
#define CLIAUTH_SINT32_MAX ((CliAuthSInt32)(0x7fffffff))
#define CLIAUTH_SINT64_MAX ((CliAuthSInt64)(0x7fffffffffffffff))
#define CLIAUTH_SINT8_MIN  ((CliAuthSInt8)(-0x80))
#define CLIAUTH_SINT16_MIN ((CliAuthSInt16)(-0x8000))
#define CLIAUTH_SINT32_MIN ((CliAuthSInt32)(-0x80000000))
#define CLIAUTH_SINT64_MIN ((CliAuthSInt64)(-0x8000000000000000))
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_TWOS_COMPLEMENT */

typedef CliAuthUInt8 CliAuthBoolean;

#define CLIAUTH_BOOLEAN_FALSE (!(!(0)))
#define CLIAUTH_BOOLEAN_TRUE  (!(0))

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_TYPES_H */

