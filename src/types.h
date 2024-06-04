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

typedef int8_t    CliAuthSInt8;
typedef int16_t   CliAuthSInt16;
typedef int32_t   CliAuthSInt32;
typedef int64_t   CliAuthSInt64;
typedef uint8_t   CliAuthUInt8;
typedef uint16_t  CliAuthUInt16;
typedef uint32_t  CliAuthUInt32;
typedef uint64_t  CliAuthUInt64;

#define CLIAUTH_SINT8_MAX  ((CliAuthSInt8)(0x7f))
#define CLIAUTH_SINT16_MAX ((CliAuthSInt16)(0x7fff))
#define CLIAUTH_SINT32_MAX ((CliAuthSInt32)(0x7fffffff))
#define CLIAUTH_SINT64_MAX ((CliAuthSInt64)(0x7fffffffffffffff))
#define CLIAUTH_UINT8_MAX  ((CliAuthUInt8)(0xff))
#define CLIAUTH_UINT16_MAX ((CliAuthUInt16)(0xffff))
#define CLIAUTH_UINT32_MAX ((CliAuthUInt32)(0xffffffff))
#define CLIAUTH_UINT64_MAX ((CliAuthUInt64)(0xffffffffffffffff))

#define CLIAUTH_SINT8_MIN  ((CliAuthSInt8)(0x80))
#define CLIAUTH_SINT16_MIN ((CliAuthSInt16)(0x8000))
#define CLIAUTH_SINT32_MIN ((CliAuthSInt32)(0x80000000))
#define CLIAUTH_SINT64_MIN ((CliAuthSInt64)(0x8000000000000000))
#define CLIAUTH_UINT8_MIN  ((CliAuthUInt8)(0x00))
#define CLIAUTH_UINT16_MIN ((CliAuthUInt16)(0x0000))
#define CLIAUTH_UINT32_MIN ((CliAuthUInt32)(0x00000000))
#define CLIAUTH_UINT64_MIN ((CliAuthUInt64)(0x0000000000000000))

typedef CliAuthUInt8 CliAuthBoolean;

#define CLIAUTH_BOOLEAN_FALSE ((CliAuthBoolean)(0))
#define CLIAUTH_BOOLEAN_TRUE  ((CliAuthBoolean)(1))

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_TYPES_H */

