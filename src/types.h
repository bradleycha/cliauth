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

/*----------------------------------------------------------------------------*/
/* Generic integer types which allow easy and well-defined reinterpretation   */
/* of integer bits.  Useful for low-level bit-fiddling operations.            */
/*----------------------------------------------------------------------------*/
union CliAuthInt8 {
   CliAuthUInt8 uint;
   CliAuthSInt8 sint;
   CliAuthUInt8 bytes [sizeof(CliAuthUInt8)];
};
union CliAuthInt16 {
   CliAuthUInt16 uint;
   CliAuthSInt16 sint;
   CliAuthUInt8 bytes [sizeof(CliAuthUInt16)];
};
union CliAuthInt32 {
   CliAuthUInt32 uint;
   CliAuthSInt32 sint;
   CliAuthUInt8 bytes [sizeof(CliAuthUInt32)];
};
union CliAuthInt64 {
   CliAuthUInt64 uint;
   CliAuthSInt64 sint;
   CliAuthUInt8 bytes [sizeof(CliAuthUInt64)];
};

/*----------------------------------------------------------------------------*/
/* Constructs a typed integer literal from an untyped integer literal.  This  */
/* is useful to ensure the compiler knows the intended type for an integer    */
/* literal which helps to avoid footguns.  For 64-bit types, there is no      */
/* standard way to store a 64-bit integer literal, thus the literal must be   */
/* split.  For CliAuthUInt64, the literal is split into two 32-bit literals.  */
/* For CliAuthSInt64, the integer literal is split into four 16-bit literals. */
/* Each partial word is ordered from most significant to least significant.   */
/* For example, the literal "0xdeadbeefbaadf00d" would be split first into    */
/* "0xdeadbeef", then into "0xbaadf00d".  The CliAuthSInt64, the sign of each */
/* word should be identical.                                                  */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_LITERAL_UINT8(word)\
   ((CliAuthUInt8)(word))
#define CLIAUTH_LITERAL_UINT16(word)\
   ((CliAuthUInt16)(word))
#define CLIAUTH_LITERAL_UINT32(word)\
   ((CliAuthUInt32)(word))
#define CLIAUTH_LITERAL_UINT64(hword0, hword1)\
   ((CliAuthUInt64)(\
      (((CliAuthUInt64)(hword0)) * (((CliAuthUInt64)(1)) << 32)) +\
      ((CliAuthUInt64)(hword1))\
   ))
#define CLIAUTH_LITERAL_SINT8(word)\
   ((CliAuthSInt8)(word))
#define CLIAUTH_LITERAL_SINT16(word)\
   ((CliAuthSInt16)(word))
#define CLIAUTH_LITERAL_SINT32(word)\
   ((CliAuthSInt32)(word))
#define CLIAUTH_LITERAL_SINT64(hhword0, hhword1, hhword2, hhword3)\
   ((CliAuthSInt64)(\
      (((CliAuthSInt64)(hhword0)) * ((CliAuthSInt64)((((CliAuthUInt64)(1)) << 48)))) +\
      (((CliAuthSInt64)(hhword1)) * ((CliAuthSInt64)((((CliAuthUInt64)(1)) << 32)))) +\
      (((CliAuthSInt64)(hhword2)) * ((CliAuthSInt64)((((CliAuthUInt64)(1)) << 16)))) +\
      ((CliAuthSInt64)(hhword3))\
   ))

/*----------------------------------------------------------------------------*/
/* Untyped integer value limits, compatible with preprocessor #if directives. */
/* These should only be used within the context of the preprocessor.  For all */
/* other usage, the typed version of each limit should be used instead.       */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_UINT8_MAX_LITERAL         (0xffu)
#define CLIAUTH_UINT16_MAX_LITERAL        (0xffffu)
#define CLIAUTH_UINT32_MAX_LITERAL        (0xffffffffu)
#define CLIAUTH_UINT64_MAX_LITERAL_HWORD0 (0xffffffffu)
#define CLIAUTH_UINT64_MAX_LITERAL_HWORD1 (0xffffffffu)
#define CLIAUTH_UINT8_MIN_LITERAL         (0x00u)
#define CLIAUTH_UINT16_MIN_LITERAL        (0x0000u)
#define CLIAUTH_UINT32_MIN_LITERAL        (0x00000000u)
#define CLIAUTH_UINT64_MIN_LITERAL_HWORD0 (0x00000000u)
#define CLIAUTH_UINT64_MIN_LITERAL_HWORD1 (0x00000000u)
#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_SIGN_MAGNITUDE
#define CLIAUTH_SINT8_MAX_LITERAL            (0x7f)
#define CLIAUTH_SINT16_MAX_LITERAL           (0x7fff)
#define CLIAUTH_SINT32_MAX_LITERAL           (0x7fffffff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD0   (0x7fff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD1   (0xffff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD2   (0xffff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD3   (0xffff)
#define CLIAUTH_SINT8_MIN_LITERAL            (-0x7f)
#define CLIAUTH_SINT16_MIN_LITERAL           (-0x7fff)
#define CLIAUTH_SINT32_MIN_LITERAL           (-0x7fffffff)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD0   (-0x7fff)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD1   (-0xffff)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD2   (-0xffff)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD3   (-0xffff)
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_SIGN_MAGNITUDE */
#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_ONES_COMPLEMENT
#define CLIAUTH_SINT8_MAX_LITERAL            (0x7f)
#define CLIAUTH_SINT16_MAX_LITERAL           (0x7fff)
#define CLIAUTH_SINT32_MAX_LITERAL           (0x7fffffff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD0   (0x7fff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD1   (0xffff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD2   (0xffff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD3   (0xffff)
#define CLIAUTH_SINT8_MIN_LITERAL            (-0x7f)
#define CLIAUTH_SINT16_MIN_LITERAL           (-0x7fff)
#define CLIAUTH_SINT32_MIN_LITERAL           (-0x7fffffff)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD0   (-0x7fff)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD1   (-0xffff)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD2   (-0xffff)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD3   (-0xffff)
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_ONES_COMPLEMENT */
#if CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_TWOS_COMPLEMENT
#define CLIAUTH_SINT8_MAX_LITERAL            (0x7f)
#define CLIAUTH_SINT16_MAX_LITERAL           (0x7fff)
#define CLIAUTH_SINT32_MAX_LITERAL           (0x7fffffff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD0   (0x7fff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD1   (0xffff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD2   (0xffff)
#define CLIAUTH_SINT64_MAX_LITERAL_HHWORD3   (0xffff)
#define CLIAUTH_SINT8_MIN_LITERAL            (-0x80)
#define CLIAUTH_SINT16_MIN_LITERAL           (-0x8000)
#define CLIAUTH_SINT32_MIN_LITERAL           (-0x80000000)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD0   (-0x8000)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD1   (-0x0000)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD2   (-0x0000)
#define CLIAUTH_SINT64_MIN_LITERAL_HHWORD3   (-0x0000)
#endif /* CLIAUTH_CONFIG_PLATFORM_INTEGER_SIGN_IS_TWOS_COMPLEMENT */

/*----------------------------------------------------------------------------*/
/* Integer value limits, already stored in their native types.  These are not */
/* compatible with preprocessor #if directives.  For such usage, the          */
/* untyped "literal" version of each limit must be used instead.              */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_UINT8_MAX\
   CLIAUTH_LITERAL_UINT8(CLIAUTH_UINT8_MAX_LITERAL)
#define CLIAUTH_UINT16_MAX\
   CLIAUTH_LITERAL_UINT16(CLIAUTH_UINT16_MAX_LITERAL)
#define CLIAUTH_UINT32_MAX\
   CLIAUTH_LITERAL_UINT32(CLIAUTH_UINT32_MAX_LITERAL)
#define CLIAUTH_UINT64_MAX\
   CLIAUTH_LITERAL_UINT64(\
      CLIAUTH_UINT64_MAX_LITERAL_HWORD0,\
      CLIAUTH_UINT64_MAX_LITERAL_HWORD1\
   )
#define CLIAUTH_UINT8_MIN\
   CLIAUTH_LITERAL_UINT8(CLIAUTH_UINT8_MIN_LITERAL)
#define CLIAUTH_UINT16_MIN\
   CLIAUTH_LITERAL_UINT16(CLIAUTH_UINT16_MIN_LITERAL)
#define CLIAUTH_UINT32_MIN\
   CLIAUTH_LITERAL_UINT32(CLIAUTH_UINT32_MIN_LITERAL)
#define CLIAUTH_UINT64_MIN\
   CLIAUTH_LITERAL_UINT64(\
      CLIAUTH_UINT64_MIN_LITERAL_HWORD0,\
      CLIAUTH_UINT64_MIN_LITERAL_HWORD1\
   )
#define CLIAUTH_SINT8_MAX\
   CLIAUTH_LITERAL_SINT8(CLIAUTH_SINT8_MAX_LITERAL)
#define CLIAUTH_SINT16_MAX\
   CLIAUTH_LITERAL_SINT16(CLIAUTH_SINT16_MAX_LITERAL)
#define CLIAUTH_SINT32_MAX\
   CLIAUTH_LITERAL_SINT32(CLIAUTH_SINT32_MAX_LITERAL)
#define CLIAUTH_SINT64_MAX\
   CLIAUTH_LITERAL_SINT64(\
      CLIAUTH_SINT64_MAX_LITERAL_HHWORD0,\
      CLIAUTH_SINT64_MAX_LITERAL_HHWORD1,\
      CLIAUTH_SINT64_MAX_LITERAL_HHWORD2,\
      CLIAUTH_SINT64_MAX_LITERAL_HHWORD3\
   )
#define CLIAUTH_SINT8_MIN\
   CLIAUTH_LITERAL_SINT8(CLIAUTH_SINT8_MIN_LITERAL)
#define CLIAUTH_SINT16_MIN\
   CLIAUTH_LITERAL_SINT16(CLIAUTH_SINT16_MIN_LITERAL)
#define CLIAUTH_SINT32_MIN\
   CLIAUTH_LITERAL_SINT32(CLIAUTH_SINT32_MIN_LITERAL)
#define CLIAUTH_SINT64_MIN\
   CLIAUTH_LITERAL_SINT64(\
      CLIAUTH_SINT64_MIN_LITERAL_HHWORD0,\
      CLIAUTH_SINT64_MIN_LITERAL_HHWORD1,\
      CLIAUTH_SINT64_MIN_LITERAL_HHWORD2,\
      CLIAUTH_SINT64_MIN_LITERAL_HHWORD3\
   )

typedef CliAuthUInt8 CliAuthBoolean;

#define CLIAUTH_BOOLEAN_FALSE ((CliAuthBoolean)(!(!(0u))))
#define CLIAUTH_BOOLEAN_TRUE  ((CliAuthBoolean)(!(0u)))

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_TYPES_H */

