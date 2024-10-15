/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/cliauth.h - Global project header which contains common includes.      */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_H
#define _CLIAUTH_H
/*----------------------------------------------------------------------------*/

/* configure script *must* be the first include so it's available at all */
/* times */
#include "config.h"

/* additional config options which require more advanced code to set properly */

#if defined(__clang__)
#define CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_GCC    0
#define CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_CLANG  1
#define CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC   0
#elif defined(__GNUC__) || defined(__GNUG__)
#define CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_GCC    1
#define CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_CLANG  0
#define CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC   0
#elif defined(_MSC_VER)
#define CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_GCC    0
#define CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_CLANG  0
#define CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC   1
#endif

#define _CLIAUTH_NULLPTR_SENTINEL\
   (0u)

/*----------------------------------------------------------------------------*/
/* Generic null pointer value which can be used for any pointer type.         */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_NULLPTR\
   ((void *)_CLIAUTH_NULLPTR_SENTINEL)

/*----------------------------------------------------------------------------*/
/* Halts execution without terminating the program.  This is effectively the  */
/* same as an infinite loop.                                                  */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_HALT\
   {for (;;) {}}

#if CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_GCC
#if __has_builtin(__builtin_unreachable)
#define _CLIAUTH_UNREACHABLE_BUILTIN __builtin_unreachable()
#endif /* __has_builtin(__builtin_unreachable) */
#endif /* CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_GCC */
#if CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_CLANG
#if __has_builtin(__builtin_unreachable)
#define _CLIAUTH_UNREACHABLE_BUILTIN __builtin_unreachable()
#endif /* __has_builtin(__builtin_unreachable) */
#endif /* CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_CLANG */
#if CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC
#define _CLIAUTH_UNREACHABLE_BUILTIN __assume(0)
#endif /* CLIAUTH_CONFIG_PLATFORM_COMPILER_IS_MSVC */

/* fallback unreachable implementation when no builtin was able to be */
/* detected for the given compiler */
#ifndef _CLIAUTH_UNREACHABLE_BUILTIN
#define _CLIAUTH_UNREACHABLE_BUILTIN CLIAUTH_HALT
#endif /* _CLIAUTH_UNREACHABLE_BUILTIN */

/*----------------------------------------------------------------------------*/
/* Tells the compiler that a code branch will never be reached.  It is        */
/* undefined behavior to reach an unreachable code branch.  This can be used  */
/* to aid in optimization as well as eliminate spurious warnings, such as in  */
/* the case of initialization of variables in a switch statement.             */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_UNREACHABLE\
   _CLIAUTH_UNREACHABLE_BUILTIN

/* implicit includes are at the bottom to ensure all previous project */
/* declarations are available in these headers */
#include "types.h"
#include "imports.h"

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_H */

