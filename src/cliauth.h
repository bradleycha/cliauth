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

#define _CLIAUTH_NULLPTR_SENTINEL   (0)
#define CLIAUTH_NULLPTR             ((void *)_CLIAUTH_NULLPTR_SENTINEL)

/* implicit includes are at the bottom to ensure all previous project */
/* declarations are available in these headers */
#include "types.h"
#include "imports.h"

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_H */

