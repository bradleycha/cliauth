/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/log.c - Logging interface implementation.                              */
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "log.h"

#include <stdarg.h>
#include <stdio.h>

void
cliauth_log(const char * format, ...) {
   va_list args;
   va_start(args, format);

   (void)vfprintf(stderr, format, args);

   va_end(args);
   return;
}

