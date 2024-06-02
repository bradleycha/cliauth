/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/log.h - Header for logging interface                                   */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_LOG_H
#define _CLIAUTH_LOG_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include <stdio.h>

#define _CLIAUTH_LOG_ANSI_COLOR(color) "\033[" color "m"

#define _CLIAUTH_LOG_PREFIX_INFO    "info"
#define _CLIAUTH_LOG_PREFIX_WARNING "warning"
#define _CLIAUTH_LOG_PREFIX_ERROR   "error"

#define _CLIAUTH_LOG_COLOR_INFO        _CLIAUTH_LOG_ANSI_COLOR("1;32")
#define _CLIAUTH_LOG_COLOR_WARNING     _CLIAUTH_LOG_ANSI_COLOR("1;33")
#define _CLIAUTH_LOG_COLOR_ERROR       _CLIAUTH_LOG_ANSI_COLOR("1;31")
#define _CLIAUTH_LOG_COLOR_SEPERATOR   _CLIAUTH_LOG_ANSI_COLOR("0;37")
#define _CLIAUTH_LOG_COLOR_ORIGIN      _CLIAUTH_LOG_ANSI_COLOR("0;36")
#define _CLIAUTH_LOG_COLOR_FORMAT      _CLIAUTH_LOG_ANSI_COLOR("0;37")
#define _CLIAUTH_LOG_COLOR_RESET       _CLIAUTH_LOG_ANSI_COLOR("0")

#if CLIAUTH_CONFIG_LOG_ORIGIN
   #define _CLIAUTH_LOG_FORMAT_ORIGIN           __FILE__ ":%d"
   #define _CLIAUTH_LOG_FORMAT_ORIGIN_SEPERATOR " - "
   #define _CLIAUTH_LOG_ORIGIN_LINE             "",__LINE__
#else /* CLIAUTH_CONFIG_LOG_ORIGIN */
   #define _CLIAUTH_LOG_FORMAT_ORIGIN
   #define _CLIAUTH_LOG_FORMAT_ORIGIN_SEPERATOR
   #define _CLIAUTH_LOG_ORIGIN_LINE
#endif /* CLIAUTH_CONFIG_LOG_ORIGIN */

#if CLIAUTH_CONFIG_LOG_ANSI
   #define _CLIAUTH_LOG_FORMAT(prefix, color, format)\
      _CLIAUTH_LOG_COLOR_SEPERATOR "["\
      color prefix\
      _CLIAUTH_LOG_COLOR_SEPERATOR "] "\
      _CLIAUTH_LOG_COLOR_ORIGIN _CLIAUTH_LOG_FORMAT_ORIGIN\
      _CLIAUTH_LOG_COLOR_SEPERATOR _CLIAUTH_LOG_FORMAT_ORIGIN_SEPERATOR\
      _CLIAUTH_LOG_COLOR_FORMAT format\
      _CLIAUTH_LOG_COLOR_RESET "\n"
#else /* CLIAUTH_CONFIG_LOG_ANSI */
   #define _CLIAUTH_LOG_FORMAT(prefix, color, format)\
      "["\
      prefix\
      "] "\
      _CLIAUTH_LOG_FORMAT_ORIGIN\
      _CLIAUTH_LOG_FORMAT_ORIGIN_SEPERATOR\
      format\
      "\n"
#endif /* CLIAUTH_CONFIG_LOG_ANSI */

#define _CLIAUTH_LOG_INVOKE(prefix, color, format)\
   _CLIAUTH_LOG_FORMAT(prefix, color, format) _CLIAUTH_LOG_ORIGIN_LINE

#define CLIAUTH_LOG_INFO(format)\
   _CLIAUTH_LOG_INVOKE(_CLIAUTH_LOG_PREFIX_INFO, _CLIAUTH_LOG_COLOR_INFO, format)
#define CLIAUTH_LOG_WARNING(format)\
   _CLIAUTH_LOG_INVOKE(_CLIAUTH_LOG_PREFIX_WARNING, _CLIAUTH_LOG_COLOR_WARNING, format)
#define CLIAUTH_LOG_ERROR(format)\
   _CLIAUTH_LOG_INVOKE(_CLIAUTH_LOG_PREFIX_ERROR, _CLIAUTH_LOG_COLOR_ERROR, format)

/*----------------------------------------------------------------------------*/
/* Writes a log message using printf-style formatting.                        */
/*----------------------------------------------------------------------------*/
/* The arguments to this function do not work as one may expect.  The         */
/* format string must be created at the callsite with one of the following    */
/* macros which specify a log level:                                          */
/*    CLIAUTH_LOG_INFO                                                        */
/*    CLIAUTH_LOG_WARNING                                                     */
/*    CLIAUTH_LOG_ERROR                                                       */
/* Additional arguments used in the formatting string can then be appended    */
/* after the invokation of any of the above macros.                           */
/*                                                                            */
/* This function is not thread-safe.  External synchronization must be used   */
/* if called from multiple threads.                                           */
/*                                                                            */
/* Examples:                                                                  */
/*    cliauth_log(CLIAUTH_LOG_INFO("Initializing subsystems"));               */
/*    cliauth_log(CLIAUTH_LOG_WARNING("%s is not present"), library_name);    */
/*    cliauth_log(CLIAUTH_LOG_ERROR("Failed after %d attempts"), attempts);   */
/*----------------------------------------------------------------------------*/
void
cliauth_log(const char * format, ...);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_LOG_H */

