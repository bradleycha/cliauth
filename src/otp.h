/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/otp.h - One-time-password (OTP) algorithms header.                     */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_OTP_H
#define _CLIAUTH_OTP_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "hash.h"

/*----------------------------------------------------------------------------*/
/* Runs the HMAC-based One Time Password (HOTP) algorithm.                    */
/*----------------------------------------------------------------------------*/
/* hash_function - The hash function to use for the HMAC algorithm.           */
/*                                                                            */
/* hash_context - A pointer to a hash context struct which is valid for the   */
/*                given hash function.                                        */
/*                                                                            */
/* key - Generic byte data to use as the key input.                           */
/*                                                                            */
/* digest_buffer - A temporary byte buffer used internally.  Should be long   */
/*                 enough to store the hash function's digest output.         */
/*                                                                            */
/* key_buffer - A temporary byte buffer used internally.  Should be long      */
/*              enough to store a single block as defined by the hash         */
/*              algorithm.                                                    */
/*                                                                            */
/* key_bytes - The number of bytes to read from 'key'.                        */
/*                                                                            */
/* block_bytes - The byte length of the hash input blocks.  This is used      */
/*               internally by the HMAC algorithm and does not affect the     */
/*               expected length of the input block size.  The block length   */
/*               must be greater than or equal to the digest length.          */
/*                                                                            */
/* digest_bytes - The byte length of the hash digest.  This is used           */
/*                internally by the HMAC algorithm and does not affect the    */
/*                expected length of the input block size.                    */
/*                                                                            */
/* counter - The counter value for the HOTP algorithm.                        */
/*                                                                            */
/* digits - The number of digits, base 10, to include in the final HOTP       */
/*          output.  This must be at least 1, and may not be greater than 9.  */
/*----------------------------------------------------------------------------*/
/* Return value - A 'digits'-length base-10 one-time-password value.          */
/*----------------------------------------------------------------------------*/
CliAuthUInt32
cliauth_otp_hotp(
   const struct CliAuthHashFunction * hash_function,
   void * hash_context,
   const void * key,
   void * digest_buffer,
   void * key_buffer,
   CliAuthUInt32 key_bytes,
   CliAuthUInt32 block_bytes,
   CliAuthUInt32 digest_bytes,
   CliAuthUInt64 counter,
   CliAuthUInt8 digits
);

/*----------------------------------------------------------------------------*/
/* Runs the Time-based One Time Password (TOTP) algorithm.                    */
/*----------------------------------------------------------------------------*/
/* hash_function - The hash function to use for the HMAC algorithm.           */
/*                                                                            */
/* hash_context - A pointer to a hash context struct which is valid for the   */
/*                given hash function.                                        */
/*                                                                            */
/* key - Generic byte data to use as the key input.                           */
/*                                                                            */
/* digest_buffer - A temporary byte buffer used internally.  Should be long   */
/*                 enough to store the hash function's digest output.         */
/*                                                                            */
/* key_buffer - A temporary byte buffer used internally.  Should be long      */
/*              enough to store a single block as defined by the hash         */
/*              algorithm.                                                    */
/*                                                                            */
/* key_bytes - The number of bytes to read from 'key'.                        */
/*                                                                            */
/* block_bytes - The byte length of the hash input blocks.  This is used      */
/*               internally by the HMAC algorithm and does not affect the     */
/*               expected length of the input block size.  The block length   */
/*               must be greater than or equal to the digest length.          */
/*                                                                            */
/* digest_bytes - The byte length of the hash digest.  This is used           */
/*                internally by the HMAC algorithm and does not affect the    */
/*                expected length of the input block size.                    */
/*                                                                            */
/* time_initial - The timestamp to start counting from, in seconds relative   */
/*                to the Unix epoch.                                          */
/*                                                                            */
/* time_current - The timestamp that represents the current time, in seconds  */
/*                relative to the Unix epoch.  This must be greater than or   */
/*                equal to 'time_initial'.                                    */
/*                                                                            */
/* time_interval - The interval at which to generate a new password, in       */
/*                 seconds.  This must be greater than zero.                  */
/*                                                                            */
/* digits - The number of digits, base 10, to include in the final HOTP       */
/*          output.  This must be at least 1, and may not be greater than 9.  */
/*----------------------------------------------------------------------------*/
/* Return value - A 'digits'-length base-10 one-time-password value.          */
/*----------------------------------------------------------------------------*/
CliAuthUInt32
cliauth_otp_totp(
   const struct CliAuthHashFunction * hash_function,
   void * hash_context,
   const void * key,
   void * digest_buffer,
   void * key_buffer,
   CliAuthUInt32 key_bytes,
   CliAuthUInt32 block_bytes,
   CliAuthUInt32 digest_bytes,
   CliAuthUInt64 time_initial,
   CliAuthUInt64 time_current,
   CliAuthUInt64 time_interval,
   CliAuthUInt8 digits
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_OTP_H */

