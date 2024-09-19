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
#include "mac.h"
#include "io.h"

/*----------------------------------------------------------------------------*/
/* Stores internal variables used when calculaing an HMAC-based one time      */
/* password (HOTP) value.                                                     */
/*----------------------------------------------------------------------------*/
struct CliAuthOtpHotpContext {
   /* hmac context */
   struct CliAuthMacHmacContext hmac_context;

   /* the counter value */
   CliAuthUInt64 counter;

   /* the number of digits to generate */
   CliAuthUInt8 digits;
};

/*----------------------------------------------------------------------------*/
/* Initializes the HOTP context.                                              */
/*----------------------------------------------------------------------------*/
/* context - The HOTP context to initialize.                                  */
/*                                                                            */
/* key_buffer - The 'key_buffer' argument for the HMAC algorithm.  See the    */
/*              documentation for 'cliauth_mac_hmac_initialize()' for more    */
/*              information.                                                  */
/*                                                                            */
/* digest_buffer - The 'digest_buffer' argument for the HMAC algorithm.  See  */
/*                 the documentation for 'cliauth_mac_hmac_initialize()' for  */
/*                 more information.                                          */
/*                                                                            */
/* hash_function - The 'hash_function' argument for the HMAC algorithm.  See  */
/*                 the documentation for 'cliauth_mac_hmac_initialize()' for  */
/*                 more information.                                          */
/*                                                                            */
/* hash_context - The 'hash_context' argument for the HMAC algorithm.  See    */
/*                the documentation for 'cliauth_mac_hmac_initialize()' for   */
/*                more information.                                           */
/*                                                                            */
/* block_bytes - The 'block_bytes' argument for the HMAC algorithm.  See the  */
/*               documentation for 'cliauth_mac_hmac_initialize()' for more   */
/*               information.                                                 */
/*                                                                            */
/* digest_bytes - The 'digest_bytes' argument for the HMAC algorithm.  See    */
/*                the documentation for 'cliauth_mac_hmac_initialize()' for   */
/*                more information.                                           */
/*                                                                            */
/* counter - The counter value for the HOTP algorithm.                        */
/*                                                                            */
/* digits - The number of digits, base 10, to include in the final HOTP       */
/*          output.  This must be at least 1, and may not be greater than 9.  */
/*----------------------------------------------------------------------------*/
void
cliauth_otp_hotp_initialize(
   struct CliAuthOtpHotpContext * context,
   CliAuthUInt8 key_buffer [],
   CliAuthUInt8 digest_buffer [],
   const struct CliAuthHashFunction * hash_function,
   void * hash_context,
   CliAuthUInt8 block_bytes,
   CliAuthUInt8 digest_bytes,
   CliAuthUInt64 counter,
   CliAuthUInt8 digits
);

/*----------------------------------------------------------------------------*/
/* Digests bytes as the secret key for the HOTP algorithm.                    */
/*----------------------------------------------------------------------------*/
/* context - The HOTP context to digest into.  The given context must have    */
/*           been initialized with 'cliauth_otp_hotp_initialize()' and must   */
/*           not have been finalized with 'cliauth_otp_hotp_finalize()'.      */
/*                                                                            */
/* key_reader - The reader to source the key bytes from.                      */
/*                                                                            */
/* key_bytes - The number of bytes to read from 'key_reader'.                 */
/*----------------------------------------------------------------------------*/
/* Return value - The result of reading the key from 'key_reader'.  If the    */
/*                returned read result statis is not                          */
/*                'CLIAUTH_IO_READ_STATUS_SUCCESS', the number of digested    */
/*                bytes can be obtained from the 'bytes' field in the         */
/*                returned read result.                                       */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReadResult
cliauth_otp_hotp_key_digest(
   struct CliAuthOtpHotpContext * context,
   const struct CliAuthIoReader * key_reader,
   CliAuthUInt32 key_bytes
);

/*----------------------------------------------------------------------------*/
/* Finalizes the HOTP value, generating a one-time-password.                  */
/*----------------------------------------------------------------------------*/
/* context - The HOTP context to finalize.  The context must have been        */
/*           initialized with 'cliauth_otp_hotp_initialize()'.  Key bytes may */
/*           no longer be digested by 'cliauth_otp_hotp_key_digest()' after   */
/*           execution.  To generate another code, the context must be        */
/*           re-initialized.                                                  */
/*----------------------------------------------------------------------------*/
/* Return value - The final generated HMAC-based one-time-password.           */
/*----------------------------------------------------------------------------*/
CliAuthUInt32
cliauth_otp_hotp_finalize(
   struct CliAuthOtpHotpContext * context
);

/*----------------------------------------------------------------------------*/
/* Calculates the HOTP 'counter' value in accordance with the TOTP algorithm. */
/*----------------------------------------------------------------------------*/
/* time_initial - The timestamp to start counting from, in seconds relative   */
/*                to the Unix epoch.                                          */
/*                                                                            */
/* time_current - The timestamp that represents the current time, in seconds  */
/*                relative to the Unix epoch.  This must be greater than or   */
/*                equal to 'time_initial'.                                    */
/*                                                                            */
/* time_interval - The interval at which to generate a new password, in       */
/*                 seconds.  This must be greater than zero.                  */
/*----------------------------------------------------------------------------*/
/* Return value - The HOTP 'counter' value generated by the TOTP algorithm    */
/*                which can be used by the HOTP algorithm to generate a TOTP  */
/*                passcode.                                                   */
/*----------------------------------------------------------------------------*/
CliAuthUInt64
cliauth_otp_totp_calculate_counter(
   CliAuthUInt64 time_initial,
   CliAuthUInt64 time_current,
   CliAuthUInt64 time_interval
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_OTP_H */

