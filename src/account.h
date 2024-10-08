/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/account.h - Account management header.                                 */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_ACCOUNT_H
#define _CLIAUTH_ACCOUNT_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "hash.h"
#include "otp.h"

/*----------------------------------------------------------------------------*/
/* The account's authenticator algorithm type.                                */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_ACCOUNT_ALGORITHM_TYPE_HOTP - Use the HOTP authentication          */
/*                                       algorithm.                           */
/*                                                                            */
/* CLIAUTH_ACCOUNT_ALGORITHM_TYPE_TOTP - Use the TOTP authentication          */
/*                                       algorithm.                           */
/*                                                                            */
/* Each enum field is given an explicit value to ensure a well-defined        */
/* in-memory representation.                                                  */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_ACCOUNT_ALGORITHM_TYPE_FIELD_COUNT 2u
enum CliAuthAccountAlgorithmType {
   CLIAUTH_ACCOUNT_ALGORITHM_TYPE_HOTP = 0,
   CLIAUTH_ACCOUNT_ALGORITHM_TYPE_TOTP = 1
};

/*----------------------------------------------------------------------------*/
/* Account algorithm parameters for the HOTP authentication algorithm.        */
/*----------------------------------------------------------------------------*/
/* counter - The current HOTP counter value.                                  */
/*----------------------------------------------------------------------------*/
struct CliAuthAccountAlgorithmHotp {
   CliAuthUInt64 counter;
};

/*----------------------------------------------------------------------------*/
/* Account algorithm parameters for the TOTP authentication algorithm.        */
/*----------------------------------------------------------------------------*/
/* period - The duration, in seconds, to generate a new passcode.  This       */
/*          should always be greater than zero.                               */
/*----------------------------------------------------------------------------*/
struct CliAuthAccountAlgorithmTotp {
   CliAuthUInt64 period;
};

/*----------------------------------------------------------------------------*/
/* Generic account algorithm parameters.                                      */
/*----------------------------------------------------------------------------*/
/* hotp - HOTP-specific parameters.                                           */
/*                                                                            */
/* totp - TOTP-specific parameters.                                           */
/*----------------------------------------------------------------------------*/
union CliAuthAccountAlgorithmParameters {
   struct CliAuthAccountAlgorithmHotp hotp;
   struct CliAuthAccountAlgorithmTotp totp;
};

/*----------------------------------------------------------------------------*/
/* An account algorithm type and its relevant parameters.                     */
/*----------------------------------------------------------------------------*/
/* type - Which algorithm type is stored in 'parameters'.                     */
/*                                                                            */
/* parameters - The algorithm-specific parameters. The 'hotp' field is only   */
/*              valid when 'type' is CLIAUTH_ACCOUNT_ALGORITHM_TYPE_HOTP.     */
/*              The 'totp' field is only valid when 'type' is                 */
/*              CLIAUTH_ACCOUNT_ALGORITHM_TYPE_TOTP.                          */
/*----------------------------------------------------------------------------*/
struct CliAuthAccountAlgorithm {
   enum CliAuthAccountAlgorithmType type;
   union CliAuthAccountAlgorithmParameters parameters;
};

/*----------------------------------------------------------------------------*/
/* Whether the default hash function is available.  If not, all accounts must */
/* explicitly specify the hash function when deserialized.                    */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_ACCOUNT_DEFAULT_HASH_IS_AVAILABLE\
   CLIAUTH_CONFIG_HASH_SHA1

/*----------------------------------------------------------------------------*/
/* Default values for various account fields.                                 */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_ACCOUNT_DEFAULT_HASH_IS_AVAILABLE
#define CLIAUTH_ACCOUNT_DEFAULT_HASH_FUNCTION\
   (&cliauth_hash_sha1)
#define CLIAUTH_ACCOUNT_DEFAULT_HASH_IDENTIFIER\
   CLIAUTH_HASH_SHA1_IDENTIFIER
#endif /* CLIAUTH_ACCOUNT_DEFAULT_HASH_IS_AVAILABLE */
#define CLIAUTH_ACCOUNT_DEFAULT_DIGITS\
   6u
#define CLIAUTH_ACCOUNT_DEFAULT_TOTP_PERIOD_HWORD0\
   0u
#define CLIAUTH_ACCOUNT_DEFAULT_TOTP_PERIOD_HWORD1\
   30u

/*----------------------------------------------------------------------------*/
/* Buffer lengths for account array fields.                                   */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_ACCOUNT_SECRETS_MAX_LENGTH\
   128u
#define CLIAUTH_ACCOUNT_ISSUER_MAX_LENGTH\
   64u
#define CLIAUTH_ACCOUNT_ACCOUNT_NAME_MAX_LENGTH\
   64u

/*----------------------------------------------------------------------------*/
/* The in-memory representation of a single authenticator account.            */
/*----------------------------------------------------------------------------*/
/* algorithm - The type of authenticator algorithm to use and its relevant    */
/*             algorithm-specific parameters.                                 */
/*                                                                            */
/* hash_function - The hash function to use with the authenticator algorithm. */
/*                                                                            */
/* secrets - An array of byte data which serves as the 'key' for the          */
/*           HOTP/TOTP algorithms.                                            */
/*                                                                            */
/* issuer - A string which represents the organization which created the      */
/*          account.  This string is not null-terminated.                     */
/*                                                                            */
/* name - A string which represents the name of the account.  This string is  */
/*        not null-terminated.                                                */
/*                                                                            */
/* secrets_bytes - The length of 'secrets' in bytes.                          */
/*                                                                            */
/* issuer_characters - The length of 'issuer' in characters.                  */
/*                                                                            */
/* name_characters - The length of 'name' in characters.                      */
/*                                                                            */
/* digits - The number of digits the passcode should contain.  This should    */
/*          always be greater than or equal to '1' and less than or equal to  */
/*          '9'.                                                              */
/*----------------------------------------------------------------------------*/
struct CliAuthAccount {
   struct CliAuthAccountAlgorithm algorithm;
   const struct CliAuthHashFunction * hash_function;
   CliAuthUInt8 secrets [CLIAUTH_ACCOUNT_SECRETS_MAX_LENGTH];
   char issuer [CLIAUTH_ACCOUNT_ISSUER_MAX_LENGTH];
   char name [CLIAUTH_ACCOUNT_ACCOUNT_NAME_MAX_LENGTH];
   CliAuthUInt8 secrets_bytes;
   CliAuthUInt8 issuer_characters;
   CliAuthUInt8 name_characters;
   CliAuthUInt8 digits;
};

/*----------------------------------------------------------------------------*/
/* TOTP-specific algorithm parameters used by                                 */
/* cliauth_account_generate_passcode().                                       */
/*----------------------------------------------------------------------------*/
/* time_initial - The initial timestamp, in seconds, and relative to the unix */
/*                timestamp.                                                  */
/*                                                                            */
/* time_current - The current timestamp, in seconds, and relative to the unix */
/*                timestamp.                                                  */
/*----------------------------------------------------------------------------*/
struct CliAuthAccountGeneratePasscodeTotpParameters {
   CliAuthUInt64 time_initial;
   CliAuthUInt64 time_current;
};

/*----------------------------------------------------------------------------*/
/* Return status enum for cliauth_account_generate_passcode().                */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_GENERATE_PASSCODE_RESULT_SUCCESS - The passcode was generated      */
/*                                            successfully.                   */
/*                                                                            */
/* CLIAUTH_GENERATE_PASSCODE_RESULT_DOES_NOT_EXIST - The passcode at the      */
/*                                                   given index offset does  */
/*                                                   not exist.               */
/*----------------------------------------------------------------------------*/
enum CliAuthAccountGeneratePasscodeResult {
   CLIAUTH_GENERATE_PASSCODE_RESULT_SUCCESS,
   CLIAUTH_GENERATE_PASSCODE_RESULT_DOES_NOT_EXIST
};

/*----------------------------------------------------------------------------*/
/* Generates a one-time passcode from the account.                            */
/*----------------------------------------------------------------------------*/
/* account - The account to generate the passcode from.  Account data is not  */
/*           updated, such as the HOTP counter value.  This must be updated   */
/*           seperately.                                                      */
/*                                                                            */
/* output - A pointer to a 32-bit integer where the generated passcode will   */
/*            be written to.  The generated passcode will only be valid if    */
/*            the function returns                                            */
/*            'CLIAUTH_GENERATE_PASSCODE_RESULT_SUCCESS'.                     */
/*                                                                            */
/* hotp_context - The HOTP context struct used internally to execute the HOTP */
/*                algorithm.  This should not be previously initialized or    */
/*                considered in any deterministic state after execution.      */
/*                                                                            */
/* totp_parameters - TOTP-specific algorithm parameters.  If the account type */
/*                   is 'CLIAUTH_ACCOUNT_ALGORITHM_TYPE_HOTP', this argument  */
/*                   is ignored.  If the account type is                      */
/*                   'CLIAUTH_ACCOUNT_ALGORITHM_TYPE_TOTP', this argument     */
/*                   must be set.                                             */
/*                                                                            */
/* index - The passcode index to generate relative to the current parameters. */
/*         A value of '0' will generate the current passcode.  A value of '1' */
/*         will generate the next passcode.  A value of '-1' will generate    */
/*         the previous passcode.                                             */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the state of the generated passcode    */
/*                in 'output'.                                                */
/*----------------------------------------------------------------------------*/
enum CliAuthAccountGeneratePasscodeResult
cliauth_account_generate_passcode(
   const struct CliAuthAccount * account,
   CliAuthUInt32 * output,
   struct CliAuthOtpHotpContext * hotp_context,
   const struct CliAuthAccountGeneratePasscodeTotpParameters * totp_parameters,
   CliAuthSInt64 index
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_ACCOUNT_H */

