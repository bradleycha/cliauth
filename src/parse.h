/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/parse.h - Data serializers and deserializers header.                   */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_PARSE_H
#define _CLIAUTH_PARSE_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "hash.h"

/*----------------------------------------------------------------------------*/
/* Return status enum for cliauth_parse_integer_*().                          */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS - The integer was parsed              */
/*                                        successfully.                       */
/*                                                                            */
/* CLIAUTH_PARSE_INTEGER_RESULT_INVALID_ENCODING - One or more invalid        */
/*                                                 characters were            */
/*                                                 encountered.               */
/*                                                                            */
/* CLIAUTH_PARSE_INTEGER_RESULT_OUT_OF_RANGE - The number cannot be           */
/*                                             stored inside the integer      */
/*                                             without overflow/underflow.    */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_PARSE_INTEGER_RESULT_FIELD_COUNT 3
enum CliAuthParseIntegerResult {
   CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS,
   CLIAUTH_PARSE_INTEGER_RESULT_INVALID_ENCODING,
   CLIAUTH_PARSE_INTEGER_RESULT_OUT_OF_RANGE
};

/*----------------------------------------------------------------------------*/
/* Parses a decimal string to an integer.                                     */
/*----------------------------------------------------------------------------*/
/* output - The resulting parsed integer.  This is only valid if the function */
/*          returns 'CLIAUTH_PARSE_INTEGER_RESULT_SUCCESS'.                   */
/*                                                                            */
/* text - A string which contains the integer to be parsed.  This string does */
/*        not need to be null-terminated.                                     */
/*                                                                            */
/* text_characters - The length of 'text' in characters.                      */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the state of the parsed integer in     */
/*                'output'.                                                   */
/*----------------------------------------------------------------------------*/
enum CliAuthParseIntegerResult
cliauth_parse_integer_uint64(
   CliAuthUInt64 * output,
   const char text [],
   CliAuthUInt32 text_characters
);

/*----------------------------------------------------------------------------*/
/* Return status enum for cliauth_parse_hash_identifier().                    */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_PARSE_HASH_RESULT_SUCCESS - The hash identifier was parsed         */
/*                                     successfully.                          */
/*                                                                            */
/* CLIAUTH_PARSE_HASH_RESULT_UNKNOWN_IDENTIFIER - The given identifier did    */
/*                                                not match any available     */
/*                                                hash functions.             */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_PARSE_HASH_RESULT_FIELD_COUNT 2
enum CliAuthParseHashResult {
   CLIAUTH_PARSE_HASH_RESULT_SUCCESS,
   CLIAUTH_PARSE_HASH_RESULT_UNKNOWN_IDENTIFIER
};

/*----------------------------------------------------------------------------*/
/* Output parsed hash function from cliauth_parse_hash_identifier().          */
/*----------------------------------------------------------------------------*/
/* function - The executable hash functions.                                  */
/*                                                                            */
/* block_bytes - The length of each input block in bytes.                     */
/*                                                                            */
/* digest_bytes - The length of the final digest in bytes.                    */
/*----------------------------------------------------------------------------*/
struct CliAuthParseHashPayload {
   const struct CliAuthHashFunction * function;
   CliAuthUInt32 block_bytes;
   CliAuthUInt32 digest_bytes;
};

/*----------------------------------------------------------------------------*/
/* Parses an identifier string into its hash function.                        */
/*----------------------------------------------------------------------------*/
/* payload - A pointer to a variable to hold the address of the matched hash  */
/*           function.  The data stored in this pointer will only be valid    */
/*           if the function returns 'CLIAUTH_PARSE_HASH_RESULT_SUCCESS'.     */
/*                                                                            */
/* identifier - A string which represents the identifier to attempt to match  */
/*              to a hash function.  This string does not need to be          */
/*              null-terminated.                                              */
/*                                                                            */
/* identifier_characters - The length of 'identifier' in characters.          */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the output state of the parsed hash    */
/*                identifier in 'payload'.                                    */
/*----------------------------------------------------------------------------*/
enum CliAuthParseHashResult
cliauth_parse_hash_identifier(
   const struct CliAuthParseHashPayload * * payload, 
   const char identifier [],
   CliAuthUInt32 identifier_characters
);

/*----------------------------------------------------------------------------*/
/* Return status enum for cliauth_parse_base32_decode().                      */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_PARSE_BASE32_DECODE_RESULT_SUCCESS - The base-32 string was        */
/*                                              decoded successfully.         */
/*                                                                            */
/* CLIAUTH_PARSE_BASE32_DECODE_RESULT_INVALID_ENCODING - One or more invalid  */
/*                                                       characters were      */
/*                                                       encountered.         */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_PARSE_BASE32_DECODE_RESULT_FIELD_COUNT 2
enum CliAuthParseBase32DecodeResult {
   CLIAUTH_PARSE_BASE32_DECODE_RESULT_SUCCESS,
   CLIAUTH_PARSE_BASE32_DECODE_RESULT_INVALID_ENCODING
};

/*----------------------------------------------------------------------------*/
/* Decodes an RFC 4648 base-32 ASCII string to an array of bytes.             */
/*----------------------------------------------------------------------------*/
/* output - A byte array to store the resulting bytes in.  Any remaining      */
/*          characters which cannot create a full byte will be truncated.     */
/*          This array must be large enough to store the decoded input        */
/*          string.  The required size of this buffer in bytes can be         */
/*          determined with the following formula:                            */
/*                                                                            */
/*          maximum bytes = floor(maximum base-32 string length * 5 / 8)      */
/*                                                                            */
/*          Conversely, the following formula can be used to calculate the    */
/*          maximum acceptable base-32 string length from a known buffer      */
/*          length:                                                           */
/*                                                                            */
/*          maximum base-32 string length = ceil(maximum bytes * 8 / 5)       */
/*                                                                            */
/*          The decoded byte data will only be valid if the function returns  */
/*          'CLIAUTH_PARSE_BASE32_DECODE_RESULT_SUCCESS'.                     */
/*                                                                            */
/* output_bytes - A pointer to the variable to store the final length of the  */
/*                decoded byte data to.  The output byte length will only be  */
/*                valid is the function returns                               */
/*                'CLIAUTH_PARSE_BASE32_DECODE_RESULT_SUCCESS'.               */
/*                                                                            */
/* input - The base-32 string to be decoded.  This string does not have to be */
/*         null-terminated.                                                   */
/*                                                                            */
/* input_characters - The length of 'input' in characters.                    */
/*----------------------------------------------------------------------------*/
/* Return value - The output state of the decoded base-32 string in 'output'. */
/*----------------------------------------------------------------------------*/
enum CliAuthParseBase32DecodeResult
cliauth_parse_base32_decode(
   void * output,
   CliAuthUInt32 * output_bytes,
   const char input [],
   CliAuthUInt32 input_characters
);

/*----------------------------------------------------------------------------*/
/* Return status enum for cliauth_parse_key_uri().                            */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS - The key URI was parsed              */
/*                                        successfully.                       */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_MALFORMED_URI - A general formatting error    */
/*                                              was encountered during        */
/*                                              parsing.                      */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_TYPE - The URI does not contain the   */
/*                                             authentication algorithm to    */
/*                                             use.                           */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_SECRETS - The URI does not contain    */
/*                                                the HOTP/TOTP base-32       */
/*                                                secrets.                    */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_HASH - The URI does not contain the   */
/*                                             HOTP/TOTP hash algorithm.      */
/*                                             The hash algorithm only needs  */
/*                                             to be specified when the SHA1  */
/*                                             algorithm is disabled.         */
/*                                             Otherwise, the hash algorithm  */
/*                                             will default to SHA1 and this  */
/*                                             error will never be returned.  */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_HOTP_COUNTER - The URI specified the  */
/*                                                     HOTP authentication    */
/*                                                     algorithm, however the */
/*                                                     initial counter value  */
/*                                                     was not given.         */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TEXT_ESCAPE - An improperly formatted */
/*                                                    escape sequence was     */
/*                                                    encountered while       */
/*                                                    decoding text.          */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TYPE - An invalid or unknown          */
/*                                             authentication algorithm was   */
/*                                             given.                         */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_SECRETS - An improperly formatted     */
/*                                                base-32 HOTP/TOTP secret    */
/*                                                was given.                  */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_HASH - An invalid or unknown hash     */
/*                                             function was given.            */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_DIGITS - An invalid passcode digits   */
/*                                               count was given.             */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TOTP_PERIOD - An invalid TOTP period  */
/*                                                    length was given.       */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_HOTP_COUNTER - An invalid HOTP        */
/*                                                     counter value was      */
/*                                                     given.                 */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_LABEL - The label before parsing is  */
/*                                               too long.                    */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_ISSUER - The issuer string is too    */
/*                                                long.                       */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_ACCOUNT_NAME - The account name      */
/*                                                      string is too long.   */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_SECRETS - The base-32 secrets string */
/*                                                 is too long.               */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_PARSE_KEY_URI_RESULT_FIELD_COUNT 17
enum CliAuthParseKeyUriResult {
   CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS,
   CLIAUTH_PARSE_KEY_URI_RESULT_MALFORMED_URI,
   CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_TYPE,
   CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_SECRETS,
   CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_HASH,
   CLIAUTH_PARSE_KEY_URI_RESULT_MISSING_HOTP_COUNTER,
   CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TEXT_ESCAPE,
   CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TYPE,
   CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_SECRETS,
   CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_HASH,
   CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_DIGITS,
   CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_TOTP_PERIOD,
   CLIAUTH_PARSE_KEY_URI_RESULT_INVALID_HOTP_COUNTER,
   CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_LABEL,
   CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_ISSUER,
   CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_ACCOUNT_NAME,
   CLIAUTH_PARSE_KEY_URI_RESULT_TOO_LONG_SECRETS
};

/*----------------------------------------------------------------------------*/
/* The type of authenticator algoritm method to use.                          */
/*----------------------------------------------------------------------------*/
/* CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_HOTP - Use the HOTP authentication */
/*                                                method.                     */
/*                                                                            */
/* CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_TOTP - Use the TOTP authentication */
/*                                                method.                     */
/*----------------------------------------------------------------------------*/
#define CLIAUTH_PARSE_KEY_URI_PAYLOAD_SPECIALIZED_TAG_FIELD_COUNT 2
enum CliAuthParseKeyUriPayloadAlgorithm {
   CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_HOTP,
   CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_TOTP
};

/*----------------------------------------------------------------------------*/
/* HOTP-specific key URI parameters.                                          */
/*----------------------------------------------------------------------------*/
/* counter - The initial counter value.                                       */
/*----------------------------------------------------------------------------*/
struct CliAuthParseKeyUriPayloadAlgorithmParametersHotp {
   CliAuthUInt64 counter;
};

/*----------------------------------------------------------------------------*/
/* TOTP-specific key URI parameters.                                          */
/*----------------------------------------------------------------------------*/
/* period - The duration, in seconds, to generate a new passcode.  This will  */
/*          always be greater than zero.                                      */
/*----------------------------------------------------------------------------*/
struct CliAuthParseKeyUriPayloadAlgorithmParametersTotp {
   CliAuthUInt64 period;
};

/*----------------------------------------------------------------------------*/
/* Generic data for algorithm-specific key URI parameters.                    */
/*----------------------------------------------------------------------------*/
/* hotp - HOTP-specific parameters.                                           */
/*                                                                            */
/* totp - TOTP-specific parameters.                                           */
/*----------------------------------------------------------------------------*/
union CliAuthParseKeyUriPayloadAlgorithmParameters {
   struct CliAuthParseKeyUriPayloadAlgorithmParametersHotp hotp;
   struct CliAuthParseKeyUriPayloadAlgorithmParametersTotp totp;
};

#define CLIAUTH_PARSE_KEY_URI_PAYLOAD_SECRETS_MAX_LENGTH       128
#define CLIAUTH_PARSE_KEY_URI_PAYLOAD_ISSUER_MAX_LENGTH        64
#define CLIAUTH_PARSE_KEY_URI_PAYLOAD_ACCOUNT_NAME_MAX_LENGTH  64

#define CLIAUTH_PARSE_KEY_URI_PAYLOAD_DEFAULT_ISSUER_CHARACTERS\
   0
#define CLIAUTH_PARSE_KEY_URI_PAYLOAD_DEFAULT_ACCOUNT_NAME_CHARACTERS\
   0
#define CLIAUTH_PARSE_KEY_URI_PAYLOAD_DEFAULT_DIGITS\
   6
#define CLIAUTH_PARSE_KEY_URI_PAYLOAD_DEFAULT_TOTP_PERIOD\
   30

/*----------------------------------------------------------------------------*/
/* Output parsed key URI from cliauth_parse_otp_uri().                        */
/*----------------------------------------------------------------------------*/
/* algorithm - The type of OTP algorithm to use.  This affects the active     */
/*             union field for 'algorithm_parameters'.                        */
/*                                                                            */
/* algorithm_parameters - Algorithm-specific parameters.  The 'hotp' field    */
/*                        is only valid when 'algorithm' is set to            */
/*                        'CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_HOTP'.     */
/*                        The 'totp' field is only valid when 'algorithm'     */
/*                        is set to                                           */
/*                        'CLIAUTH_PARSE_KEY_URI_PAYLOAD_ALGORITHM_TOTP'.     */
/*                                                                            */
/* hash - The hash function to use with the HOTP/TOTP algorithms.             */
/*                                                                            */
/* secrets - An array of byte data which serves as the 'key' for the          */
/*           HOTP/TOTP algorithms.                                            */
/*                                                                            */
/* issuer - A string which represents the organization which created the OTP  */
/*          URI.  This string is not null-terminated.                         */
/*                                                                            */
/* account_name - A string which represents the name of the account           */
/*                associated with this key URI.  This string is not           */
/*                null-terminated.                                            */
/*                                                                            */
/* secrets_bytes - The length of 'secrets' in bytes.                          */
/*                                                                            */
/* issuer_characters - The length of 'issuer' in characters.                  */
/*                                                                            */
/* account_name_characters - The length of 'account_name' in characters.      */
/*                                                                            */
/* digits - The number of digits the passcode should contain.  This will      */
/*          always be greater than or equal to '1' and less than or equal to  */
/*          '9'.                                                              */
/*----------------------------------------------------------------------------*/
struct CliAuthParseKeyUriPayload {
   enum CliAuthParseKeyUriPayloadAlgorithm algorithm;
   union CliAuthParseKeyUriPayloadAlgorithmParameters algorithm_parameters;
   const struct CliAuthParseHashPayload * hash;
   CliAuthUInt8 secrets [CLIAUTH_PARSE_KEY_URI_PAYLOAD_SECRETS_MAX_LENGTH];
   char issuer [CLIAUTH_PARSE_KEY_URI_PAYLOAD_ISSUER_MAX_LENGTH];
   char account_name [CLIAUTH_PARSE_KEY_URI_PAYLOAD_ACCOUNT_NAME_MAX_LENGTH];
   CliAuthUInt8 secrets_bytes;
   CliAuthUInt8 issuer_characters;
   CliAuthUInt8 account_name_characters;
   CliAuthUInt8 digits;
};

/*----------------------------------------------------------------------------*/
/* Parses a key URI (usually scanned from a QR-code).                         */
/*----------------------------------------------------------------------------*/
/* payload - A pointer to the data to store the parsed key URI in.  The data  */
/*           will only be valid if the function returns                       */
/*          'CLIAUTH_PARSE_KEY_URI_RESULT_SUCCESS'.                           */
/*                                                                            */
/* uri - A string which contains the entire key URI.  The string does not     */
/*       have to be null-terminated.                                          */
/*                                                                            */
/* uri_characters - The length of 'uri' in characters.                        */
/*----------------------------------------------------------------------------*/
/* Return value - An enum representing the state of the parsed key URI in     */
/*                'payload'.                                                  */
/*----------------------------------------------------------------------------*/
enum CliAuthParseKeyUriResult
cliauth_parse_key_uri(
   struct CliAuthParseKeyUriPayload * payload,
   const char uri [],
   CliAuthUInt32 uri_characters
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_PARSE_H */

