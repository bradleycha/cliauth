/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/mac.h - Message authentication code (MAC) algorithms header.           */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_MAC_H
#define _CLIAUTH_MAC_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"
#include "hash.h"
#include "io.h"

/*----------------------------------------------------------------------------*/
/* Stores internal variables used when calculating a keyed-hash message       */
/* authentication code (HMAC) digest.                                         */
/*----------------------------------------------------------------------------*/
struct CliAuthMacHmacContext {
   /* the buffer to compute and store k0 in */
   CliAuthUInt8 * k0_buffer;

   /* the buffer to compute intermediate digest values */
   CliAuthUInt8 * digest_buffer;

   /* the hash function to use */
   const struct CliAuthHashFunction * hash_function;

   /* the hash context to use with the hash function */
   void * hash_context;

   /* the length of a single hash input block in bytes */
   CliAuthUInt8 block_bytes;

   /* the length of the hash digest in bytes */
   CliAuthUInt8 digest_bytes;

   /* the number of remaining bytes in the k0 buffer */
   CliAuthUInt8 k0_capacity;

   /* whether hashing has been initiated when the key length is greater than */
   /* the hash input block length */
   CliAuthBoolean k0_hash_initiated;
};

/*----------------------------------------------------------------------------*/
/* Initializes the HMAC context.                                              */
/*----------------------------------------------------------------------------*/
/* context - The HMAC context to initialize.                                  */
/*                                                                            */
/* key_buffer - An array of bytes used internally.  The given array must at   */
/*              least be long enough to store a single hash input block as    */
/*              given by 'block_bytes'.                                       */
/*                                                                            */
/* digest_buffer - An array of bytes used internally.  The given array must   */
/*                 at least be long enough to store a hash digest value as    */
/*                 given by 'digest_bytes'.                                   */
/*                                                                            */
/* hash_function - The hash function to compute the HMAC digest with.         */
/*                                                                            */
/* hash_context - The context struct specific to 'hash_function'.  This may   */
/*                not be re-used until after                                  */
/*                'cliauth_mac_hmac_message_finalize()' has been called.      */
/*                                                                            */
/* block_bytes - The number of bytes which consist of a single input block    */
/*               specific to 'hash_function'.                                 */
/*                                                                            */
/* digest_bytes - The number of bytes which consist of the output digest      */
/*                specific to 'hash_function'.                                */
/*----------------------------------------------------------------------------*/
void
cliauth_mac_hmac_initialize(
   struct CliAuthMacHmacContext * context,
   CliAuthUInt8 key_buffer [],
   CliAuthUInt8 digest_buffer [],
   const struct CliAuthHashFunction * hash_function,
   void * hash_context,
   CliAuthUInt8 block_bytes,
   CliAuthUInt8 digest_bytes
);

/*----------------------------------------------------------------------------*/
/* Digests bytes as the secret key value for the HMAC algorithm.              */
/*----------------------------------------------------------------------------*/
/* context - The HMAC context to digest into.  The given context must         */
/*           first be initialized with 'cliauth_mac_hmac_initialize()' and    */
/*           must not have been finalized by                                  */
/*           'cliauth_mac_hmac_key_finalize()'.                               */
/*                                                                            */
/* key_reader - The reader to source the key bytes from.                      */
/*                                                                            */
/* key_bytes - The number of bytes to read from 'key_reader'.                 */
/*----------------------------------------------------------------------------*/
/* Return value - The result of reading the key from 'key_reader'.  If the    */
/*                returned read result status is not                          */
/*                'CLIAUTH_IO_READ_STATUS_SUCCESS', the number of digested    */
/*                bytes can be obtained from the 'bytes' field in the         */
/*                returned read result.                                       */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReadResult
cliauth_mac_hmac_key_digest(
   struct CliAuthMacHmacContext * context,
   const struct CliAuthIoReader * key_reader,
   CliAuthUInt32 key_bytes
);

/*----------------------------------------------------------------------------*/
/* Finalizes the HMAC secret key value.                                       */
/*----------------------------------------------------------------------------*/
/* context - The HMAC context whose key to finalize.  The context must have   */
/*           been initialized with 'cliauth_mac_hmac_initialize()'.  Key      */
/*           bytes may no longer be digested by                               */
/*           'cliauth_mac_hmac_key_digest()' after execution.                 */
/*----------------------------------------------------------------------------*/
void
cliauth_mac_hmac_key_finalize(
   struct CliAuthMacHmacContext * context
);

/*----------------------------------------------------------------------------*/
/* Digests bytes as the message for the HMAC algorithm.                       */
/*----------------------------------------------------------------------------*/
/* context - The HMAC context to digest into.  The given context must first   */
/*           have had its secret key digested and finalized with              */
/*           'cliauth_mac_hmac_key_finalize()' and must not have been         */
/*           finalized with 'cliauth_mac_hmac_finalize()'.                    */
/*----------------------------------------------------------------------------*/
/* Return value - The result of reading the key from 'message_reader'.  If    */
/*                the returned read result status is not                      */
/*                'CLIAUTH_IO_READ_STATUS_SUCCESS', the number of digested    */
/*                bytes can be obtained from the 'bytes' field in the         */
/*                returned read result.                                       */
/*----------------------------------------------------------------------------*/
struct CliAuthIoReadResult
cliauth_mac_hmac_message_digest(
   struct CliAuthMacHmacContext * context,
   const struct CliAuthIoReader * message_reader,
   CliAuthUInt32 message_bytes
);

/*----------------------------------------------------------------------------*/
/* Calculate the final HMAC digest value.                                     */
/*----------------------------------------------------------------------------*/
/* context - The context to finalize.  The given context must first have had  */
/*           its secret key value finalized with                              */
/*           'cliauth_mac_hmac_key_finalize()'.  To use the HMAC context      */
/*           again, it must be re-initialized with                            */
/*           'cliauth_mac_hmac_initialize()'.                                 */
/*----------------------------------------------------------------------------*/
/* Return value - A pointer to the final digest value.  The pointer will have */
/*                the same lifetime as the hash context given when the        */
/*                context was initialized.  For more information, see the     */
/*                documentation for CliAuthHashFunctionFinalize.              */
/*----------------------------------------------------------------------------*/
CliAuthUInt8 *
cliauth_mac_hmac_finalize(
   struct CliAuthMacHmacContext * context
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_MAC_H */

