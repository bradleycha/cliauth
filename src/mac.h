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
/* Runs the Keyed-Hash Message Authentication Code (HMAC) algorithm.          */
/*----------------------------------------------------------------------------*/
/* hash_function - The hash function to use.                                  */
/*                                                                            */
/* hash_context - A pointer to a hash context struct which is valid for the   */
/*                given hash function.                                        */
/*                                                                            */
/* message - Generic byte data to use as the message input.                   */
/*                                                                            */
/* key - Generic byte data to use as the key input.                           */
/*                                                                            */
/* digest - A byte array long enough to store the digest output as defined by */
/*          the given hash function.                                          */
/*                                                                            */
/* key_buffer - A temporary byte buffer used internally.  Should be long      */
/*              enough to store a single block as defined by the hash         */
/*              algorithm.                                                    */
/*                                                                            */
/* message_bytes - The number of bytes to read from 'message'.                */
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
/*                expected length of the output digest buffer.                */
/*----------------------------------------------------------------------------*/
void
cliauth_mac_hmac(
   const struct CliAuthHashFunction * hash_function,
   void * hash_context,
   const void * message,
   const void * key,
   void * digest,
   void * key_buffer,
   CliAuthUInt32 message_bytes,
   CliAuthUInt32 key_bytes,
   CliAuthUInt32 block_bytes,
   CliAuthUInt32 digest_bytes
);

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_MAC_H */

