/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2024                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/hash.h - Header for hashing algorithms                                 */
/*----------------------------------------------------------------------------*/

#ifndef _CLIAUTH_HASH_H
#define _CLIAUTH_HASH_H
/*----------------------------------------------------------------------------*/

#include "cliauth.h"

/*----------------------------------------------------------------------------*/
/* Defines the context for running a generic hash algorithm.                  */
/*----------------------------------------------------------------------------*/
/* message - A pointer to an array of generic byte data to be digested by the */
/*           algorithm, with the number of bytes given by 'bytes'.            */
/*                                                                            */
/* digest - A pointer to a buffer to write the output hash value.  The size   */
/*          of this buffer depends on the algorithm, but it must be at least  */
/*          the same number of bytes in length as required by the algorithm.  */
/*                                                                            */
/* bytes - The number of bytes to read from 'message'.                        */
/*                                                                            */
/*----------------------------------------------------------------------------*/
struct CliAuthHashContext {
   const void *         message;
   void *               digest;
   CliAuthUInt32        bytes;
};

/*----------------------------------------------------------------------------*/
/* A function pointer for an arbitrary hash algorithm.                        */
/*----------------------------------------------------------------------------*/
typedef void (*CliAuthHashFunction)(const struct CliAuthHashContext * context);

/*----------------------------------------------------------------------------*/
/* SHA-224 hash algorithm.                                                    */
/*----------------------------------------------------------------------------*/
/* The output digest buffer should be of length                               */
/* 'CLIAUTH_HASH_DIGEST_LENGTH_SHA224'.                                       */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_CONFIG_HASH_SHA224
#define CLIAUTH_HASH_SHA224_DIGEST_LENGTH 28
void
cliauth_hash_sha224(const struct CliAuthHashContext * context);
#endif /* CLIAUTH_CONFIG_HASH_SHA224 */

/*----------------------------------------------------------------------------*/
/* SHA-256 hash algorithm.                                                    */
/*----------------------------------------------------------------------------*/
/* The output digest buffer should be of length                               */
/* 'CLIAUTH_HASH_DIGEST_LENGTH_SHA256'.                                       */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_CONFIG_HASH_SHA256
#define CLIAUTH_HASH_SHA256_DIGEST_LENGTH 32
void
cliauth_hash_sha256(const struct CliAuthHashContext * context);
#endif /* CLIAUTH_CONFIG_HASH_SHA256 */

/*----------------------------------------------------------------------------*/
/* SHA-384 hash algorithm.                                                    */
/*----------------------------------------------------------------------------*/
/* The output digest buffer should be of length                               */
/* 'CLIAUTH_HASH_DIGEST_LENGTH_SHA384'.                                       */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_CONFIG_HASH_SHA384
#define CLIAUTH_HASH_SHA384_DIGEST_LENGTH 48
void
cliauth_hash_sha384(const struct CliAuthHashContext * context);
#endif /* CLIAUTH_CONFIG_HASH_SHA384 */

/*----------------------------------------------------------------------------*/
/* SHA-512 hash algorithm.                                                    */
/*----------------------------------------------------------------------------*/
/* The output digest buffer should be of length                               */
/* 'CLIAUTH_HASH_DIGEST_LENGTH_SHA512'.                                       */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_CONFIG_HASH_SHA512
#define CLIAUTH_HASH_SHA512_DIGEST_LENGTH 64
void
cliauth_hash_sha512(const struct CliAuthHashContext * context);
#endif /* CLIAUTH_CONFIG_HASH_SHA512 */

/*----------------------------------------------------------------------------*/
/* SHA-512-224 hash algorithm.                                                */
/*----------------------------------------------------------------------------*/
/* The output digest buffer should be of length                               */
/* 'CLIAUTH_HASH_DIGEST_LENGTH_SHA512_224'.                                   */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_CONFIG_HASH_SHA512_224
#define CLIAUTH_HASH_SHA512_224_DIGEST_LENGTH 28
void
cliauth_hash_sha512_224(const struct CliAuthHashContext * context);
#endif /* CLIAUTH_CONFIG_HASH_SHA512_224 */

/*----------------------------------------------------------------------------*/
/* SHA-512-256 hash algorithm.                                                */
/*----------------------------------------------------------------------------*/
/* The output digest buffer should be of length                               */
/* 'CLIAUTH_HASH_DIGEST_LENGTH_SHA512_256'.                                   */
/*----------------------------------------------------------------------------*/
#if CLIAUTH_CONFIG_HASH_SHA512_256
#define CLIAUTH_HASH_SHA512_256_DIGEST_LENGTH 32
void
cliauth_hash_sha512_256(const struct CliAuthHashContext * context);
#endif /* CLIAUTH_CONFIG_HASH_SHA512_256 */

/*----------------------------------------------------------------------------*/
#endif /* _CLIAUTH_HASH_H */

