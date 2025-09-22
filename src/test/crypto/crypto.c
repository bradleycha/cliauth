/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2025                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/test/crypto/crypto.c - Cryptographic API unit tests implementations.   */
/*----------------------------------------------------------------------------*/

#include "test/cliauth_test.h"
#include "test/crypto/crypto.h"

#include "cliauth/cliauth.h"
#include "test/crypto/i_hash.h"
#include "test/crypto/i_mac.h"

#define CLIAUTH_TEST_CRYPTO_NODE_LABEL \
   "crypto"
#define CLIAUTH_TEST_CRYPTO_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_NODE_LABEL) / sizeof(char)) - 1u)

static const struct CliAuthTestNode *
cliauth_test_crypto_node_children [] = {
   &cliauth_test_crypto_hash_node,
   &cliauth_test_crypto_mac_node
};

#define CLIAUTH_TEST_CRYPTO_NODE_CHILDREN_COUNT \
   ( \
      sizeof(cliauth_test_crypto_node_children) / \
      sizeof(cliauth_test_crypto_node_children[0]) \
   )

const struct CliAuthTestNode
cliauth_test_crypto_node = {
   CLIAUTH_TEST_CRYPTO_NODE_LABEL,
   cliauth_test_crypto_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

