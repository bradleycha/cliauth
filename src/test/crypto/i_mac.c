/*----------------------------------------------------------------------------*/
/*                      Copyright (c) CliAuth 2024, 2025                      */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/test/crypto/i_mac.c - Message authentication codes unit tests          */
/*    implementations.                                                        */
/*----------------------------------------------------------------------------*/

#include "test/cliauth_test.h"
#include "test/crypto/i_mac.h"

#include "cliauth/cliauth.h"
#include "cliauth/io/log.h"
#include "cliauth/io/byte_array_mapper.h"
#include "cliauth/io/mapper_stream.h"
#include "cliauth/io/io.h"
#include "cliauth/crypto/mac.h"
#include "cliauth/crypto/hash.h"
#include "cliauth/memory/memory.h"

#include <inttypes.h>

/* these tests require SHA1 support */
#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_ENABLE\
   (CLIAUTH_CONFIG_CRYPTO_HASH_SHA1)

#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_NODE_LABEL \
   "crypto/mac/hmac"
#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_MAC_HMAC_NODE_LABEL) / sizeof(char)) - 1)

#if CLIAUTH_TEST_CRYPTO_MAC_HMAC_ENABLE
/*----------------------------------------------------------------------------*/

static const CliAuthUInt8
cliauth_test_crypto_mac_hmac_message [] = {
   0xb1, 0x11, 0x16, 0x80, 0x00, 0x00, 0x81, 0xe5,
   0xb1, 0x11, 0x16, 0xd1, 0x11, 0x11, 0x11, 0xc5
};

#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_MESSAGE_BYTES \
   (sizeof(cliauth_test_crypto_mac_hmac_message))

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_mac_hmac_runner(
   const CliAuthUInt8 * key,
   CliAuthUInt32 key_bytes,
   const CliAuthUInt8 * digest_expected
) {
   struct CliAuthIoByteArrayMapperReader message_byte_array_mapper_reader;
   struct CliAuthIoByteArrayMapperReader key_byte_array_mapper_reader;
   struct CliAuthIoMapperReader message_mapper_reader;
   struct CliAuthIoMapperReader key_mapper_reader;
   struct CliAuthIoMapperStreamReader message_mapper_stream_reader;
   struct CliAuthIoMapperStreamReader key_mapper_stream_reader;
   struct CliAuthIoStreamReader message_stream_reader;
   struct CliAuthIoStreamReader key_stream_reader;
   struct CliAuthCryptoMacHmacContext hmac_context;
   CliAuthUInt32 message_bytes_remaining;
   CliAuthUInt32 key_bytes_remaining;
   struct CliAuthIoResult io_result;
   CliAuthUInt8 * digest_calculated;

   cliauth_io_byte_array_mapper_reader_initialize(
      &message_byte_array_mapper_reader,
      cliauth_test_crypto_mac_hmac_message
   );
   cliauth_io_byte_array_mapper_reader_initialize(
      &key_byte_array_mapper_reader,
      key
   );
   message_mapper_reader = cliauth_io_byte_array_mapper_reader_interface(
      &message_byte_array_mapper_reader
   );
   key_mapper_reader = cliauth_io_byte_array_mapper_reader_interface(
      &key_byte_array_mapper_reader
   );
   cliauth_io_mapper_stream_reader_initialize(
      &message_mapper_stream_reader,
      &message_mapper_reader,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_HMAC_MESSAGE_BYTES),
      CLIAUTH_LITERAL_UINT32(0u)
   );
   cliauth_io_mapper_stream_reader_initialize(
      &key_mapper_stream_reader,
      &key_mapper_reader,
      key_bytes,
      CLIAUTH_LITERAL_UINT32(0u)
   );
   message_stream_reader = cliauth_io_mapper_stream_reader_interface(
      &message_mapper_stream_reader
   );
   key_stream_reader = cliauth_io_mapper_stream_reader_interface(
      &key_mapper_stream_reader
   );

   cliauth_crypto_mac_hmac_initialize(
      &hmac_context,
      &cliauth_crypto_hash[CLIAUTH_CRYPTO_HASH_INDEX_SHA1]
   );

   key_bytes_remaining = key_bytes;
   while (key_bytes_remaining != CLIAUTH_LITERAL_UINT32(0u)) {
      io_result = cliauth_crypto_mac_hmac_key_digest(
         &hmac_context,
         &key_stream_reader,
         key_bytes_remaining
      );
      key_bytes_remaining -= io_result.bytes;

      switch (io_result.status) {
         case CLIAUTH_IO_STATUS_SUCCESS:
         case CLIAUTH_IO_STATUS_BUSY:
            break;

         case CLIAUTH_IO_STATUS_END_OF_STREAM:
            cliauth_io_log(
               CLIAUTH_IO_LOG_ERROR("unexpectedly reached I/O end of stream with %" PRIu32 " undigested key bytes"),
               key_bytes_remaining
            );
            return CLIAUTH_TEST_RUNNER_STATUS_FAILED;

         case CLIAUTH_IO_STATUS_ERROR_UNKNOWN:
            cliauth_io_log(
               CLIAUTH_IO_LOG_ERROR("unexpectedly encountered an unknown I/O error with %" PRIu32 " undigested key bytes"),
               key_bytes_remaining
            );
            return CLIAUTH_TEST_RUNNER_STATUS_FAILED;

         default:
            CLIAUTH_UNREACHABLE;
      }
   }

   cliauth_crypto_mac_hmac_key_finalize(&hmac_context);

   message_bytes_remaining = CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_HMAC_MESSAGE_BYTES);
   while (message_bytes_remaining != CLIAUTH_LITERAL_UINT32(0u)) {
      io_result = cliauth_crypto_mac_hmac_message_digest(
         &hmac_context,
         &message_stream_reader,
         message_bytes_remaining
      );
      message_bytes_remaining -= io_result.bytes;

      switch (io_result.status) {
         case CLIAUTH_IO_STATUS_SUCCESS:
         case CLIAUTH_IO_STATUS_BUSY:
            break;

         case CLIAUTH_IO_STATUS_END_OF_STREAM:
            cliauth_io_log(
               CLIAUTH_IO_LOG_ERROR("unexpectedly reached I/O end of stream with %" PRIu32 " undigested message bytes"),
               message_bytes_remaining
            );
            return CLIAUTH_TEST_RUNNER_STATUS_FAILED;

         case CLIAUTH_IO_STATUS_ERROR_UNKNOWN:
            cliauth_io_log(
               CLIAUTH_IO_LOG_ERROR("unexpectedly encountered an unknown I/O error with %" PRIu32 " undigested message bytes"),
               message_bytes_remaining
            );
            return CLIAUTH_TEST_RUNNER_STATUS_FAILED;

         default:
            CLIAUTH_UNREACHABLE;
      }
   }

   digest_calculated = cliauth_crypto_mac_hmac_finalize(&hmac_context);

   if (cliauth_memory_compare_with_equal_lengths(
      digest_expected,
      digest_calculated,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_CRYPTO_HASH_SHA1_DIGEST_LENGTH)
   ) == CLIAUTH_BOOLEAN_FALSE) {
      cliauth_io_log(CLIAUTH_IO_LOG_ERROR("expected digest and calculated digest are not the same"));
      return CLIAUTH_TEST_RUNNER_STATUS_FAILED;
   }

   return CLIAUTH_TEST_RUNNER_STATUS_PASSED;
}

static const CliAuthUInt8
cliauth_test_crypto_mac_hmac_key1 [] = {
   0x85, 0x23, 0xd5, 0xca, 0xb1, 0x2c, 0x87, 0xed,
   0x6e, 0x2d, 0xfc, 0x60, 0x50, 0xef, 0x16, 0x24
};

#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY1_BYTES \
   (sizeof(cliauth_test_crypto_mac_hmac_key1))

static const CliAuthUInt8
cliauth_test_crypto_mac_hmac_key1_digest [CLIAUTH_CRYPTO_HASH_SHA1_DIGEST_LENGTH] = {
   0x5a, 0xe4, 0x17, 0x06, 0xe8, 0x77, 0x93, 0x64,
   0xc3, 0xf9, 0x0e, 0xa3, 0x28, 0xce, 0x8f, 0xef,
   0xbb, 0xc3, 0xda, 0xda
};

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_mac_hmac_key1_runner(void) {
   return cliauth_test_crypto_mac_hmac_runner(
      cliauth_test_crypto_mac_hmac_key1,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY1_BYTES),
      cliauth_test_crypto_mac_hmac_key1_digest
   );
}

static const CliAuthUInt8
cliauth_test_crypto_mac_hmac_key2 [] = {
   0xda, 0xe1, 0x96, 0x9c, 0x6c, 0xe7, 0xff, 0xf8,
   0x15, 0x15, 0xcc, 0x6d, 0xc7, 0xe0, 0x76, 0x6e,
   0x99, 0xe9, 0x03, 0x9d, 0x84, 0x1a, 0x8a, 0x73,
   0xde, 0xa9, 0x37, 0x48, 0xda, 0x68, 0x6d, 0xa8,
   0x62, 0x56, 0x88, 0x76, 0x7d, 0xdb, 0x87, 0x03,
   0x72, 0x4a, 0x61, 0xa4, 0x0a, 0x15, 0x0d, 0x6b,
   0x8d, 0x43, 0xce, 0x9b, 0x6f, 0xf1, 0x1b, 0x3d,
   0x54, 0x07, 0x83, 0x52, 0x25, 0x52, 0x95, 0xae
};

#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY2_BYTES \
   (sizeof(cliauth_test_crypto_mac_hmac_key2))

static const CliAuthUInt8
cliauth_test_crypto_mac_hmac_key2_digest [CLIAUTH_CRYPTO_HASH_SHA1_DIGEST_LENGTH] = {
   0xc5, 0x79, 0xd3, 0xbd, 0xf8, 0x4f, 0x2c, 0xf5,
   0x60, 0xe1, 0xb2, 0xbf, 0x11, 0x73, 0x03, 0xfe,
   0xce, 0x10, 0xb8, 0x89
};

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_mac_hmac_key2_runner(void) {
   return cliauth_test_crypto_mac_hmac_runner(
      cliauth_test_crypto_mac_hmac_key2,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY2_BYTES),
      cliauth_test_crypto_mac_hmac_key2_digest
   );
}

static const CliAuthUInt8
cliauth_test_crypto_mac_hmac_key3 [] = {
   0xda, 0x0c, 0x0b, 0x33, 0xcd, 0xa4, 0xe5, 0x9d,
   0xa9, 0x3d, 0x0c, 0x47, 0x9d, 0x7a, 0x15, 0xe0,
   0x15, 0x73, 0xfc, 0xc0, 0x15, 0x2c, 0x9d, 0x0a,
   0x8c, 0x4c, 0x31, 0x70, 0x5f, 0x34, 0x9a, 0xdd,
   0x0f, 0x61, 0x72, 0x44, 0xc7, 0x10, 0xc1, 0x3b,
   0x45, 0xd1, 0x89, 0xf3, 0x9b, 0xa8, 0x89, 0x97,
   0x49, 0x56, 0x71, 0x21, 0x9e, 0x67, 0x7f, 0x6b,
   0x0b, 0x7c, 0xca, 0x99, 0x55, 0x5f, 0x72, 0xf5,
   0x84, 0xcd, 0xe9, 0x09, 0xa4, 0xce, 0x6d, 0xe1,
   0x62, 0x6c, 0x2a, 0x36, 0x2c, 0xe6, 0x3e, 0xe1,
   0xdc, 0x96, 0x69, 0x84, 0xd9, 0xea, 0xb2, 0xdd,
   0xa8, 0xc6, 0xf3, 0x93, 0x6a, 0x5b, 0x4b, 0x62,
   0x73
};

#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY3_BYTES \
   (sizeof(cliauth_test_crypto_mac_hmac_key3))

static const CliAuthUInt8
cliauth_test_crypto_mac_hmac_key3_digest [CLIAUTH_CRYPTO_HASH_SHA1_DIGEST_LENGTH] = {
   0xf3, 0x45, 0xbe, 0x31, 0xf9, 0xe2, 0xd2, 0x85,
   0x95, 0x79, 0x88, 0x7a, 0xff, 0x7c, 0xd5, 0x24,
   0xab, 0xfe, 0x94, 0x9c
};

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_mac_hmac_key3_runner(void) {
   return cliauth_test_crypto_mac_hmac_runner(
      cliauth_test_crypto_mac_hmac_key3,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY3_BYTES),
      cliauth_test_crypto_mac_hmac_key3_digest
   );
}

#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY1_NODE_LABEL \
   "crypto/mac/hmac (key 1, |K| < K_0)"
#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY1_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY1_NODE_LABEL) / sizeof(char)) - 1)

static const struct CliAuthTestNode
cliauth_test_crypto_mac_hmac_key1_node = {
   CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY1_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY1_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_mac_hmac_key1_runner
};

#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY2_NODE_LABEL \
   "crypto/mac/hmac (key 2, |K| = K_0)"
#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY2_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY2_NODE_LABEL) / sizeof(char)) - 1)

static const struct CliAuthTestNode
cliauth_test_crypto_mac_hmac_key2_node = {
   CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY2_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY2_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_mac_hmac_key2_runner
};

#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY3_NODE_LABEL \
   "crypto/mac/hmac (key 3, |K| > K_0)"
#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY3_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY3_NODE_LABEL) / sizeof(char)) - 1)

static const struct CliAuthTestNode
cliauth_test_crypto_mac_hmac_key3_node = {
   CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY3_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_HMAC_KEY3_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_mac_hmac_key3_runner
};

static const struct CliAuthTestNode *
cliauth_test_crypto_mac_hmac_node_children [] = {
   &cliauth_test_crypto_mac_hmac_key1_node,
   &cliauth_test_crypto_mac_hmac_key2_node,
   &cliauth_test_crypto_mac_hmac_key3_node
};

#define CLIAUTH_TEST_CRYPTO_MAC_HMAC_NODE_CHILDREN_COUNT \
   ( \
      sizeof(cliauth_test_crypto_mac_hmac_node_children) / \
      sizeof(cliauth_test_crypto_mac_hmac_node_children[0]) \
   )

static const struct CliAuthTestNode
cliauth_test_crypto_mac_hmac_node = {
   CLIAUTH_TEST_CRYPTO_MAC_HMAC_NODE_LABEL,
   cliauth_test_crypto_mac_hmac_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_HMAC_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_HMAC_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

/*----------------------------------------------------------------------------*/
#else /* CLIAUTH_TEST_CRYPTO_MAC_HMAC_ENABLE */
/*----------------------------------------------------------------------------*/

/* disables all HMAC unit tests when unavailable */
static const struct CliAuthTestNode
cliauth_test_crypto_mac_hmac_node = {
   CLIAUTH_TEST_CRYPTO_MAC_HMAC_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_HMAC_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   CLIAUTH_NULLPTR
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_TEST_CRYPTO_MAC_HMAC_ENABLE */

#define CLIAUTH_TEST_CRYPTO_MAC_NODE_LABEL \
   "crypto/mac"
#define CLIAUTH_TEST_CRYPTO_MAC_NODE_LABEL_CHARACTERS \
   ((sizeof(CLIAUTH_TEST_CRYPTO_MAC_NODE_LABEL) / sizeof(char)) - 1)

static const struct CliAuthTestNode *
cliauth_test_crypto_mac_node_children [] = {
   &cliauth_test_crypto_mac_hmac_node
};

#define CLIAUTH_TEST_CRYPTO_MAC_NODE_CHILDREN_COUNT \
   ( \
      sizeof(cliauth_test_crypto_mac_node_children) / \
      sizeof(cliauth_test_crypto_mac_node_children[0]) \
   )

const struct CliAuthTestNode
cliauth_test_crypto_mac_node = {
   CLIAUTH_TEST_CRYPTO_MAC_NODE_LABEL,
   cliauth_test_crypto_mac_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_MAC_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

