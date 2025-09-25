/*----------------------------------------------------------------------------*/
/*                         Copyright (c) CliAuth 2025                         */
/*                   https://github.com/bradleycha/cliauth                    */
/*----------------------------------------------------------------------------*/
/* src/test/crypto/i_otp.c - One-time passcode unit tests.                    */
/*----------------------------------------------------------------------------*/

#include "test/cliauth_test.h"
#include "test/crypto/i_otp.h"

#include "cliauth/cliauth.h"
#include "cliauth/io/log.h"
#include "cliauth/io/byte_array_mapper.h"
#include "cliauth/io/mapper_stream.h"
#include "cliauth/io/io.h"
#include "cliauth/crypto/otp.h"
#include "cliauth/crypto/hash.h"

#include <inttypes.h>

/* these tests require SHA1 support */
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_ENABLE \
   (CLIAUTH_CONFIG_CRYPTO_HASH_SHA1)

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_NODE_LABEL \
   "crypto/otp/hotp"
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_NODE_LABEL_CHARACTERS \
   CLIAUTH_STRING_CHARACTERS(CLIAUTH_TEST_CRYPTO_OTP_HOTP_NODE_LABEL)

#if CLIAUTH_TEST_CRYPTO_OTP_HOTP_ENABLE
/*----------------------------------------------------------------------------*/

static const CliAuthUInt8
cliauth_test_crypto_otp_hotp_key [] = {
   0xdd, 0x53, 0x56, 0x3b, 0x3a, 0x4a, 0x8b, 0x95,
   0x1b, 0xf3, 0xf0, 0xcd, 0x6e, 0x6f, 0xdb, 0x08,
   0xaa, 0x6f, 0x1c, 0xa3, 0xd7, 0x0f, 0xd0, 0x26,
   0x96, 0xcd, 0xa9, 0xea, 0xd9, 0x04, 0x54, 0x15,
   0x8f, 0x2c, 0xc7, 0x8b, 0x85, 0x84, 0xd5, 0x61,
   0x44, 0x07, 0xb6, 0xd0, 0x03, 0x27, 0x1f
};

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_KEY_BYTES \
   (sizeof(cliauth_test_crypto_otp_hotp_key))

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_otp_hotp_runner(
   CliAuthUInt64 counter,
   CliAuthUInt8 digits,
   CliAuthUInt32 passcode_expected
) {
   struct CliAuthIoByteArrayMapperReader key_byte_array_mapper_reader;
   struct CliAuthIoMapperReader key_mapper_reader;
   struct CliAuthIoMapperStreamReader key_mapper_stream_reader;
   struct CliAuthIoStreamReader key_stream_reader;
   struct CliAuthCryptoOtpHotpContext hotp_context;
   CliAuthUInt32 key_bytes_remaining;
   struct CliAuthIoResult io_result;
   CliAuthUInt32 passcode_calculated;

   cliauth_io_byte_array_mapper_reader_initialize(
      &key_byte_array_mapper_reader,
      cliauth_test_crypto_otp_hotp_key
   );
   key_mapper_reader = cliauth_io_byte_array_mapper_reader_interface(
      &key_byte_array_mapper_reader
   );
   cliauth_io_mapper_stream_reader_initialize(
      &key_mapper_stream_reader,
      &key_mapper_reader,
      CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_HOTP_KEY_BYTES),
      CLIAUTH_LITERAL_UINT32(0u)
   );
   key_stream_reader = cliauth_io_mapper_stream_reader_interface(
      &key_mapper_stream_reader
   );

   cliauth_crypto_otp_hotp_initialize(
      &hotp_context,
      &cliauth_crypto_hash[CLIAUTH_CRYPTO_HASH_INDEX_SHA1],
      counter,
      digits
   );

   key_bytes_remaining = CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_HOTP_KEY_BYTES);
   while (key_bytes_remaining != CLIAUTH_LITERAL_UINT32(0u)) {
      io_result = cliauth_crypto_otp_hotp_key_digest(
         &hotp_context,
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

   passcode_calculated = cliauth_crypto_otp_hotp_finalize(
      &hotp_context
   );

   if (passcode_expected != passcode_calculated) {
      cliauth_io_log(
         CLIAUTH_IO_LOG_ERROR("calculated passcode %0*" PRIu32 ", expected passcode %0*" PRIu32),
         digits,
         passcode_calculated,
         digits,
         passcode_expected
      );
      return CLIAUTH_TEST_RUNNER_STATUS_FAILED;
   }

   return CLIAUTH_TEST_RUNNER_STATUS_PASSED;
}

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE1_NODE_LABEL \
   "crypto/otp/hotp (case 1)"
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE1_NODE_LABEL_CHARACTERS \
   CLIAUTH_STRING_CHARACTERS(CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE1_NODE_LABEL)

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE1_COUNTER \
   CLIAUTH_LITERAL_UINT64(0u, 0u)
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE1_DIGITS \
   CLIAUTH_LITERAL_UINT8(6u)
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE1_PASSCODE_EXPECTED \
   CLIAUTH_LITERAL_UINT32(562161u)

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_otp_hotp_case1_runner(void) {
   return cliauth_test_crypto_otp_hotp_runner(
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE1_COUNTER,
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE1_DIGITS,
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE1_PASSCODE_EXPECTED
   );
}

static const struct CliAuthTestNode
cliauth_test_crypto_otp_hotp_case1_node = {
   CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE1_NODE_LABEL,  
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE1_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_otp_hotp_case1_runner
};

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE2_NODE_LABEL \
   "crypto/otp/hotp (case 2)"
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE2_NODE_LABEL_CHARACTERS \
   CLIAUTH_STRING_CHARACTERS(CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE2_NODE_LABEL)

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE2_COUNTER \
   CLIAUTH_LITERAL_UINT64(0u, 42u)
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE2_DIGITS \
   CLIAUTH_LITERAL_UINT8(8u)
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE2_PASSCODE_EXPECTED \
   CLIAUTH_LITERAL_UINT32(42122732u)

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_otp_hotp_case2_runner(void) {
   return cliauth_test_crypto_otp_hotp_runner(
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE2_COUNTER,
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE2_DIGITS,
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE2_PASSCODE_EXPECTED
   );
}

static const struct CliAuthTestNode
cliauth_test_crypto_otp_hotp_case2_node = {
   CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE2_NODE_LABEL,  
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE2_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_otp_hotp_case2_runner
};

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE3_NODE_LABEL \
   "crypto/otp/hotp (case 3)"
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE3_NODE_LABEL_CHARACTERS \
   CLIAUTH_STRING_CHARACTERS(CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE3_NODE_LABEL)

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE3_COUNTER \
   CLIAUTH_LITERAL_UINT64(0u, 9999999u)
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE3_DIGITS \
   CLIAUTH_LITERAL_UINT8(9u)
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE3_PASSCODE_EXPECTED \
   CLIAUTH_LITERAL_UINT32(408140611u)

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_otp_hotp_case3_runner(void) {
   return cliauth_test_crypto_otp_hotp_runner(
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE3_COUNTER,
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE3_DIGITS,
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE3_PASSCODE_EXPECTED
   );
}

static const struct CliAuthTestNode
cliauth_test_crypto_otp_hotp_case3_node = {
   CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE3_NODE_LABEL,  
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE3_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_otp_hotp_case3_runner
};

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE4_NODE_LABEL \
   "crypto/otp/hotp (case 4)"
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE4_NODE_LABEL_CHARACTERS \
   CLIAUTH_STRING_CHARACTERS(CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE4_NODE_LABEL)

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE4_COUNTER \
   CLIAUTH_LITERAL_UINT64(0x00000000u, 0xffffffffu)
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE4_DIGITS \
   CLIAUTH_LITERAL_UINT8(9u)
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE4_PASSCODE_EXPECTED \
   CLIAUTH_LITERAL_UINT32(419893689u)

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_otp_hotp_case4_runner(void) {
   return cliauth_test_crypto_otp_hotp_runner(
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE4_COUNTER,
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE4_DIGITS,
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE4_PASSCODE_EXPECTED
   );
}

static const struct CliAuthTestNode
cliauth_test_crypto_otp_hotp_case4_node = {
   CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE4_NODE_LABEL,  
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE4_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_otp_hotp_case4_runner
};

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE5_NODE_LABEL \
   "crypto/otp/hotp (case 5)"
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE5_NODE_LABEL_CHARACTERS \
   CLIAUTH_STRING_CHARACTERS(CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE5_NODE_LABEL)

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE5_COUNTER \
   CLIAUTH_LITERAL_UINT64(0x01234567u, 0x89abcdefu)
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE5_DIGITS \
   CLIAUTH_LITERAL_UINT8(9u)
#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE5_PASSCODE_EXPECTED \
   CLIAUTH_LITERAL_UINT32(986870641u)

static enum CliAuthTestRunnerStatus
cliauth_test_crypto_otp_hotp_case5_runner(void) {
   return cliauth_test_crypto_otp_hotp_runner(
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE5_COUNTER,
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE5_DIGITS,
      CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE5_PASSCODE_EXPECTED
   );
}

static const struct CliAuthTestNode
cliauth_test_crypto_otp_hotp_case5_node = {
   CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE5_NODE_LABEL,  
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_HOTP_CASE5_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   cliauth_test_crypto_otp_hotp_case5_runner
};

static const struct CliAuthTestNode *
cliauth_test_crypto_otp_hotp_node_children [] = {
   &cliauth_test_crypto_otp_hotp_case1_node,
   &cliauth_test_crypto_otp_hotp_case2_node,
   &cliauth_test_crypto_otp_hotp_case3_node,
   &cliauth_test_crypto_otp_hotp_case4_node,
   &cliauth_test_crypto_otp_hotp_case5_node
};

#define CLIAUTH_TEST_CRYPTO_OTP_HOTP_NODE_CHILDREN_COUNT \
   CLIAUTH_ARRAY_ELEMENTS(cliauth_test_crypto_otp_hotp_node_children)

static const struct CliAuthTestNode
cliauth_test_crypto_otp_hotp_node = {
   CLIAUTH_TEST_CRYPTO_OTP_HOTP_NODE_LABEL,
   cliauth_test_crypto_otp_hotp_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_HOTP_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_HOTP_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

/*----------------------------------------------------------------------------*/
#else /* CLIAUTH_TEST_CRYPTO_OTP_HOTP_ENABLE */
/*----------------------------------------------------------------------------*/

/* disables all HOTP unit tests when unavailable */
static const struct CliAuthTestNode
cliauth_test_crypto_otp_hotp_node = {
   CLIAUTH_TEST_CRYPTO_OTP_HOTP_NODE_LABEL,
   CLIAUTH_NULLPTR,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_HOTP_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(0u),
   CLIAUTH_NULLPTR
};

/*----------------------------------------------------------------------------*/
#endif /* CLIAUTH_TEST_CRYPTO_OTP_HOTP_ENABLE */

#define CLIAUTH_TEST_CRYPTO_OTP_NODE_LABEL \
   "crypto/otp"
#define CLIAUTH_TEST_CRYPTO_OTP_NODE_LABEL_CHARACTERS \
   CLIAUTH_STRING_CHARACTERS(CLIAUTH_TEST_CRYPTO_OTP_NODE_LABEL)

static const struct CliAuthTestNode *
cliauth_test_crypto_otp_node_children [] = {
   &cliauth_test_crypto_otp_hotp_node
};

#define CLIAUTH_TEST_CRYPTO_OTP_NODE_CHILDREN_COUNT \
   CLIAUTH_ARRAY_ELEMENTS(cliauth_test_crypto_otp_node_children)

const struct CliAuthTestNode
cliauth_test_crypto_otp_node = {
   CLIAUTH_TEST_CRYPTO_OTP_NODE_LABEL,
   cliauth_test_crypto_otp_node_children,
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_NODE_LABEL_CHARACTERS),
   CLIAUTH_LITERAL_UINT32(CLIAUTH_TEST_CRYPTO_OTP_NODE_CHILDREN_COUNT),
   CLIAUTH_NULLPTR
};

