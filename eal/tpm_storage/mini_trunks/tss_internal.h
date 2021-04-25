// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINI_TRUNKS_TSS_INTERNAL_H_
#define MINI_TRUNKS_TSS_INTERNAL_H_

#include <string>
#include "tss.h"

size_t GetNumberOfRequestHandles(TPM_CC command_code);
size_t GetNumberOfResponseHandles(TPM_CC command_code);

TPM_RC Serialize_uint8_t(const uint8_t& value,
                         std::string* buffer);

TPM_RC Parse_uint8_t(std::string* buffer,
                     uint8_t* value,
                     std::string* value_bytes);

TPM_RC Serialize_int8_t(const int8_t& value, std::string* buffer);

TPM_RC Parse_int8_t(std::string* buffer,
                    int8_t* value,
                    std::string* value_bytes);

TPM_RC Serialize_int(const int& value, std::string* buffer);

TPM_RC Parse_int(std::string* buffer,
                 int* value,
                 std::string* value_bytes);

TPM_RC Serialize_uint16_t(const uint16_t& value,
                          std::string* buffer);

TPM_RC Parse_uint16_t(std::string* buffer,
                      uint16_t* value,
                      std::string* value_bytes);

TPM_RC Serialize_int16_t(const int16_t& value,
                         std::string* buffer);

TPM_RC Parse_int16_t(std::string* buffer,
                     int16_t* value,
                     std::string* value_bytes);

TPM_RC Serialize_uint32_t(const uint32_t& value,
                          std::string* buffer);

TPM_RC Parse_uint32_t(std::string* buffer,
                      uint32_t* value,
                      std::string* value_bytes);

TPM_RC Serialize_int32_t(const int32_t& value,
                         std::string* buffer);

TPM_RC Parse_int32_t(std::string* buffer,
                     int32_t* value,
                     std::string* value_bytes);

TPM_RC Serialize_uint64_t(const uint64_t& value,
                          std::string* buffer);

TPM_RC Parse_uint64_t(std::string* buffer,
                      uint64_t* value,
                      std::string* value_bytes);

TPM_RC Serialize_int64_t(const int64_t& value,
                         std::string* buffer);

TPM_RC Parse_int64_t(std::string* buffer,
                     int64_t* value,
                     std::string* value_bytes);

TPM_RC Serialize_UINT8(const UINT8& value, std::string* buffer);

TPM_RC Parse_UINT8(std::string* buffer,
                   UINT8* value,
                   std::string* value_bytes);

TPM_RC Serialize_BYTE(const BYTE& value, std::string* buffer);

TPM_RC Parse_BYTE(std::string* buffer,
                  BYTE* value,
                  std::string* value_bytes);

TPM_RC Serialize_INT8(const INT8& value, std::string* buffer);

TPM_RC Parse_INT8(std::string* buffer,
                  INT8* value,
                  std::string* value_bytes);

TPM_RC Serialize_BOOL(const BOOL& value, std::string* buffer);

TPM_RC Parse_BOOL(std::string* buffer,
                  BOOL* value,
                  std::string* value_bytes);

TPM_RC Serialize_UINT16(const UINT16& value, std::string* buffer);

TPM_RC Parse_UINT16(std::string* buffer,
                    UINT16* value,
                    std::string* value_bytes);

TPM_RC Serialize_INT16(const INT16& value, std::string* buffer);

TPM_RC Parse_INT16(std::string* buffer,
                   INT16* value,
                   std::string* value_bytes);

TPM_RC Serialize_UINT32(const UINT32& value, std::string* buffer);

TPM_RC Parse_UINT32(std::string* buffer,
                    UINT32* value,
                    std::string* value_bytes);

TPM_RC Serialize_INT32(const INT32& value, std::string* buffer);

TPM_RC Parse_INT32(std::string* buffer,
                   INT32* value,
                   std::string* value_bytes);

TPM_RC Serialize_UINT64(const UINT64& value, std::string* buffer);

TPM_RC Parse_UINT64(std::string* buffer,
                    UINT64* value,
                    std::string* value_bytes);

TPM_RC Serialize_INT64(const INT64& value, std::string* buffer);

TPM_RC Parse_INT64(std::string* buffer,
                   INT64* value,
                   std::string* value_bytes);

TPM_RC Serialize_TPM_ALGORITHM_ID(const TPM_ALGORITHM_ID& value,
                                  std::string* buffer);

TPM_RC Parse_TPM_ALGORITHM_ID(std::string* buffer,
                              TPM_ALGORITHM_ID* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPM_MODIFIER_INDICATOR(
    const TPM_MODIFIER_INDICATOR& value, std::string* buffer);

TPM_RC Parse_TPM_MODIFIER_INDICATOR(std::string* buffer,
                                    TPM_MODIFIER_INDICATOR* value,
                                    std::string* value_bytes);

TPM_RC Serialize_TPM_AUTHORIZATION_SIZE(
    const TPM_AUTHORIZATION_SIZE& value, std::string* buffer);

TPM_RC Parse_TPM_AUTHORIZATION_SIZE(std::string* buffer,
                                    TPM_AUTHORIZATION_SIZE* value,
                                    std::string* value_bytes);

TPM_RC Serialize_TPM_PARAMETER_SIZE(
    const TPM_PARAMETER_SIZE& value, std::string* buffer);

TPM_RC Parse_TPM_PARAMETER_SIZE(std::string* buffer,
                                TPM_PARAMETER_SIZE* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPM_KEY_SIZE(const TPM_KEY_SIZE& value,
                              std::string* buffer);

TPM_RC Parse_TPM_KEY_SIZE(std::string* buffer,
                          TPM_KEY_SIZE* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPM_KEY_BITS(const TPM_KEY_BITS& value,
                              std::string* buffer);

TPM_RC Parse_TPM_KEY_BITS(std::string* buffer,
                          TPM_KEY_BITS* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPM_HANDLE(const TPM_HANDLE& value,
                            std::string* buffer);

TPM_RC Parse_TPM_HANDLE(std::string* buffer,
                        TPM_HANDLE* value,
                        std::string* value_bytes);

TPM_RC Serialize_TPM2B_NONCE(const TPM2B_NONCE& value,
                             std::string* buffer);

TPM_RC Parse_TPM2B_NONCE(std::string* buffer,
                         TPM2B_NONCE* value,
                         std::string* value_bytes);

TPM_RC Serialize_TPM2B_AUTH(const TPM2B_AUTH& value,
                            std::string* buffer);

TPM_RC Parse_TPM2B_AUTH(std::string* buffer,
                        TPM2B_AUTH* value,
                        std::string* value_bytes);

TPM_RC Serialize_TPM2B_OPERAND(const TPM2B_OPERAND& value,
                               std::string* buffer);

TPM_RC Parse_TPM2B_OPERAND(std::string* buffer,
                           TPM2B_OPERAND* value,
                           std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_HMAC(const TPMS_SCHEME_HMAC& value,
                                  std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_HMAC(std::string* buffer,
                              TPMS_SCHEME_HMAC* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_RSASSA(
    const TPMS_SCHEME_RSASSA& value, std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_RSASSA(std::string* buffer,
                                TPMS_SCHEME_RSASSA* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_RSAPSS(
    const TPMS_SCHEME_RSAPSS& value, std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_RSAPSS(std::string* buffer,
                                TPMS_SCHEME_RSAPSS* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_ECDSA(const TPMS_SCHEME_ECDSA& value,
                                   std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_ECDSA(std::string* buffer,
                               TPMS_SCHEME_ECDSA* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_SM2(const TPMS_SCHEME_SM2& value,
                                 std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_SM2(std::string* buffer,
                             TPMS_SCHEME_SM2* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_ECSCHNORR(
    const TPMS_SCHEME_ECSCHNORR& value, std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_ECSCHNORR(std::string* buffer,
                                   TPMS_SCHEME_ECSCHNORR* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPMI_YES_NO(const TPMI_YES_NO& value,
                             std::string* buffer);

TPM_RC Parse_TPMI_YES_NO(std::string* buffer,
                         TPMI_YES_NO* value,
                         std::string* value_bytes);

TPM_RC Serialize_TPMI_DH_OBJECT(const TPMI_DH_OBJECT& value,
                                std::string* buffer);

TPM_RC Parse_TPMI_DH_OBJECT(std::string* buffer,
                            TPMI_DH_OBJECT* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMI_DH_PERSISTENT(
    const TPMI_DH_PERSISTENT& value, std::string* buffer);

TPM_RC Parse_TPMI_DH_PERSISTENT(std::string* buffer,
                                TPMI_DH_PERSISTENT* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPMI_DH_ENTITY(const TPMI_DH_ENTITY& value,
                                std::string* buffer);

TPM_RC Parse_TPMI_DH_ENTITY(std::string* buffer,
                            TPMI_DH_ENTITY* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMI_DH_PCR(const TPMI_DH_PCR& value,
                             std::string* buffer);

TPM_RC Parse_TPMI_DH_PCR(std::string* buffer,
                         TPMI_DH_PCR* value,
                         std::string* value_bytes);

TPM_RC Serialize_TPMI_SH_AUTH_SESSION(
    const TPMI_SH_AUTH_SESSION& value, std::string* buffer);

TPM_RC Parse_TPMI_SH_AUTH_SESSION(std::string* buffer,
                                  TPMI_SH_AUTH_SESSION* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPMI_SH_HMAC(const TPMI_SH_HMAC& value,
                              std::string* buffer);

TPM_RC Parse_TPMI_SH_HMAC(std::string* buffer,
                          TPMI_SH_HMAC* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPMI_SH_POLICY(const TPMI_SH_POLICY& value,
                                std::string* buffer);

TPM_RC Parse_TPMI_SH_POLICY(std::string* buffer,
                            TPMI_SH_POLICY* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMI_DH_CONTEXT(const TPMI_DH_CONTEXT& value,
                                 std::string* buffer);

TPM_RC Parse_TPMI_DH_CONTEXT(std::string* buffer,
                             TPMI_DH_CONTEXT* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMI_RH_HIERARCHY(const TPMI_RH_HIERARCHY& value,
                                   std::string* buffer);

TPM_RC Parse_TPMI_RH_HIERARCHY(std::string* buffer,
                               TPMI_RH_HIERARCHY* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMI_RH_ENABLES(const TPMI_RH_ENABLES& value,
                                 std::string* buffer);

TPM_RC Parse_TPMI_RH_ENABLES(std::string* buffer,
                             TPMI_RH_ENABLES* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMI_RH_HIERARCHY_AUTH(
    const TPMI_RH_HIERARCHY_AUTH& value, std::string* buffer);

TPM_RC Parse_TPMI_RH_HIERARCHY_AUTH(std::string* buffer,
                                    TPMI_RH_HIERARCHY_AUTH* value,
                                    std::string* value_bytes);

TPM_RC Serialize_TPMI_RH_PLATFORM(const TPMI_RH_PLATFORM& value,
                                  std::string* buffer);

TPM_RC Parse_TPMI_RH_PLATFORM(std::string* buffer,
                              TPMI_RH_PLATFORM* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMI_RH_OWNER(const TPMI_RH_OWNER& value,
                               std::string* buffer);

TPM_RC Parse_TPMI_RH_OWNER(std::string* buffer,
                           TPMI_RH_OWNER* value,
                           std::string* value_bytes);

TPM_RC Serialize_TPMI_RH_ENDORSEMENT(
    const TPMI_RH_ENDORSEMENT& value, std::string* buffer);

TPM_RC Parse_TPMI_RH_ENDORSEMENT(std::string* buffer,
                                 TPMI_RH_ENDORSEMENT* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMI_RH_PROVISION(const TPMI_RH_PROVISION& value,
                                   std::string* buffer);

TPM_RC Parse_TPMI_RH_PROVISION(std::string* buffer,
                               TPMI_RH_PROVISION* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMI_RH_CLEAR(const TPMI_RH_CLEAR& value,
                               std::string* buffer);

TPM_RC Parse_TPMI_RH_CLEAR(std::string* buffer,
                           TPMI_RH_CLEAR* value,
                           std::string* value_bytes);

TPM_RC Serialize_TPMI_RH_NV_AUTH(const TPMI_RH_NV_AUTH& value,
                                 std::string* buffer);

TPM_RC Parse_TPMI_RH_NV_AUTH(std::string* buffer,
                             TPMI_RH_NV_AUTH* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMI_RH_LOCKOUT(const TPMI_RH_LOCKOUT& value,
                                 std::string* buffer);

TPM_RC Parse_TPMI_RH_LOCKOUT(std::string* buffer,
                             TPMI_RH_LOCKOUT* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMI_RH_NV_INDEX(const TPMI_RH_NV_INDEX& value,
                                  std::string* buffer);

TPM_RC Parse_TPMI_RH_NV_INDEX(std::string* buffer,
                              TPMI_RH_NV_INDEX* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_HASH(const TPMI_ALG_HASH& value,
                               std::string* buffer);

TPM_RC Parse_TPMI_ALG_HASH(std::string* buffer,
                           TPMI_ALG_HASH* value,
                           std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_ASYM(const TPMI_ALG_ASYM& value,
                               std::string* buffer);

TPM_RC Parse_TPMI_ALG_ASYM(std::string* buffer,
                           TPMI_ALG_ASYM* value,
                           std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_SYM(const TPMI_ALG_SYM& value,
                              std::string* buffer);

TPM_RC Parse_TPMI_ALG_SYM(std::string* buffer,
                          TPMI_ALG_SYM* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_SYM_OBJECT(
    const TPMI_ALG_SYM_OBJECT& value, std::string* buffer);

TPM_RC Parse_TPMI_ALG_SYM_OBJECT(std::string* buffer,
                                 TPMI_ALG_SYM_OBJECT* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_SYM_MODE(const TPMI_ALG_SYM_MODE& value,
                                   std::string* buffer);

TPM_RC Parse_TPMI_ALG_SYM_MODE(std::string* buffer,
                               TPMI_ALG_SYM_MODE* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_KDF(const TPMI_ALG_KDF& value,
                              std::string* buffer);

TPM_RC Parse_TPMI_ALG_KDF(std::string* buffer,
                          TPMI_ALG_KDF* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_SIG_SCHEME(
    const TPMI_ALG_SIG_SCHEME& value, std::string* buffer);

TPM_RC Parse_TPMI_ALG_SIG_SCHEME(std::string* buffer,
                                 TPMI_ALG_SIG_SCHEME* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMI_ECC_KEY_EXCHANGE(
    const TPMI_ECC_KEY_EXCHANGE& value, std::string* buffer);

TPM_RC Parse_TPMI_ECC_KEY_EXCHANGE(std::string* buffer,
                                   TPMI_ECC_KEY_EXCHANGE* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPMI_ST_COMMAND_TAG(
    const TPMI_ST_COMMAND_TAG& value, std::string* buffer);

TPM_RC Parse_TPMI_ST_COMMAND_TAG(std::string* buffer,
                                 TPMI_ST_COMMAND_TAG* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMI_ST_ATTEST(const TPMI_ST_ATTEST& value,
                                std::string* buffer);

TPM_RC Parse_TPMI_ST_ATTEST(std::string* buffer,
                            TPMI_ST_ATTEST* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMI_AES_KEY_BITS(const TPMI_AES_KEY_BITS& value,
                                   std::string* buffer);

TPM_RC Parse_TPMI_AES_KEY_BITS(std::string* buffer,
                               TPMI_AES_KEY_BITS* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMI_SM4_KEY_BITS(const TPMI_SM4_KEY_BITS& value,
                                   std::string* buffer);

TPM_RC Parse_TPMI_SM4_KEY_BITS(std::string* buffer,
                               TPMI_SM4_KEY_BITS* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_KEYEDHASH_SCHEME(
    const TPMI_ALG_KEYEDHASH_SCHEME& value, std::string* buffer);

TPM_RC
Parse_TPMI_ALG_KEYEDHASH_SCHEME(std::string* buffer,
                                TPMI_ALG_KEYEDHASH_SCHEME* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_ASYM_SCHEME(
    const TPMI_ALG_ASYM_SCHEME& value, std::string* buffer);

TPM_RC Parse_TPMI_ALG_ASYM_SCHEME(std::string* buffer,
                                  TPMI_ALG_ASYM_SCHEME* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_RSA_SCHEME(
    const TPMI_ALG_RSA_SCHEME& value, std::string* buffer);

TPM_RC Parse_TPMI_ALG_RSA_SCHEME(std::string* buffer,
                                 TPMI_ALG_RSA_SCHEME* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_RSA_DECRYPT(
    const TPMI_ALG_RSA_DECRYPT& value, std::string* buffer);

TPM_RC Parse_TPMI_ALG_RSA_DECRYPT(std::string* buffer,
                                  TPMI_ALG_RSA_DECRYPT* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPMI_RSA_KEY_BITS(const TPMI_RSA_KEY_BITS& value,
                                   std::string* buffer);

TPM_RC Parse_TPMI_RSA_KEY_BITS(std::string* buffer,
                               TPMI_RSA_KEY_BITS* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_ECC_SCHEME(
    const TPMI_ALG_ECC_SCHEME& value, std::string* buffer);

TPM_RC Parse_TPMI_ALG_ECC_SCHEME(std::string* buffer,
                                 TPMI_ALG_ECC_SCHEME* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMI_ECC_CURVE(const TPMI_ECC_CURVE& value,
                                std::string* buffer);

TPM_RC Parse_TPMI_ECC_CURVE(std::string* buffer,
                            TPMI_ECC_CURVE* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMI_ALG_PUBLIC(const TPMI_ALG_PUBLIC& value,
                                 std::string* buffer);

TPM_RC Parse_TPMI_ALG_PUBLIC(std::string* buffer,
                             TPMI_ALG_PUBLIC* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMA_ALGORITHM(const TPMA_ALGORITHM& value,
                                std::string* buffer);

TPM_RC Parse_TPMA_ALGORITHM(std::string* buffer,
                            TPMA_ALGORITHM* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMA_OBJECT(const TPMA_OBJECT& value,
                             std::string* buffer);

TPM_RC Parse_TPMA_OBJECT(std::string* buffer,
                         TPMA_OBJECT* value,
                         std::string* value_bytes);

TPM_RC Serialize_TPMA_SESSION(const TPMA_SESSION& value,
                              std::string* buffer);

TPM_RC Parse_TPMA_SESSION(std::string* buffer,
                          TPMA_SESSION* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPMA_LOCALITY(const TPMA_LOCALITY& value,
                               std::string* buffer);

TPM_RC Parse_TPMA_LOCALITY(std::string* buffer,
                           TPMA_LOCALITY* value,
                           std::string* value_bytes);

TPM_RC Serialize_TPMA_PERMANENT(const TPMA_PERMANENT& value,
                                std::string* buffer);

TPM_RC Parse_TPMA_PERMANENT(std::string* buffer,
                            TPMA_PERMANENT* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMA_STARTUP_CLEAR(
    const TPMA_STARTUP_CLEAR& value, std::string* buffer);

TPM_RC Parse_TPMA_STARTUP_CLEAR(std::string* buffer,
                                TPMA_STARTUP_CLEAR* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPMA_MEMORY(const TPMA_MEMORY& value,
                             std::string* buffer);

TPM_RC Parse_TPMA_MEMORY(std::string* buffer,
                         TPMA_MEMORY* value,
                         std::string* value_bytes);

TPM_RC Serialize_TPMA_CC(const TPMA_CC& value,
                         std::string* buffer);

TPM_RC Parse_TPMA_CC(std::string* buffer,
                                   TPMA_CC* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPM_NV_INDEX(const TPM_NV_INDEX& value,
                              std::string* buffer);

TPM_RC Parse_TPM_NV_INDEX(std::string* buffer,
                          TPM_NV_INDEX* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPMA_NV(const TPMA_NV& value,
                         std::string* buffer);

TPM_RC Parse_TPMA_NV(std::string* buffer,
                     TPMA_NV* value,
                     std::string* value_bytes);

TPM_RC Serialize_TPM_SPEC(const TPM_SPEC& value,
                          std::string* buffer);

TPM_RC Parse_TPM_SPEC(std::string* buffer,
                      TPM_SPEC* value,
                      std::string* value_bytes);

TPM_RC Serialize_TPM_GENERATED(const TPM_GENERATED& value,
                               std::string* buffer);

TPM_RC Parse_TPM_GENERATED(std::string* buffer,
                           TPM_GENERATED* value,
                           std::string* value_bytes);

TPM_RC Serialize_TPM_ALG_ID(const TPM_ALG_ID& value,
                            std::string* buffer);

TPM_RC Parse_TPM_ALG_ID(std::string* buffer,
                        TPM_ALG_ID* value,
                        std::string* value_bytes);

TPM_RC Serialize_TPM_ECC_CURVE(const TPM_ECC_CURVE& value,
                               std::string* buffer);

TPM_RC Parse_TPM_ECC_CURVE(std::string* buffer,
                           TPM_ECC_CURVE* value,
                           std::string* value_bytes);

TPM_RC Serialize_TPM_CC(const TPM_CC& value, std::string* buffer);

TPM_RC Parse_TPM_CC(std::string* buffer,
                    TPM_CC* value,
                    std::string* value_bytes);

TPM_RC Serialize_TPM_RC(const TPM_RC& value, std::string* buffer);

TPM_RC Parse_TPM_RC(std::string* buffer,
                    TPM_RC* value,
                    std::string* value_bytes);

TPM_RC Serialize_TPM_CLOCK_ADJUST(const TPM_CLOCK_ADJUST& value,
                                  std::string* buffer);

TPM_RC Parse_TPM_CLOCK_ADJUST(std::string* buffer,
                              TPM_CLOCK_ADJUST* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPM_EO(const TPM_EO& value, std::string* buffer);

TPM_RC Parse_TPM_EO(std::string* buffer,
                                  TPM_EO* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPM_ST(const TPM_ST& value, std::string* buffer);

TPM_RC Parse_TPM_ST(std::string* buffer,
                                  TPM_ST* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPM_SU(const TPM_SU& value, std::string* buffer);

TPM_RC Parse_TPM_SU(std::string* buffer,
                                  TPM_SU* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPM_SE(const TPM_SE& value, std::string* buffer);

TPM_RC Parse_TPM_SE(std::string* buffer,
                                  TPM_SE* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPM_CAP(const TPM_CAP& value,
                         std::string* buffer);

TPM_RC Parse_TPM_CAP(std::string* buffer,
                     TPM_CAP* value,
                     std::string* value_bytes);

TPM_RC Serialize_TPM_PT(const TPM_PT& value, std::string* buffer);

TPM_RC Parse_TPM_PT(std::string* buffer,
                                  TPM_PT* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPM_PT_PCR(const TPM_PT_PCR& value,
                            std::string* buffer);

TPM_RC Parse_TPM_PT_PCR(std::string* buffer,
                        TPM_PT_PCR* value,
                        std::string* value_bytes);

TPM_RC Serialize_TPM_PS(const TPM_PS& value, std::string* buffer);

TPM_RC Parse_TPM_PS(std::string* buffer,
                                  TPM_PS* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPM_HT(const TPM_HT& value, std::string* buffer);

TPM_RC Parse_TPM_HT(std::string* buffer,
                                  TPM_HT* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPM_RH(const TPM_RH& value, std::string* buffer);

TPM_RC Parse_TPM_RH(std::string* buffer,
                                  TPM_RH* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPM_HC(const TPM_HC& value, std::string* buffer);

TPM_RC Parse_TPM_HC(std::string* buffer,
                                  TPM_HC* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPMS_ALGORITHM_DESCRIPTION(
    const TPMS_ALGORITHM_DESCRIPTION& value, std::string* buffer);

TPM_RC
Parse_TPMS_ALGORITHM_DESCRIPTION(std::string* buffer,
                                 TPMS_ALGORITHM_DESCRIPTION* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMT_HA(const TPMT_HA& value,
                         std::string* buffer);

TPM_RC Parse_TPMT_HA(std::string* buffer,
                     TPMT_HA* value,
                     std::string* value_bytes);

TPM_RC Serialize_TPM2B_DIGEST(const TPM2B_DIGEST& value,
                              std::string* buffer);

TPM_RC Parse_TPM2B_DIGEST(std::string* buffer,
                          TPM2B_DIGEST* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPM2B_DATA(const TPM2B_DATA& value,
                            std::string* buffer);

TPM_RC Parse_TPM2B_DATA(std::string* buffer,
                        TPM2B_DATA* value,
                        std::string* value_bytes);

TPM_RC Serialize_TPM2B_EVENT(const TPM2B_EVENT& value,
                             std::string* buffer);

TPM_RC Parse_TPM2B_EVENT(std::string* buffer,
                         TPM2B_EVENT* value,
                         std::string* value_bytes);

TPM_RC Serialize_TPM2B_MAX_BUFFER(const TPM2B_MAX_BUFFER& value,
                                  std::string* buffer);

TPM_RC Parse_TPM2B_MAX_BUFFER(std::string* buffer,
                              TPM2B_MAX_BUFFER* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPM2B_MAX_NV_BUFFER(
    const TPM2B_MAX_NV_BUFFER& value, std::string* buffer);

TPM_RC Parse_TPM2B_MAX_NV_BUFFER(std::string* buffer,
                                 TPM2B_MAX_NV_BUFFER* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPM2B_TIMEOUT(const TPM2B_TIMEOUT& value,
                               std::string* buffer);

TPM_RC Parse_TPM2B_TIMEOUT(std::string* buffer,
                           TPM2B_TIMEOUT* value,
                           std::string* value_bytes);

TPM_RC Serialize_TPM2B_IV(const TPM2B_IV& value,
                          std::string* buffer);

TPM_RC Parse_TPM2B_IV(std::string* buffer,
                      TPM2B_IV* value,
                      std::string* value_bytes);

TPM_RC Serialize_TPM2B_NAME(const TPM2B_NAME& value,
                            std::string* buffer);

TPM_RC Parse_TPM2B_NAME(std::string* buffer,
                        TPM2B_NAME* value,
                        std::string* value_bytes);

TPM_RC Serialize_TPMS_PCR_SELECT(const TPMS_PCR_SELECT& value,
                                 std::string* buffer);

TPM_RC Parse_TPMS_PCR_SELECT(std::string* buffer,
                             TPMS_PCR_SELECT* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMS_PCR_SELECTION(
    const TPMS_PCR_SELECTION& value, std::string* buffer);

TPM_RC Parse_TPMS_PCR_SELECTION(std::string* buffer,
                                TPMS_PCR_SELECTION* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPMT_TK_CREATION(const TPMT_TK_CREATION& value,
                                  std::string* buffer);

TPM_RC Parse_TPMT_TK_CREATION(std::string* buffer,
                              TPMT_TK_CREATION* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMT_TK_VERIFIED(const TPMT_TK_VERIFIED& value,
                                  std::string* buffer);

TPM_RC Parse_TPMT_TK_VERIFIED(std::string* buffer,
                              TPMT_TK_VERIFIED* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMT_TK_AUTH(const TPMT_TK_AUTH& value,
                              std::string* buffer);

TPM_RC Parse_TPMT_TK_AUTH(std::string* buffer,
                          TPMT_TK_AUTH* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPMT_TK_HASHCHECK(const TPMT_TK_HASHCHECK& value,
                                   std::string* buffer);

TPM_RC Parse_TPMT_TK_HASHCHECK(std::string* buffer,
                               TPMT_TK_HASHCHECK* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMS_ALG_PROPERTY(const TPMS_ALG_PROPERTY& value,
                                   std::string* buffer);

TPM_RC Parse_TPMS_ALG_PROPERTY(std::string* buffer,
                               TPMS_ALG_PROPERTY* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMS_TAGGED_PROPERTY(
    const TPMS_TAGGED_PROPERTY& value, std::string* buffer);

TPM_RC Parse_TPMS_TAGGED_PROPERTY(std::string* buffer,
                                  TPMS_TAGGED_PROPERTY* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPMS_TAGGED_PCR_SELECT(
    const TPMS_TAGGED_PCR_SELECT& value, std::string* buffer);

TPM_RC Parse_TPMS_TAGGED_PCR_SELECT(std::string* buffer,
                                    TPMS_TAGGED_PCR_SELECT* value,
                                    std::string* value_bytes);

TPM_RC Serialize_TPML_CC(const TPML_CC& value,
                         std::string* buffer);

TPM_RC Parse_TPML_CC(std::string* buffer,
                     TPML_CC* value,
                     std::string* value_bytes);

TPM_RC Serialize_TPML_CCA(const TPML_CCA& value,
                          std::string* buffer);

TPM_RC Parse_TPML_CCA(std::string* buffer,
                      TPML_CCA* value,
                      std::string* value_bytes);

TPM_RC Serialize_TPML_ALG(const TPML_ALG& value,
                          std::string* buffer);

TPM_RC Parse_TPML_ALG(std::string* buffer,
                      TPML_ALG* value,
                      std::string* value_bytes);

TPM_RC Serialize_TPML_HANDLE(const TPML_HANDLE& value,
                             std::string* buffer);

TPM_RC Parse_TPML_HANDLE(std::string* buffer,
                         TPML_HANDLE* value,
                         std::string* value_bytes);

TPM_RC Serialize_TPML_DIGEST(const TPML_DIGEST& value,
                             std::string* buffer);

TPM_RC Parse_TPML_DIGEST(std::string* buffer,
                         TPML_DIGEST* value,
                         std::string* value_bytes);

TPM_RC Serialize_TPML_DIGEST_VALUES(
    const TPML_DIGEST_VALUES& value, std::string* buffer);

TPM_RC Parse_TPML_DIGEST_VALUES(std::string* buffer,
                                TPML_DIGEST_VALUES* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPM2B_DIGEST_VALUES(
    const TPM2B_DIGEST_VALUES& value, std::string* buffer);

TPM_RC Parse_TPM2B_DIGEST_VALUES(std::string* buffer,
                                 TPM2B_DIGEST_VALUES* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPML_PCR_SELECTION(
    const TPML_PCR_SELECTION& value, std::string* buffer);

TPM_RC Parse_TPML_PCR_SELECTION(std::string* buffer,
                                TPML_PCR_SELECTION* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPML_ALG_PROPERTY(const TPML_ALG_PROPERTY& value,
                                   std::string* buffer);

TPM_RC Parse_TPML_ALG_PROPERTY(std::string* buffer,
                               TPML_ALG_PROPERTY* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPML_TAGGED_TPM_PROPERTY(
    const TPML_TAGGED_TPM_PROPERTY& value, std::string* buffer);

TPM_RC
Parse_TPML_TAGGED_TPM_PROPERTY(std::string* buffer,
                               TPML_TAGGED_TPM_PROPERTY* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPML_TAGGED_PCR_PROPERTY(
    const TPML_TAGGED_PCR_PROPERTY& value, std::string* buffer);

TPM_RC
Parse_TPML_TAGGED_PCR_PROPERTY(std::string* buffer,
                               TPML_TAGGED_PCR_PROPERTY* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPML_ECC_CURVE(const TPML_ECC_CURVE& value,
                                std::string* buffer);

TPM_RC Parse_TPML_ECC_CURVE(std::string* buffer,
                            TPML_ECC_CURVE* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMS_CAPABILITY_DATA(
    const TPMS_CAPABILITY_DATA& value, std::string* buffer);

TPM_RC Parse_TPMS_CAPABILITY_DATA(std::string* buffer,
                                  TPMS_CAPABILITY_DATA* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPMS_CLOCK_INFO(const TPMS_CLOCK_INFO& value,
                                 std::string* buffer);

TPM_RC Parse_TPMS_CLOCK_INFO(std::string* buffer,
                             TPMS_CLOCK_INFO* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMS_TIME_INFO(const TPMS_TIME_INFO& value,
                                std::string* buffer);

TPM_RC Parse_TPMS_TIME_INFO(std::string* buffer,
                            TPMS_TIME_INFO* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMS_TIME_ATTEST_INFO(
    const TPMS_TIME_ATTEST_INFO& value, std::string* buffer);

TPM_RC Parse_TPMS_TIME_ATTEST_INFO(std::string* buffer,
                                   TPMS_TIME_ATTEST_INFO* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPMS_CERTIFY_INFO(const TPMS_CERTIFY_INFO& value,
                                   std::string* buffer);

TPM_RC Parse_TPMS_CERTIFY_INFO(std::string* buffer,
                               TPMS_CERTIFY_INFO* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMS_QUOTE_INFO(const TPMS_QUOTE_INFO& value,
                                 std::string* buffer);

TPM_RC Parse_TPMS_QUOTE_INFO(std::string* buffer,
                             TPMS_QUOTE_INFO* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMS_COMMAND_AUDIT_INFO(
    const TPMS_COMMAND_AUDIT_INFO& value, std::string* buffer);

TPM_RC
Parse_TPMS_COMMAND_AUDIT_INFO(std::string* buffer,
                              TPMS_COMMAND_AUDIT_INFO* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMS_SESSION_AUDIT_INFO(
    const TPMS_SESSION_AUDIT_INFO& value, std::string* buffer);

TPM_RC
Parse_TPMS_SESSION_AUDIT_INFO(std::string* buffer,
                              TPMS_SESSION_AUDIT_INFO* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMS_CREATION_INFO(
    const TPMS_CREATION_INFO& value, std::string* buffer);

TPM_RC Parse_TPMS_CREATION_INFO(std::string* buffer,
                                TPMS_CREATION_INFO* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPMS_NV_CERTIFY_INFO(
    const TPMS_NV_CERTIFY_INFO& value, std::string* buffer);

TPM_RC Parse_TPMS_NV_CERTIFY_INFO(std::string* buffer,
                                  TPMS_NV_CERTIFY_INFO* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPMS_ATTEST(const TPMS_ATTEST& value,
                             std::string* buffer);

TPM_RC Parse_TPMS_ATTEST(std::string* buffer,
                         TPMS_ATTEST* value,
                         std::string* value_bytes);

TPM_RC Serialize_TPM2B_ATTEST(const TPM2B_ATTEST& value,
                              std::string* buffer);

TPM_RC Parse_TPM2B_ATTEST(std::string* buffer,
                          TPM2B_ATTEST* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPMS_AUTH_COMMAND(const TPMS_AUTH_COMMAND& value,
                                   std::string* buffer);

TPM_RC Parse_TPMS_AUTH_COMMAND(std::string* buffer,
                               TPMS_AUTH_COMMAND* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMS_AUTH_RESPONSE(
    const TPMS_AUTH_RESPONSE& value, std::string* buffer);

TPM_RC Parse_TPMS_AUTH_RESPONSE(std::string* buffer,
                                TPMS_AUTH_RESPONSE* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPMT_SYM_DEF(const TPMT_SYM_DEF& value,
                              std::string* buffer);

TPM_RC Parse_TPMT_SYM_DEF(std::string* buffer,
                          TPMT_SYM_DEF* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPMT_SYM_DEF_OBJECT(
    const TPMT_SYM_DEF_OBJECT& value, std::string* buffer);

TPM_RC Parse_TPMT_SYM_DEF_OBJECT(std::string* buffer,
                                 TPMT_SYM_DEF_OBJECT* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPM2B_SYM_KEY(const TPM2B_SYM_KEY& value,
                               std::string* buffer);

TPM_RC Parse_TPM2B_SYM_KEY(std::string* buffer,
                           TPM2B_SYM_KEY* value,
                           std::string* value_bytes);

TPM_RC Serialize_TPMS_SYMCIPHER_PARMS(
    const TPMS_SYMCIPHER_PARMS& value, std::string* buffer);

TPM_RC Parse_TPMS_SYMCIPHER_PARMS(std::string* buffer,
                                  TPMS_SYMCIPHER_PARMS* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPM2B_SENSITIVE_DATA(
    const TPM2B_SENSITIVE_DATA& value, std::string* buffer);

TPM_RC Parse_TPM2B_SENSITIVE_DATA(std::string* buffer,
                                  TPM2B_SENSITIVE_DATA* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPMS_SENSITIVE_CREATE(
    const TPMS_SENSITIVE_CREATE& value, std::string* buffer);

TPM_RC Parse_TPMS_SENSITIVE_CREATE(std::string* buffer,
                                   TPMS_SENSITIVE_CREATE* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPM2B_SENSITIVE_CREATE(
    const TPM2B_SENSITIVE_CREATE& value, std::string* buffer);

TPM_RC Parse_TPM2B_SENSITIVE_CREATE(std::string* buffer,
                                    TPM2B_SENSITIVE_CREATE* value,
                                    std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_SIGHASH(
    const TPMS_SCHEME_SIGHASH& value, std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_SIGHASH(std::string* buffer,
                                 TPMS_SCHEME_SIGHASH* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_XOR(const TPMS_SCHEME_XOR& value,
                                 std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_XOR(std::string* buffer,
                             TPMS_SCHEME_XOR* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMT_KEYEDHASH_SCHEME(
    const TPMT_KEYEDHASH_SCHEME& value, std::string* buffer);

TPM_RC Parse_TPMT_KEYEDHASH_SCHEME(std::string* buffer,
                                   TPMT_KEYEDHASH_SCHEME* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_ECDAA(const TPMS_SCHEME_ECDAA& value,
                                   std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_ECDAA(std::string* buffer,
                               TPMS_SCHEME_ECDAA* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMT_SIG_SCHEME(const TPMT_SIG_SCHEME& value,
                                 std::string* buffer);

TPM_RC Parse_TPMT_SIG_SCHEME(std::string* buffer,
                             TPMT_SIG_SCHEME* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_OAEP(const TPMS_SCHEME_OAEP& value,
                                  std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_OAEP(std::string* buffer,
                              TPMS_SCHEME_OAEP* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_ECDH(const TPMS_SCHEME_ECDH& value,
                                  std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_ECDH(std::string* buffer,
                              TPMS_SCHEME_ECDH* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_MGF1(const TPMS_SCHEME_MGF1& value,
                                  std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_MGF1(std::string* buffer,
                              TPMS_SCHEME_MGF1* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_KDF1_SP800_56a(
    const TPMS_SCHEME_KDF1_SP800_56a& value, std::string* buffer);

TPM_RC
Parse_TPMS_SCHEME_KDF1_SP800_56a(std::string* buffer,
                                 TPMS_SCHEME_KDF1_SP800_56a* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_KDF2(const TPMS_SCHEME_KDF2& value,
                                  std::string* buffer);

TPM_RC Parse_TPMS_SCHEME_KDF2(std::string* buffer,
                              TPMS_SCHEME_KDF2* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_KDF1_SP800_108(
    const TPMS_SCHEME_KDF1_SP800_108& value, std::string* buffer);

TPM_RC
Parse_TPMS_SCHEME_KDF1_SP800_108(std::string* buffer,
                                 TPMS_SCHEME_KDF1_SP800_108* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMT_KDF_SCHEME(const TPMT_KDF_SCHEME& value,
                                 std::string* buffer);

TPM_RC Parse_TPMT_KDF_SCHEME(std::string* buffer,
                             TPMT_KDF_SCHEME* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMT_ASYM_SCHEME(const TPMT_ASYM_SCHEME& value,
                                  std::string* buffer);

TPM_RC Parse_TPMT_ASYM_SCHEME(std::string* buffer,
                              TPMT_ASYM_SCHEME* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMT_RSA_SCHEME(const TPMT_RSA_SCHEME& value,
                                 std::string* buffer);

TPM_RC Parse_TPMT_RSA_SCHEME(std::string* buffer,
                             TPMT_RSA_SCHEME* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMT_RSA_DECRYPT(const TPMT_RSA_DECRYPT& value,
                                  std::string* buffer);

TPM_RC Parse_TPMT_RSA_DECRYPT(std::string* buffer,
                              TPMT_RSA_DECRYPT* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPM2B_PUBLIC_KEY_RSA(
    const TPM2B_PUBLIC_KEY_RSA& value, std::string* buffer);

TPM_RC Parse_TPM2B_PUBLIC_KEY_RSA(std::string* buffer,
                                  TPM2B_PUBLIC_KEY_RSA* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPM2B_PRIVATE_KEY_RSA(
    const TPM2B_PRIVATE_KEY_RSA& value, std::string* buffer);

TPM_RC Parse_TPM2B_PRIVATE_KEY_RSA(std::string* buffer,
                                   TPM2B_PRIVATE_KEY_RSA* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPM2B_ECC_PARAMETER(
    const TPM2B_ECC_PARAMETER& value, std::string* buffer);

TPM_RC Parse_TPM2B_ECC_PARAMETER(std::string* buffer,
                                 TPM2B_ECC_PARAMETER* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMS_ECC_POINT(const TPMS_ECC_POINT& value,
                                std::string* buffer);

TPM_RC Parse_TPMS_ECC_POINT(std::string* buffer,
                            TPMS_ECC_POINT* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPM2B_ECC_POINT(const TPM2B_ECC_POINT& value,
                                 std::string* buffer);

TPM_RC Parse_TPM2B_ECC_POINT(std::string* buffer,
                             TPM2B_ECC_POINT* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMT_ECC_SCHEME(const TPMT_ECC_SCHEME& value,
                                 std::string* buffer);

TPM_RC Parse_TPMT_ECC_SCHEME(std::string* buffer,
                             TPMT_ECC_SCHEME* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMS_ALGORITHM_DETAIL_ECC(
    const TPMS_ALGORITHM_DETAIL_ECC& value, std::string* buffer);

TPM_RC
Parse_TPMS_ALGORITHM_DETAIL_ECC(std::string* buffer,
                                TPMS_ALGORITHM_DETAIL_ECC* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPMS_SIGNATURE_RSASSA(
    const TPMS_SIGNATURE_RSASSA& value, std::string* buffer);

TPM_RC Parse_TPMS_SIGNATURE_RSASSA(std::string* buffer,
                                   TPMS_SIGNATURE_RSASSA* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPMS_SIGNATURE_RSAPSS(
    const TPMS_SIGNATURE_RSAPSS& value, std::string* buffer);

TPM_RC Parse_TPMS_SIGNATURE_RSAPSS(std::string* buffer,
                                   TPMS_SIGNATURE_RSAPSS* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPMS_SIGNATURE_ECDSA(
    const TPMS_SIGNATURE_ECDSA& value, std::string* buffer);

TPM_RC Parse_TPMS_SIGNATURE_ECDSA(std::string* buffer,
                                  TPMS_SIGNATURE_ECDSA* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPMT_SIGNATURE(const TPMT_SIGNATURE& value,
                                std::string* buffer);

TPM_RC Parse_TPMT_SIGNATURE(std::string* buffer,
                            TPMT_SIGNATURE* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPM2B_ENCRYPTED_SECRET(
    const TPM2B_ENCRYPTED_SECRET& value, std::string* buffer);

TPM_RC Parse_TPM2B_ENCRYPTED_SECRET(std::string* buffer,
                                    TPM2B_ENCRYPTED_SECRET* value,
                                    std::string* value_bytes);

TPM_RC Serialize_TPMS_KEYEDHASH_PARMS(
    const TPMS_KEYEDHASH_PARMS& value, std::string* buffer);

TPM_RC Parse_TPMS_KEYEDHASH_PARMS(std::string* buffer,
                                  TPMS_KEYEDHASH_PARMS* value,
                                  std::string* value_bytes);

TPM_RC Serialize_TPMS_ASYM_PARMS(const TPMS_ASYM_PARMS& value,
                                 std::string* buffer);

TPM_RC Parse_TPMS_ASYM_PARMS(std::string* buffer,
                             TPMS_ASYM_PARMS* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMS_RSA_PARMS(const TPMS_RSA_PARMS& value,
                                std::string* buffer);

TPM_RC Parse_TPMS_RSA_PARMS(std::string* buffer,
                            TPMS_RSA_PARMS* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMS_ECC_PARMS(const TPMS_ECC_PARMS& value,
                                std::string* buffer);

TPM_RC Parse_TPMS_ECC_PARMS(std::string* buffer,
                            TPMS_ECC_PARMS* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMT_PUBLIC_PARMS(const TPMT_PUBLIC_PARMS& value,
                                   std::string* buffer);

TPM_RC Parse_TPMT_PUBLIC_PARMS(std::string* buffer,
                               TPMT_PUBLIC_PARMS* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMT_PUBLIC(const TPMT_PUBLIC& value,
                             std::string* buffer);

TPM_RC Parse_TPMT_PUBLIC(std::string* buffer,
                         TPMT_PUBLIC* value,
                         std::string* value_bytes);

TPM_RC Serialize_TPM2B_PUBLIC(const TPM2B_PUBLIC& value,
                              std::string* buffer);

TPM_RC Parse_TPM2B_PUBLIC(std::string* buffer,
                          TPM2B_PUBLIC* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPM2B_PRIVATE_VENDOR_SPECIFIC(
    const TPM2B_PRIVATE_VENDOR_SPECIFIC& value, std::string* buffer);

TPM_RC
Parse_TPM2B_PRIVATE_VENDOR_SPECIFIC(std::string* buffer,
                                    TPM2B_PRIVATE_VENDOR_SPECIFIC* value,
                                    std::string* value_bytes);

TPM_RC Serialize_TPMT_SENSITIVE(const TPMT_SENSITIVE& value,
                                std::string* buffer);

TPM_RC Parse_TPMT_SENSITIVE(std::string* buffer,
                            TPMT_SENSITIVE* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPM2B_SENSITIVE(const TPM2B_SENSITIVE& value,
                                 std::string* buffer);

TPM_RC Parse_TPM2B_SENSITIVE(std::string* buffer,
                             TPM2B_SENSITIVE* value,
                             std::string* value_bytes);

TPM_RC Serialize__PRIVATE(const _PRIVATE& value,
                          std::string* buffer);

TPM_RC Parse__PRIVATE(std::string* buffer,
                      _PRIVATE* value,
                      std::string* value_bytes);

TPM_RC Serialize_TPM2B_PRIVATE(const TPM2B_PRIVATE& value,
                               std::string* buffer);

TPM_RC Parse_TPM2B_PRIVATE(std::string* buffer,
                           TPM2B_PRIVATE* value,
                           std::string* value_bytes);

TPM_RC Serialize__ID_OBJECT(const _ID_OBJECT& value,
                            std::string* buffer);

TPM_RC Parse__ID_OBJECT(std::string* buffer,
                        _ID_OBJECT* value,
                        std::string* value_bytes);

TPM_RC Serialize_TPM2B_ID_OBJECT(const TPM2B_ID_OBJECT& value,
                                 std::string* buffer);

TPM_RC Parse_TPM2B_ID_OBJECT(std::string* buffer,
                             TPM2B_ID_OBJECT* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMS_NV_PUBLIC(const TPMS_NV_PUBLIC& value,
                                std::string* buffer);

TPM_RC Parse_TPMS_NV_PUBLIC(std::string* buffer,
                            TPMS_NV_PUBLIC* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPM2B_NV_PUBLIC(const TPM2B_NV_PUBLIC& value,
                                 std::string* buffer);

TPM_RC Parse_TPM2B_NV_PUBLIC(std::string* buffer,
                             TPM2B_NV_PUBLIC* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPM2B_CONTEXT_SENSITIVE(
    const TPM2B_CONTEXT_SENSITIVE& value, std::string* buffer);

TPM_RC
Parse_TPM2B_CONTEXT_SENSITIVE(std::string* buffer,
                              TPM2B_CONTEXT_SENSITIVE* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMS_CONTEXT_DATA(const TPMS_CONTEXT_DATA& value,
                                   std::string* buffer);

TPM_RC Parse_TPMS_CONTEXT_DATA(std::string* buffer,
                               TPMS_CONTEXT_DATA* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPM2B_CONTEXT_DATA(
    const TPM2B_CONTEXT_DATA& value, std::string* buffer);

TPM_RC Parse_TPM2B_CONTEXT_DATA(std::string* buffer,
                                TPM2B_CONTEXT_DATA* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPMS_CONTEXT(const TPMS_CONTEXT& value,
                              std::string* buffer);

TPM_RC Parse_TPMS_CONTEXT(std::string* buffer,
                          TPMS_CONTEXT* value,
                          std::string* value_bytes);

TPM_RC Serialize_TPMS_CREATION_DATA(
    const TPMS_CREATION_DATA& value, std::string* buffer);

TPM_RC Parse_TPMS_CREATION_DATA(std::string* buffer,
                                TPMS_CREATION_DATA* value,
                                std::string* value_bytes);

TPM_RC Serialize_TPM2B_CREATION_DATA(
    const TPM2B_CREATION_DATA& value, std::string* buffer);

TPM_RC Parse_TPM2B_CREATION_DATA(std::string* buffer,
                                 TPM2B_CREATION_DATA* value,
                                 std::string* value_bytes);

TPM_RC Serialize_TPMU_HA(const TPMU_HA& value,
                         std::string* buffer);

TPM_RC Parse_TPMU_HA(std::string* buffer,
                                   TPMU_HA* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPMU_NAME(const TPMU_NAME& value,
                           std::string* buffer);

TPM_RC Parse_TPMU_NAME(std::string* buffer,
                       TPMU_NAME* value,
                       std::string* value_bytes);

TPM_RC Serialize_TPMU_CAPABILITIES(const TPMU_CAPABILITIES& value,
                                   std::string* buffer);

TPM_RC Parse_TPMU_CAPABILITIES(std::string* buffer,
                               TPMU_CAPABILITIES* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMU_ATTEST(const TPMU_ATTEST& value,
                             std::string* buffer);

TPM_RC Parse_TPMU_ATTEST(std::string* buffer,
                         TPMU_ATTEST* value,
                         std::string* value_bytes);

TPM_RC Serialize_TPMU_SYM_KEY_BITS(const TPMU_SYM_KEY_BITS& value,
                                   std::string* buffer);

TPM_RC Parse_TPMU_SYM_KEY_BITS(std::string* buffer,
                               TPMU_SYM_KEY_BITS* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMU_SYM_MODE(const TPMU_SYM_MODE& value,
                               std::string* buffer);

TPM_RC Parse_TPMU_SYM_MODE(std::string* buffer,
                           TPMU_SYM_MODE* value,
                           std::string* value_bytes);

TPM_RC Serialize_TPMU_SCHEME_KEYEDHASH(
    const TPMU_SCHEME_KEYEDHASH& value, std::string* buffer);

TPM_RC Parse_TPMU_SCHEME_KEYEDHASH(std::string* buffer,
                                   TPMU_SCHEME_KEYEDHASH* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPMU_SIG_SCHEME(const TPMU_SIG_SCHEME& value,
                                 std::string* buffer);

TPM_RC Parse_TPMU_SIG_SCHEME(std::string* buffer,
                             TPMU_SIG_SCHEME* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMU_KDF_SCHEME(const TPMU_KDF_SCHEME& value,
                                 std::string* buffer);

TPM_RC Parse_TPMU_KDF_SCHEME(std::string* buffer,
                             TPMU_KDF_SCHEME* value,
                             std::string* value_bytes);

TPM_RC Serialize_TPMU_ASYM_SCHEME(const TPMU_ASYM_SCHEME& value,
                                  std::string* buffer);

TPM_RC Parse_TPMU_ASYM_SCHEME(std::string* buffer,
                              TPMU_ASYM_SCHEME* value,
                              std::string* value_bytes);

TPM_RC Serialize_TPMU_SIGNATURE(const TPMU_SIGNATURE& value,
                                std::string* buffer);

TPM_RC Parse_TPMU_SIGNATURE(std::string* buffer,
                            TPMU_SIGNATURE* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMU_ENCRYPTED_SECRET(
    const TPMU_ENCRYPTED_SECRET& value, std::string* buffer);

TPM_RC Parse_TPMU_ENCRYPTED_SECRET(std::string* buffer,
                                   TPMU_ENCRYPTED_SECRET* value,
                                   std::string* value_bytes);

TPM_RC Serialize_TPMU_PUBLIC_ID(const TPMU_PUBLIC_ID& value,
                                std::string* buffer);

TPM_RC Parse_TPMU_PUBLIC_ID(std::string* buffer,
                            TPMU_PUBLIC_ID* value,
                            std::string* value_bytes);

TPM_RC Serialize_TPMU_PUBLIC_PARMS(const TPMU_PUBLIC_PARMS& value,
                                   std::string* buffer);

TPM_RC Parse_TPMU_PUBLIC_PARMS(std::string* buffer,
                               TPMU_PUBLIC_PARMS* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMU_SENSITIVE_COMPOSITE(
    const TPMU_SENSITIVE_COMPOSITE& value, std::string* buffer);

TPM_RC
Parse_TPMU_SENSITIVE_COMPOSITE(std::string* buffer,
                               TPMU_SENSITIVE_COMPOSITE* value,
                               std::string* value_bytes);

TPM_RC Serialize_TPMU_SYM_DETAILS(const TPMU_SYM_DETAILS& value,
                                  std::string* buffer);

TPM_RC Parse_TPMU_SYM_DETAILS(std::string* buffer,
                              TPMU_SYM_DETAILS* value,
                              std::string* value_bytes);

#endif  // MINI_TRUNKS_TSS_INTERNAL_H_
