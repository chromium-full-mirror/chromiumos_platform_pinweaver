// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINI_TRUNKS_TSS_INTERNAL_H_
#define MINI_TRUNKS_TSS_INTERNAL_H_

#include "tss.h"

size_t GetNumberOfRequestHandles(TPM_CC command_code);
size_t GetNumberOfResponseHandles(TPM_CC command_code);

TPM_RC Serialize_uint8_t(const uint8_t* value,
                         dst_data_buf_t* buffer);

TPM_RC Parse_uint8_t(src_data_buf_t* buffer,
                     uint8_t* value,
                     dst_data_buf_t* value_bytes);

TPM_RC Serialize_int8_t(const int8_t* value, dst_data_buf_t* buffer);

TPM_RC Parse_int8_t(src_data_buf_t* buffer,
                    int8_t* value,
                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_int(const int* value, dst_data_buf_t* buffer);

TPM_RC Parse_int(src_data_buf_t* buffer,
                 int* value,
                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_uint16_t(const uint16_t* value,
                          dst_data_buf_t* buffer);

TPM_RC Parse_uint16_t(src_data_buf_t* buffer,
                      uint16_t* value,
                      dst_data_buf_t* value_bytes);

TPM_RC Serialize_int16_t(const int16_t* value,
                         dst_data_buf_t* buffer);

TPM_RC Parse_int16_t(src_data_buf_t* buffer,
                     int16_t* value,
                     dst_data_buf_t* value_bytes);

TPM_RC Serialize_uint32_t(const uint32_t* value,
                          dst_data_buf_t* buffer);

TPM_RC Parse_uint32_t(src_data_buf_t* buffer,
                      uint32_t* value,
                      dst_data_buf_t* value_bytes);

TPM_RC Serialize_int32_t(const int32_t* value,
                         dst_data_buf_t* buffer);

TPM_RC Parse_int32_t(src_data_buf_t* buffer,
                     int32_t* value,
                     dst_data_buf_t* value_bytes);

TPM_RC Serialize_uint64_t(const uint64_t* value,
                          dst_data_buf_t* buffer);

TPM_RC Parse_uint64_t(src_data_buf_t* buffer,
                      uint64_t* value,
                      dst_data_buf_t* value_bytes);

TPM_RC Serialize_int64_t(const int64_t* value,
                         dst_data_buf_t* buffer);

TPM_RC Parse_int64_t(src_data_buf_t* buffer,
                     int64_t* value,
                     dst_data_buf_t* value_bytes);

TPM_RC Serialize_UINT8(const UINT8* value, dst_data_buf_t* buffer);

TPM_RC Parse_UINT8(src_data_buf_t* buffer,
                   UINT8* value,
                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_BYTE(const BYTE* value, dst_data_buf_t* buffer);

TPM_RC Parse_BYTE(src_data_buf_t* buffer,
                  BYTE* value,
                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_INT8(const INT8* value, dst_data_buf_t* buffer);

TPM_RC Parse_INT8(src_data_buf_t* buffer,
                  INT8* value,
                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_BOOL(const BOOL* value, dst_data_buf_t* buffer);

TPM_RC Parse_BOOL(src_data_buf_t* buffer,
                  BOOL* value,
                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_UINT16(const UINT16* value, dst_data_buf_t* buffer);

TPM_RC Parse_UINT16(src_data_buf_t* buffer,
                    UINT16* value,
                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_INT16(const INT16* value, dst_data_buf_t* buffer);

TPM_RC Parse_INT16(src_data_buf_t* buffer,
                   INT16* value,
                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_UINT32(const UINT32* value, dst_data_buf_t* buffer);

TPM_RC Parse_UINT32(src_data_buf_t* buffer,
                    UINT32* value,
                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_INT32(const INT32* value, dst_data_buf_t* buffer);

TPM_RC Parse_INT32(src_data_buf_t* buffer,
                   INT32* value,
                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_UINT64(const UINT64* value, dst_data_buf_t* buffer);

TPM_RC Parse_UINT64(src_data_buf_t* buffer,
                    UINT64* value,
                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_INT64(const INT64* value, dst_data_buf_t* buffer);

TPM_RC Parse_INT64(src_data_buf_t* buffer,
                   INT64* value,
                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_ALGORITHM_ID(const TPM_ALGORITHM_ID* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPM_ALGORITHM_ID(src_data_buf_t* buffer,
                              TPM_ALGORITHM_ID* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_MODIFIER_INDICATOR(
    const TPM_MODIFIER_INDICATOR* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_MODIFIER_INDICATOR(src_data_buf_t* buffer,
                                    TPM_MODIFIER_INDICATOR* value,
                                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_AUTHORIZATION_SIZE(
    const TPM_AUTHORIZATION_SIZE* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_AUTHORIZATION_SIZE(src_data_buf_t* buffer,
                                    TPM_AUTHORIZATION_SIZE* value,
                                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_PARAMETER_SIZE(
    const TPM_PARAMETER_SIZE* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_PARAMETER_SIZE(src_data_buf_t* buffer,
                                TPM_PARAMETER_SIZE* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_KEY_SIZE(const TPM_KEY_SIZE* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPM_KEY_SIZE(src_data_buf_t* buffer,
                          TPM_KEY_SIZE* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_KEY_BITS(const TPM_KEY_BITS* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPM_KEY_BITS(src_data_buf_t* buffer,
                          TPM_KEY_BITS* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_HANDLE(const TPM_HANDLE* value,
                            dst_data_buf_t* buffer);

TPM_RC Parse_TPM_HANDLE(src_data_buf_t* buffer,
                        TPM_HANDLE* value,
                        dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_NONCE(const TPM2B_NONCE* value,
                             dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_NONCE(src_data_buf_t* buffer,
                         TPM2B_NONCE* value,
                         dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_AUTH(const TPM2B_AUTH* value,
                            dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_AUTH(src_data_buf_t* buffer,
                        TPM2B_AUTH* value,
                        dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_OPERAND(const TPM2B_OPERAND* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_OPERAND(src_data_buf_t* buffer,
                           TPM2B_OPERAND* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_HMAC(const TPMS_SCHEME_HMAC* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_HMAC(src_data_buf_t* buffer,
                              TPMS_SCHEME_HMAC* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_RSASSA(
    const TPMS_SCHEME_RSASSA* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_RSASSA(src_data_buf_t* buffer,
                                TPMS_SCHEME_RSASSA* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_RSAPSS(
    const TPMS_SCHEME_RSAPSS* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_RSAPSS(src_data_buf_t* buffer,
                                TPMS_SCHEME_RSAPSS* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_ECDSA(const TPMS_SCHEME_ECDSA* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_ECDSA(src_data_buf_t* buffer,
                               TPMS_SCHEME_ECDSA* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_SM2(const TPMS_SCHEME_SM2* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_SM2(src_data_buf_t* buffer,
                             TPMS_SCHEME_SM2* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_ECSCHNORR(
    const TPMS_SCHEME_ECSCHNORR* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_ECSCHNORR(src_data_buf_t* buffer,
                                   TPMS_SCHEME_ECSCHNORR* value,
                                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_YES_NO(const TPMI_YES_NO* value,
                             dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_YES_NO(src_data_buf_t* buffer,
                         TPMI_YES_NO* value,
                         dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_DH_OBJECT(const TPMI_DH_OBJECT* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_DH_OBJECT(src_data_buf_t* buffer,
                            TPMI_DH_OBJECT* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_DH_PERSISTENT(
    const TPMI_DH_PERSISTENT* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_DH_PERSISTENT(src_data_buf_t* buffer,
                                TPMI_DH_PERSISTENT* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_DH_ENTITY(const TPMI_DH_ENTITY* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_DH_ENTITY(src_data_buf_t* buffer,
                            TPMI_DH_ENTITY* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_DH_PCR(const TPMI_DH_PCR* value,
                             dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_DH_PCR(src_data_buf_t* buffer,
                         TPMI_DH_PCR* value,
                         dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_SH_AUTH_SESSION(
    const TPMI_SH_AUTH_SESSION* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_SH_AUTH_SESSION(src_data_buf_t* buffer,
                                  TPMI_SH_AUTH_SESSION* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_SH_HMAC(const TPMI_SH_HMAC* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_SH_HMAC(src_data_buf_t* buffer,
                          TPMI_SH_HMAC* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_SH_POLICY(const TPMI_SH_POLICY* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_SH_POLICY(src_data_buf_t* buffer,
                            TPMI_SH_POLICY* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_DH_CONTEXT(const TPMI_DH_CONTEXT* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_DH_CONTEXT(src_data_buf_t* buffer,
                             TPMI_DH_CONTEXT* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RH_HIERARCHY(const TPMI_RH_HIERARCHY* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RH_HIERARCHY(src_data_buf_t* buffer,
                               TPMI_RH_HIERARCHY* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RH_ENABLES(const TPMI_RH_ENABLES* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RH_ENABLES(src_data_buf_t* buffer,
                             TPMI_RH_ENABLES* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RH_HIERARCHY_AUTH(
    const TPMI_RH_HIERARCHY_AUTH* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RH_HIERARCHY_AUTH(src_data_buf_t* buffer,
                                    TPMI_RH_HIERARCHY_AUTH* value,
                                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RH_PLATFORM(const TPMI_RH_PLATFORM* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RH_PLATFORM(src_data_buf_t* buffer,
                              TPMI_RH_PLATFORM* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RH_OWNER(const TPMI_RH_OWNER* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RH_OWNER(src_data_buf_t* buffer,
                           TPMI_RH_OWNER* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RH_ENDORSEMENT(
    const TPMI_RH_ENDORSEMENT* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RH_ENDORSEMENT(src_data_buf_t* buffer,
                                 TPMI_RH_ENDORSEMENT* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RH_PROVISION(const TPMI_RH_PROVISION* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RH_PROVISION(src_data_buf_t* buffer,
                               TPMI_RH_PROVISION* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RH_CLEAR(const TPMI_RH_CLEAR* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RH_CLEAR(src_data_buf_t* buffer,
                           TPMI_RH_CLEAR* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RH_NV_AUTH(const TPMI_RH_NV_AUTH* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RH_NV_AUTH(src_data_buf_t* buffer,
                             TPMI_RH_NV_AUTH* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RH_LOCKOUT(const TPMI_RH_LOCKOUT* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RH_LOCKOUT(src_data_buf_t* buffer,
                             TPMI_RH_LOCKOUT* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RH_NV_INDEX(const TPMI_RH_NV_INDEX* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RH_NV_INDEX(src_data_buf_t* buffer,
                              TPMI_RH_NV_INDEX* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_HASH(const TPMI_ALG_HASH* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_HASH(src_data_buf_t* buffer,
                           TPMI_ALG_HASH* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_ASYM(const TPMI_ALG_ASYM* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_ASYM(src_data_buf_t* buffer,
                           TPMI_ALG_ASYM* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_SYM(const TPMI_ALG_SYM* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_SYM(src_data_buf_t* buffer,
                          TPMI_ALG_SYM* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_SYM_OBJECT(
    const TPMI_ALG_SYM_OBJECT* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_SYM_OBJECT(src_data_buf_t* buffer,
                                 TPMI_ALG_SYM_OBJECT* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_SYM_MODE(const TPMI_ALG_SYM_MODE* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_SYM_MODE(src_data_buf_t* buffer,
                               TPMI_ALG_SYM_MODE* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_KDF(const TPMI_ALG_KDF* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_KDF(src_data_buf_t* buffer,
                          TPMI_ALG_KDF* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_SIG_SCHEME(
    const TPMI_ALG_SIG_SCHEME* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_SIG_SCHEME(src_data_buf_t* buffer,
                                 TPMI_ALG_SIG_SCHEME* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ECC_KEY_EXCHANGE(
    const TPMI_ECC_KEY_EXCHANGE* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ECC_KEY_EXCHANGE(src_data_buf_t* buffer,
                                   TPMI_ECC_KEY_EXCHANGE* value,
                                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ST_COMMAND_TAG(
    const TPMI_ST_COMMAND_TAG* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ST_COMMAND_TAG(src_data_buf_t* buffer,
                                 TPMI_ST_COMMAND_TAG* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ST_ATTEST(const TPMI_ST_ATTEST* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ST_ATTEST(src_data_buf_t* buffer,
                            TPMI_ST_ATTEST* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_AES_KEY_BITS(const TPMI_AES_KEY_BITS* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_AES_KEY_BITS(src_data_buf_t* buffer,
                               TPMI_AES_KEY_BITS* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_SM4_KEY_BITS(const TPMI_SM4_KEY_BITS* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_SM4_KEY_BITS(src_data_buf_t* buffer,
                               TPMI_SM4_KEY_BITS* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_KEYEDHASH_SCHEME(
    const TPMI_ALG_KEYEDHASH_SCHEME* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPMI_ALG_KEYEDHASH_SCHEME(src_data_buf_t* buffer,
                                TPMI_ALG_KEYEDHASH_SCHEME* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_ASYM_SCHEME(
    const TPMI_ALG_ASYM_SCHEME* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_ASYM_SCHEME(src_data_buf_t* buffer,
                                  TPMI_ALG_ASYM_SCHEME* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_RSA_SCHEME(
    const TPMI_ALG_RSA_SCHEME* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_RSA_SCHEME(src_data_buf_t* buffer,
                                 TPMI_ALG_RSA_SCHEME* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_RSA_DECRYPT(
    const TPMI_ALG_RSA_DECRYPT* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_RSA_DECRYPT(src_data_buf_t* buffer,
                                  TPMI_ALG_RSA_DECRYPT* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_RSA_KEY_BITS(const TPMI_RSA_KEY_BITS* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_RSA_KEY_BITS(src_data_buf_t* buffer,
                               TPMI_RSA_KEY_BITS* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_ECC_SCHEME(
    const TPMI_ALG_ECC_SCHEME* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_ECC_SCHEME(src_data_buf_t* buffer,
                                 TPMI_ALG_ECC_SCHEME* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ECC_CURVE(const TPMI_ECC_CURVE* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ECC_CURVE(src_data_buf_t* buffer,
                            TPMI_ECC_CURVE* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMI_ALG_PUBLIC(const TPMI_ALG_PUBLIC* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMI_ALG_PUBLIC(src_data_buf_t* buffer,
                             TPMI_ALG_PUBLIC* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMA_ALGORITHM(const TPMA_ALGORITHM* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMA_ALGORITHM(src_data_buf_t* buffer,
                            TPMA_ALGORITHM* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMA_OBJECT(const TPMA_OBJECT* value,
                             dst_data_buf_t* buffer);

TPM_RC Parse_TPMA_OBJECT(src_data_buf_t* buffer,
                         TPMA_OBJECT* value,
                         dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMA_SESSION(const TPMA_SESSION* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPMA_SESSION(src_data_buf_t* buffer,
                          TPMA_SESSION* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMA_LOCALITY(const TPMA_LOCALITY* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPMA_LOCALITY(src_data_buf_t* buffer,
                           TPMA_LOCALITY* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMA_PERMANENT(const TPMA_PERMANENT* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMA_PERMANENT(src_data_buf_t* buffer,
                            TPMA_PERMANENT* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMA_STARTUP_CLEAR(
    const TPMA_STARTUP_CLEAR* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMA_STARTUP_CLEAR(src_data_buf_t* buffer,
                                TPMA_STARTUP_CLEAR* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMA_MEMORY(const TPMA_MEMORY* value,
                             dst_data_buf_t* buffer);

TPM_RC Parse_TPMA_MEMORY(src_data_buf_t* buffer,
                         TPMA_MEMORY* value,
                         dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMA_CC(const TPMA_CC* value,
                         dst_data_buf_t* buffer);

TPM_RC Parse_TPMA_CC(src_data_buf_t* buffer,
                                   TPMA_CC* value,
                                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_NV_INDEX(const TPM_NV_INDEX* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPM_NV_INDEX(src_data_buf_t* buffer,
                          TPM_NV_INDEX* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMA_NV(const TPMA_NV* value,
                         dst_data_buf_t* buffer);

TPM_RC Parse_TPMA_NV(src_data_buf_t* buffer,
                     TPMA_NV* value,
                     dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_SPEC(const TPM_SPEC* value,
                          dst_data_buf_t* buffer);

TPM_RC Parse_TPM_SPEC(src_data_buf_t* buffer,
                      TPM_SPEC* value,
                      dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_GENERATED(const TPM_GENERATED* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPM_GENERATED(src_data_buf_t* buffer,
                           TPM_GENERATED* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_ALG_ID(const TPM_ALG_ID* value,
                            dst_data_buf_t* buffer);

TPM_RC Parse_TPM_ALG_ID(src_data_buf_t* buffer,
                        TPM_ALG_ID* value,
                        dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_ECC_CURVE(const TPM_ECC_CURVE* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPM_ECC_CURVE(src_data_buf_t* buffer,
                           TPM_ECC_CURVE* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_CC(const TPM_CC* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_CC(src_data_buf_t* buffer,
                    TPM_CC* value,
                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_RC(const TPM_RC* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_RC(src_data_buf_t* buffer,
                    TPM_RC* value,
                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_CLOCK_ADJUST(const TPM_CLOCK_ADJUST* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPM_CLOCK_ADJUST(src_data_buf_t* buffer,
                              TPM_CLOCK_ADJUST* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_EO(const TPM_EO* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_EO(src_data_buf_t* buffer,
                                  TPM_EO* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_ST(const TPM_ST* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_ST(src_data_buf_t* buffer,
                                  TPM_ST* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_SU(const TPM_SU* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_SU(src_data_buf_t* buffer,
                                  TPM_SU* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_SE(const TPM_SE* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_SE(src_data_buf_t* buffer,
                                  TPM_SE* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_CAP(const TPM_CAP* value,
                         dst_data_buf_t* buffer);

TPM_RC Parse_TPM_CAP(src_data_buf_t* buffer,
                     TPM_CAP* value,
                     dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_PT(const TPM_PT* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_PT(src_data_buf_t* buffer,
                                  TPM_PT* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_PT_PCR(const TPM_PT_PCR* value,
                            dst_data_buf_t* buffer);

TPM_RC Parse_TPM_PT_PCR(src_data_buf_t* buffer,
                        TPM_PT_PCR* value,
                        dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_PS(const TPM_PS* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_PS(src_data_buf_t* buffer,
                                  TPM_PS* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_HT(const TPM_HT* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_HT(src_data_buf_t* buffer,
                                  TPM_HT* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_RH(const TPM_RH* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_RH(src_data_buf_t* buffer,
                                  TPM_RH* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM_HC(const TPM_HC* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM_HC(src_data_buf_t* buffer,
                                  TPM_HC* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_ALGORITHM_DESCRIPTION(
    const TPMS_ALGORITHM_DESCRIPTION* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPMS_ALGORITHM_DESCRIPTION(src_data_buf_t* buffer,
                                 TPMS_ALGORITHM_DESCRIPTION* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_HA(const TPMT_HA* value,
                         dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_HA(src_data_buf_t* buffer,
                     TPMT_HA* value,
                     dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_DIGEST(const TPM2B_DIGEST* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_DIGEST(src_data_buf_t* buffer,
                          TPM2B_DIGEST* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_DATA(const TPM2B_DATA* value,
                            dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_DATA(src_data_buf_t* buffer,
                        TPM2B_DATA* value,
                        dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_EVENT(const TPM2B_EVENT* value,
                             dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_EVENT(src_data_buf_t* buffer,
                         TPM2B_EVENT* value,
                         dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_MAX_BUFFER(const TPM2B_MAX_BUFFER* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_MAX_BUFFER(src_data_buf_t* buffer,
                              TPM2B_MAX_BUFFER* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_MAX_NV_BUFFER(
    const TPM2B_MAX_NV_BUFFER* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_MAX_NV_BUFFER(src_data_buf_t* buffer,
                                 TPM2B_MAX_NV_BUFFER* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_TIMEOUT(const TPM2B_TIMEOUT* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_TIMEOUT(src_data_buf_t* buffer,
                           TPM2B_TIMEOUT* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_IV(const TPM2B_IV* value,
                          dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_IV(src_data_buf_t* buffer,
                      TPM2B_IV* value,
                      dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_NAME(const TPM2B_NAME* value,
                            dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_NAME(src_data_buf_t* buffer,
                        TPM2B_NAME* value,
                        dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_PCR_SELECT(const TPMS_PCR_SELECT* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_PCR_SELECT(src_data_buf_t* buffer,
                             TPMS_PCR_SELECT* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_PCR_SELECTION(
    const TPMS_PCR_SELECTION* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_PCR_SELECTION(src_data_buf_t* buffer,
                                TPMS_PCR_SELECTION* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_TK_CREATION(const TPMT_TK_CREATION* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_TK_CREATION(src_data_buf_t* buffer,
                              TPMT_TK_CREATION* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_TK_VERIFIED(const TPMT_TK_VERIFIED* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_TK_VERIFIED(src_data_buf_t* buffer,
                              TPMT_TK_VERIFIED* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_TK_AUTH(const TPMT_TK_AUTH* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_TK_AUTH(src_data_buf_t* buffer,
                          TPMT_TK_AUTH* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_TK_HASHCHECK(const TPMT_TK_HASHCHECK* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_TK_HASHCHECK(src_data_buf_t* buffer,
                               TPMT_TK_HASHCHECK* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_ALG_PROPERTY(const TPMS_ALG_PROPERTY* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_ALG_PROPERTY(src_data_buf_t* buffer,
                               TPMS_ALG_PROPERTY* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_TAGGED_PROPERTY(
    const TPMS_TAGGED_PROPERTY* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_TAGGED_PROPERTY(src_data_buf_t* buffer,
                                  TPMS_TAGGED_PROPERTY* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_TAGGED_PCR_SELECT(
    const TPMS_TAGGED_PCR_SELECT* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_TAGGED_PCR_SELECT(src_data_buf_t* buffer,
                                    TPMS_TAGGED_PCR_SELECT* value,
                                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPML_CC(const TPML_CC* value,
                         dst_data_buf_t* buffer);

TPM_RC Parse_TPML_CC(src_data_buf_t* buffer,
                     TPML_CC* value,
                     dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPML_CCA(const TPML_CCA* value,
                          dst_data_buf_t* buffer);

TPM_RC Parse_TPML_CCA(src_data_buf_t* buffer,
                      TPML_CCA* value,
                      dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPML_ALG(const TPML_ALG* value,
                          dst_data_buf_t* buffer);

TPM_RC Parse_TPML_ALG(src_data_buf_t* buffer,
                      TPML_ALG* value,
                      dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPML_HANDLE(const TPML_HANDLE* value,
                             dst_data_buf_t* buffer);

TPM_RC Parse_TPML_HANDLE(src_data_buf_t* buffer,
                         TPML_HANDLE* value,
                         dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPML_DIGEST(const TPML_DIGEST* value,
                             dst_data_buf_t* buffer);

TPM_RC Parse_TPML_DIGEST(src_data_buf_t* buffer,
                         TPML_DIGEST* value,
                         dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPML_DIGEST_VALUES(
    const TPML_DIGEST_VALUES* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPML_DIGEST_VALUES(src_data_buf_t* buffer,
                                TPML_DIGEST_VALUES* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_DIGEST_VALUES(
    const TPM2B_DIGEST_VALUES* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_DIGEST_VALUES(src_data_buf_t* buffer,
                                 TPM2B_DIGEST_VALUES* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPML_PCR_SELECTION(
    const TPML_PCR_SELECTION* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPML_PCR_SELECTION(src_data_buf_t* buffer,
                                TPML_PCR_SELECTION* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPML_ALG_PROPERTY(const TPML_ALG_PROPERTY* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPML_ALG_PROPERTY(src_data_buf_t* buffer,
                               TPML_ALG_PROPERTY* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPML_TAGGED_TPM_PROPERTY(
    const TPML_TAGGED_TPM_PROPERTY* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPML_TAGGED_TPM_PROPERTY(src_data_buf_t* buffer,
                               TPML_TAGGED_TPM_PROPERTY* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPML_TAGGED_PCR_PROPERTY(
    const TPML_TAGGED_PCR_PROPERTY* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPML_TAGGED_PCR_PROPERTY(src_data_buf_t* buffer,
                               TPML_TAGGED_PCR_PROPERTY* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPML_ECC_CURVE(const TPML_ECC_CURVE* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPML_ECC_CURVE(src_data_buf_t* buffer,
                            TPML_ECC_CURVE* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_CAPABILITY_DATA(
    const TPMS_CAPABILITY_DATA* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_CAPABILITY_DATA(src_data_buf_t* buffer,
                                  TPMS_CAPABILITY_DATA* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_CLOCK_INFO(const TPMS_CLOCK_INFO* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_CLOCK_INFO(src_data_buf_t* buffer,
                             TPMS_CLOCK_INFO* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_TIME_INFO(const TPMS_TIME_INFO* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_TIME_INFO(src_data_buf_t* buffer,
                            TPMS_TIME_INFO* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_TIME_ATTEST_INFO(
    const TPMS_TIME_ATTEST_INFO* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_TIME_ATTEST_INFO(src_data_buf_t* buffer,
                                   TPMS_TIME_ATTEST_INFO* value,
                                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_CERTIFY_INFO(const TPMS_CERTIFY_INFO* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_CERTIFY_INFO(src_data_buf_t* buffer,
                               TPMS_CERTIFY_INFO* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_QUOTE_INFO(const TPMS_QUOTE_INFO* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_QUOTE_INFO(src_data_buf_t* buffer,
                             TPMS_QUOTE_INFO* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_COMMAND_AUDIT_INFO(
    const TPMS_COMMAND_AUDIT_INFO* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPMS_COMMAND_AUDIT_INFO(src_data_buf_t* buffer,
                              TPMS_COMMAND_AUDIT_INFO* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SESSION_AUDIT_INFO(
    const TPMS_SESSION_AUDIT_INFO* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPMS_SESSION_AUDIT_INFO(src_data_buf_t* buffer,
                              TPMS_SESSION_AUDIT_INFO* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_CREATION_INFO(
    const TPMS_CREATION_INFO* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_CREATION_INFO(src_data_buf_t* buffer,
                                TPMS_CREATION_INFO* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_NV_CERTIFY_INFO(
    const TPMS_NV_CERTIFY_INFO* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_NV_CERTIFY_INFO(src_data_buf_t* buffer,
                                  TPMS_NV_CERTIFY_INFO* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_ATTEST(const TPMS_ATTEST* value,
                             dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_ATTEST(src_data_buf_t* buffer,
                         TPMS_ATTEST* value,
                         dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_ATTEST(const TPM2B_ATTEST* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_ATTEST(src_data_buf_t* buffer,
                          TPM2B_ATTEST* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_AUTH_COMMAND(const TPMS_AUTH_COMMAND* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_AUTH_COMMAND(src_data_buf_t* buffer,
                               TPMS_AUTH_COMMAND* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_AUTH_RESPONSE(
    const TPMS_AUTH_RESPONSE* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_AUTH_RESPONSE(src_data_buf_t* buffer,
                                TPMS_AUTH_RESPONSE* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_SYM_DEF(const TPMT_SYM_DEF* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_SYM_DEF(src_data_buf_t* buffer,
                          TPMT_SYM_DEF* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_SYM_DEF_OBJECT(
    const TPMT_SYM_DEF_OBJECT* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_SYM_DEF_OBJECT(src_data_buf_t* buffer,
                                 TPMT_SYM_DEF_OBJECT* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_SYM_KEY(const TPM2B_SYM_KEY* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_SYM_KEY(src_data_buf_t* buffer,
                           TPM2B_SYM_KEY* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SYMCIPHER_PARMS(
    const TPMS_SYMCIPHER_PARMS* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SYMCIPHER_PARMS(src_data_buf_t* buffer,
                                  TPMS_SYMCIPHER_PARMS* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_SENSITIVE_DATA(
    const TPM2B_SENSITIVE_DATA* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_SENSITIVE_DATA(src_data_buf_t* buffer,
                                  TPM2B_SENSITIVE_DATA* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SENSITIVE_CREATE(
    const TPMS_SENSITIVE_CREATE* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SENSITIVE_CREATE(src_data_buf_t* buffer,
                                   TPMS_SENSITIVE_CREATE* value,
                                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_SENSITIVE_CREATE(
    const TPM2B_SENSITIVE_CREATE* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_SENSITIVE_CREATE(src_data_buf_t* buffer,
                                    TPM2B_SENSITIVE_CREATE* value,
                                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_SIGHASH(
    const TPMS_SCHEME_SIGHASH* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_SIGHASH(src_data_buf_t* buffer,
                                 TPMS_SCHEME_SIGHASH* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_XOR(const TPMS_SCHEME_XOR* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_XOR(src_data_buf_t* buffer,
                             TPMS_SCHEME_XOR* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_KEYEDHASH_SCHEME(
    const TPMT_KEYEDHASH_SCHEME* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_KEYEDHASH_SCHEME(src_data_buf_t* buffer,
                                   TPMT_KEYEDHASH_SCHEME* value,
                                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_ECDAA(const TPMS_SCHEME_ECDAA* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_ECDAA(src_data_buf_t* buffer,
                               TPMS_SCHEME_ECDAA* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_SIG_SCHEME(const TPMT_SIG_SCHEME* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_SIG_SCHEME(src_data_buf_t* buffer,
                             TPMT_SIG_SCHEME* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_OAEP(const TPMS_SCHEME_OAEP* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_OAEP(src_data_buf_t* buffer,
                              TPMS_SCHEME_OAEP* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_ECDH(const TPMS_SCHEME_ECDH* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_ECDH(src_data_buf_t* buffer,
                              TPMS_SCHEME_ECDH* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_MGF1(const TPMS_SCHEME_MGF1* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_MGF1(src_data_buf_t* buffer,
                              TPMS_SCHEME_MGF1* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_KDF1_SP800_56a(
    const TPMS_SCHEME_KDF1_SP800_56a* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPMS_SCHEME_KDF1_SP800_56a(src_data_buf_t* buffer,
                                 TPMS_SCHEME_KDF1_SP800_56a* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_KDF2(const TPMS_SCHEME_KDF2* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SCHEME_KDF2(src_data_buf_t* buffer,
                              TPMS_SCHEME_KDF2* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SCHEME_KDF1_SP800_108(
    const TPMS_SCHEME_KDF1_SP800_108* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPMS_SCHEME_KDF1_SP800_108(src_data_buf_t* buffer,
                                 TPMS_SCHEME_KDF1_SP800_108* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_KDF_SCHEME(const TPMT_KDF_SCHEME* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_KDF_SCHEME(src_data_buf_t* buffer,
                             TPMT_KDF_SCHEME* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_ASYM_SCHEME(const TPMT_ASYM_SCHEME* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_ASYM_SCHEME(src_data_buf_t* buffer,
                              TPMT_ASYM_SCHEME* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_RSA_SCHEME(const TPMT_RSA_SCHEME* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_RSA_SCHEME(src_data_buf_t* buffer,
                             TPMT_RSA_SCHEME* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_RSA_DECRYPT(const TPMT_RSA_DECRYPT* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_RSA_DECRYPT(src_data_buf_t* buffer,
                              TPMT_RSA_DECRYPT* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_PUBLIC_KEY_RSA(
    const TPM2B_PUBLIC_KEY_RSA* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_PUBLIC_KEY_RSA(src_data_buf_t* buffer,
                                  TPM2B_PUBLIC_KEY_RSA* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_PRIVATE_KEY_RSA(
    const TPM2B_PRIVATE_KEY_RSA* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_PRIVATE_KEY_RSA(src_data_buf_t* buffer,
                                   TPM2B_PRIVATE_KEY_RSA* value,
                                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_ECC_PARAMETER(
    const TPM2B_ECC_PARAMETER* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_ECC_PARAMETER(src_data_buf_t* buffer,
                                 TPM2B_ECC_PARAMETER* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_ECC_POINT(const TPMS_ECC_POINT* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_ECC_POINT(src_data_buf_t* buffer,
                            TPMS_ECC_POINT* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_ECC_POINT(const TPM2B_ECC_POINT* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_ECC_POINT(src_data_buf_t* buffer,
                             TPM2B_ECC_POINT* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_ECC_SCHEME(const TPMT_ECC_SCHEME* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_ECC_SCHEME(src_data_buf_t* buffer,
                             TPMT_ECC_SCHEME* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_ALGORITHM_DETAIL_ECC(
    const TPMS_ALGORITHM_DETAIL_ECC* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPMS_ALGORITHM_DETAIL_ECC(src_data_buf_t* buffer,
                                TPMS_ALGORITHM_DETAIL_ECC* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SIGNATURE_RSASSA(
    const TPMS_SIGNATURE_RSASSA* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SIGNATURE_RSASSA(src_data_buf_t* buffer,
                                   TPMS_SIGNATURE_RSASSA* value,
                                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SIGNATURE_RSAPSS(
    const TPMS_SIGNATURE_RSAPSS* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SIGNATURE_RSAPSS(src_data_buf_t* buffer,
                                   TPMS_SIGNATURE_RSAPSS* value,
                                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_SIGNATURE_ECDSA(
    const TPMS_SIGNATURE_ECDSA* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_SIGNATURE_ECDSA(src_data_buf_t* buffer,
                                  TPMS_SIGNATURE_ECDSA* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_SIGNATURE(const TPMT_SIGNATURE* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_SIGNATURE(src_data_buf_t* buffer,
                            TPMT_SIGNATURE* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_ENCRYPTED_SECRET(
    const TPM2B_ENCRYPTED_SECRET* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_ENCRYPTED_SECRET(src_data_buf_t* buffer,
                                    TPM2B_ENCRYPTED_SECRET* value,
                                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_KEYEDHASH_PARMS(
    const TPMS_KEYEDHASH_PARMS* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_KEYEDHASH_PARMS(src_data_buf_t* buffer,
                                  TPMS_KEYEDHASH_PARMS* value,
                                  dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_ASYM_PARMS(const TPMS_ASYM_PARMS* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_ASYM_PARMS(src_data_buf_t* buffer,
                             TPMS_ASYM_PARMS* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_RSA_PARMS(const TPMS_RSA_PARMS* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_RSA_PARMS(src_data_buf_t* buffer,
                            TPMS_RSA_PARMS* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_ECC_PARMS(const TPMS_ECC_PARMS* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_ECC_PARMS(src_data_buf_t* buffer,
                            TPMS_ECC_PARMS* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_PUBLIC_PARMS(const TPMT_PUBLIC_PARMS* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_PUBLIC_PARMS(src_data_buf_t* buffer,
                               TPMT_PUBLIC_PARMS* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_PUBLIC(const TPMT_PUBLIC* value,
                             dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_PUBLIC(src_data_buf_t* buffer,
                         TPMT_PUBLIC* value,
                         dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_PUBLIC(const TPM2B_PUBLIC* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_PUBLIC(src_data_buf_t* buffer,
                          TPM2B_PUBLIC* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_PRIVATE_VENDOR_SPECIFIC(
    const TPM2B_PRIVATE_VENDOR_SPECIFIC* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPM2B_PRIVATE_VENDOR_SPECIFIC(src_data_buf_t* buffer,
                                    TPM2B_PRIVATE_VENDOR_SPECIFIC* value,
                                    dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMT_SENSITIVE(const TPMT_SENSITIVE* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMT_SENSITIVE(src_data_buf_t* buffer,
                            TPMT_SENSITIVE* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_SENSITIVE(const TPM2B_SENSITIVE* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_SENSITIVE(src_data_buf_t* buffer,
                             TPM2B_SENSITIVE* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize__PRIVATE(const _PRIVATE* value,
                          dst_data_buf_t* buffer);

TPM_RC Parse__PRIVATE(src_data_buf_t* buffer,
                      _PRIVATE* value,
                      dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_PRIVATE(const TPM2B_PRIVATE* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_PRIVATE(src_data_buf_t* buffer,
                           TPM2B_PRIVATE* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize__ID_OBJECT(const _ID_OBJECT* value,
                            dst_data_buf_t* buffer);

TPM_RC Parse__ID_OBJECT(src_data_buf_t* buffer,
                        _ID_OBJECT* value,
                        dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_ID_OBJECT(const TPM2B_ID_OBJECT* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_ID_OBJECT(src_data_buf_t* buffer,
                             TPM2B_ID_OBJECT* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_NV_PUBLIC(const TPMS_NV_PUBLIC* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_NV_PUBLIC(src_data_buf_t* buffer,
                            TPMS_NV_PUBLIC* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_NV_PUBLIC(const TPM2B_NV_PUBLIC* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_NV_PUBLIC(src_data_buf_t* buffer,
                             TPM2B_NV_PUBLIC* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_CONTEXT_SENSITIVE(
    const TPM2B_CONTEXT_SENSITIVE* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPM2B_CONTEXT_SENSITIVE(src_data_buf_t* buffer,
                              TPM2B_CONTEXT_SENSITIVE* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_CONTEXT_DATA(const TPMS_CONTEXT_DATA* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_CONTEXT_DATA(src_data_buf_t* buffer,
                               TPMS_CONTEXT_DATA* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_CONTEXT_DATA(
    const TPM2B_CONTEXT_DATA* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_CONTEXT_DATA(src_data_buf_t* buffer,
                                TPM2B_CONTEXT_DATA* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_CONTEXT(const TPMS_CONTEXT* value,
                              dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_CONTEXT(src_data_buf_t* buffer,
                          TPMS_CONTEXT* value,
                          dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMS_CREATION_DATA(
    const TPMS_CREATION_DATA* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMS_CREATION_DATA(src_data_buf_t* buffer,
                                TPMS_CREATION_DATA* value,
                                dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPM2B_CREATION_DATA(
    const TPM2B_CREATION_DATA* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPM2B_CREATION_DATA(src_data_buf_t* buffer,
                                 TPM2B_CREATION_DATA* value,
                                 dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_HA(const TPMU_HA* value,
                         dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_HA(src_data_buf_t* buffer,
                     TPMU_HA* value,
                     dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_NAME(const TPMU_NAME* value,
                           dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_NAME(src_data_buf_t* buffer,
                       TPMU_NAME* value,
                       dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_CAPABILITIES(const TPMU_CAPABILITIES* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_CAPABILITIES(src_data_buf_t* buffer,
                               TPMU_CAPABILITIES* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_ATTEST(const TPMU_ATTEST* value,
                             dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_ATTEST(src_data_buf_t* buffer,
                         TPMU_ATTEST* value,
                         dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_SYM_KEY_BITS(const TPMU_SYM_KEY_BITS* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_SYM_KEY_BITS(src_data_buf_t* buffer,
                               TPMU_SYM_KEY_BITS* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_SYM_MODE(const TPMU_SYM_MODE* value,
                               dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_SYM_MODE(src_data_buf_t* buffer,
                           TPMU_SYM_MODE* value,
                           dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_SCHEME_KEYEDHASH(
    const TPMU_SCHEME_KEYEDHASH* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_SCHEME_KEYEDHASH(src_data_buf_t* buffer,
                                   TPMU_SCHEME_KEYEDHASH* value,
                                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_SIG_SCHEME(const TPMU_SIG_SCHEME* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_SIG_SCHEME(src_data_buf_t* buffer,
                             TPMU_SIG_SCHEME* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_KDF_SCHEME(const TPMU_KDF_SCHEME* value,
                                 dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_KDF_SCHEME(src_data_buf_t* buffer,
                             TPMU_KDF_SCHEME* value,
                             dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_ASYM_SCHEME(const TPMU_ASYM_SCHEME* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_ASYM_SCHEME(src_data_buf_t* buffer,
                              TPMU_ASYM_SCHEME* value,
                              dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_SIGNATURE(const TPMU_SIGNATURE* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_SIGNATURE(src_data_buf_t* buffer,
                            TPMU_SIGNATURE* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_ENCRYPTED_SECRET(
    const TPMU_ENCRYPTED_SECRET* value, dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_ENCRYPTED_SECRET(src_data_buf_t* buffer,
                                   TPMU_ENCRYPTED_SECRET* value,
                                   dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_PUBLIC_ID(const TPMU_PUBLIC_ID* value,
                                dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_PUBLIC_ID(src_data_buf_t* buffer,
                            TPMU_PUBLIC_ID* value,
                            dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_PUBLIC_PARMS(const TPMU_PUBLIC_PARMS* value,
                                   dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_PUBLIC_PARMS(src_data_buf_t* buffer,
                               TPMU_PUBLIC_PARMS* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_SENSITIVE_COMPOSITE(
    const TPMU_SENSITIVE_COMPOSITE* value, dst_data_buf_t* buffer);

TPM_RC
Parse_TPMU_SENSITIVE_COMPOSITE(src_data_buf_t* buffer,
                               TPMU_SENSITIVE_COMPOSITE* value,
                               dst_data_buf_t* value_bytes);

TPM_RC Serialize_TPMU_SYM_DETAILS(const TPMU_SYM_DETAILS* value,
                                  dst_data_buf_t* buffer);

TPM_RC Parse_TPMU_SYM_DETAILS(src_data_buf_t* buffer,
                              TPMU_SYM_DETAILS* value,
                              dst_data_buf_t* value_bytes);

#endif  // MINI_TRUNKS_TSS_INTERNAL_H_
