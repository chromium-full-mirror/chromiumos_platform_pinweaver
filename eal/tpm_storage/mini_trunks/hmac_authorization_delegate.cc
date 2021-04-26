// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstring>

#include "authorization_delegate.h"
#include "eal.h"
#include "eal_tpm.h"
#include "tss_internal.h"

const uint32_t kDigestBits = 256;
const uint16_t kNonceMinSize = 16;
const uint16_t kNonceMaxSize = 32;
const uint8_t kDecryptSession = 1 << 5;
const uint8_t kEncryptSession = 1 << 6;
const uint8_t kLabelSize = 4;
const size_t kAesKeySize = 128/8;      // 128 bits is minimum AES key size.
const size_t kAesIVSize = kAesKeySize;
const size_t kMaxDecryptSize = 256;
const uint8_t kContinueSession = 1;
const size_t kHashDigestSize = SHA256_DIGEST_LENGTH;
const size_t kMaxDigestSize = sizeof(TPMU_HA);
const size_t kSessionKeySize = 256/8;

typedef struct hmac_key_t {
  size_t size;
  uint8_t buffer[2 * kMaxDigestSize];
} hmac_key_t;

void HmacKeyInit(hmac_key_t* key) {
  key->size = 0;
}

void HmacKeyAppend(hmac_key_t* key, const TPM2B_DIGEST* data) {
  memcpy(key->buffer + key->size, data->buffer, data->size);
  key->size += data->size;
}

// This method implements the key derivation function used in the TPM.
// NOTE: It only returns 32 byte keys.
static bool CreateKey(
    HmacAuthorizationDelegate* delegate,
    const hmac_key_t* hmac_key,
    const src_data_buf_t* label,
    const TPM2B_NONCE* nonce_newer,
    const TPM2B_NONCE* nonce_older,
    uint8_t* key /* size=SHA256_DIGEST_LENGTH */) {
  uint32_t counter_buf;
  dst_data_buf_t counter = {sizeof(uint32_t), 0, (uint8_t *)&counter_buf};
  uint32_t digest_size_bits_buf;
  dst_data_buf_t digest_size_bits = {sizeof(uint32_t), 0
                                     &digest_size_bits_buf};
  const uint32_t kOne = 1;
  if (Serialize_uint32_t(&kOne, &counter) != TPM_RC_SUCCESS ||
      Serialize_uint32_t(&kDigestBits, &digest_size_bits) != TPM_RC_SUCCESS) {
    return false;
  }

  pinweaver_eal_hmac_sha256_ctx_t hmac;

  // TODO: check errors
  pinweaver_eal_hmac_sha256_init(&hmac, hmac_key->buffer,
                                 hmac_key->size);
  pinweaver_eal_hmac_sha256_update(&hmac, counter.buffer,
                                   counter.size);
  pinweaver_eal_hmac_sha256_update(&hmac, label->buffer,
                                   label->size);
  pinweaver_eal_hmac_sha256_update(&hmac, nonce_newer->buffer,
                                   nonce_newer->size);
  pinweaver_eal_hmac_sha256_update(&hmac, nonce_older->buffer,
                                   nonce_older->size);
  pinweaver_eal_hmac_sha256_update(&hmac, digest_size_bits.buffer,
                                   digest_size_bits.size);
  pinweaver_eal_hmac_sha256_final(&hmac, key);

  return true;
}

// This method performs an AES operation using a 128 bit key.
// |operation_type| can be either AES_ENCRYPT or AES_DECRYPT and it
// determines if the operation is an encryption or decryption.
static bool AesOperation(
    HmacAuthorizationDelegate* delegate,
    src_data_buf_t* parameter,
    const TPM2B_NONCE& nonce_newer,
    const TPM2B_NONCE& nonce_older,
    int operation_type) {
  if (parameter->size > kMaxDecryptSize) {
    return false;
  }
  const src_data_buf_t kLabelCFB = {kLabelSize, (uint8_t *)"CFB"};
  hmac_key_t hmac_key;
  HmacKeyInit(&hmac_key);
  HmacKeyAppend(&hmac_key, &delegate->session_key_);
  HmacKeyAppend(&hmac_key, &delegate->entity_authorization_value_);
  uint8_t compound_key[kSessionKeySize];
  if (!CreateKey(delegate,
                &hmac_key,
                &kLabelCFB,
                &nonce_newer,
                &nonce_older,
                compound_key)) {
    return false;
  }
  unsigned char aes_key[kAesKeySize];
  unsigned char aes_iv[kAesIVSize];
  memcpy(aes_key, &compound_key[0], kAesKeySize);
  memcpy(aes_iv, &compound_key[kAesKeySize], kAesIVSize);
  unsigned char decrypted[kMaxDecryptSize];
  if (pinweaver_eal_aes128_cfb(aes_key, kAesKeySize, aes_iv,
                               parameter->buffer, parameter->size,
                               operation_type, decrypted) != 0) {
    return false;
  }
  memcpy(parameter->buffer, decrypted, parameter->size);
  return true;
}

// This method regenerates the caller nonce. The new nonce is the same
// length as the previous nonce. The buffer is filled with random data.
// NOTE: This operation is DESTRUCTIVE, and rewrites the caller_nonce_ field.
static void RegenerateCallerNonce(HmacAuthorizationDelegate* delegate) {
  // nonce_size is guaranteed to be less than 32 bytes and greater than 16.
  pinweaver_eal_rand_bytes(delegate->caller_nonce_.buffer,
                           delegate->caller_nonce_.size);
}

bool GetCommandAuthorizationHmac(
    HmacAuthorizationDelegate* delegate,
    const src_data_buf_t* command_hash,
    bool is_command_parameter_encryption_possible,
    bool is_response_parameter_encryption_possible,
    dst_data_buf_t* authorization) {
  if (!delegate->session_handle_) {
    authorization->size = 0;
    return false;
  }
  TPMS_AUTH_COMMAND auth;
  auth.session_handle = delegate->session_handle_;
  if (!delegate->nonce_generated_) {
    RegenerateCallerNonce(delegate);
  }
  auth.nonce = delegate->caller_nonce_;
  auth.session_attributes = kContinueSession;
  if (delegate->is_parameter_encryption_enabled_) {
    if (is_command_parameter_encryption_possible) {
      auth.session_attributes |= kDecryptSession;
    }
    if (is_response_parameter_encryption_possible) {
      auth.session_attributes |= kEncryptSession;
    }
  }
  // We reset the |nonce_generated| flag in preparation of the next command.
  delegate->nonce_generated_ = false;
  UINT8 attributes_bytes_buf;
  dst_data_buf_t attributes_bytes = {sizeof(attributes_bytes_buf), 0,
                                     &attributes_bytes_buf};
  if (Serialize_TPMA_SESSION(&auth.session_attributes, &attributes_bytes) !=
      TPM_RC_SUCCESS) {
    return false;
  }

  hmac_key_t hmac_key;
  HmacKeyInit(&hmac_key);
  HmacKeyAppend(&hmac_key, &delegate->session_key_);
  if (!delegate->use_entity_authorization_for_encryption_only_) {
    HmacKeyAppend(&hmac_key, &delegate->entity_authorization_value_);
  }
  pinweaver_eal_hmac_sha256_ctx_t hmac;
  pinweaver_eal_hmac_sha256_init(&hmac, hmac_key.buffer, hmac_key.size);
  pinweaver_eal_hmac_sha256_update(&hmac,
                                   command_hash->buffer,
                                   command_hash->size);
  pinweaver_eal_hmac_sha256_update(&hmac,
                                   delegate->caller_nonce_.buffer,
                                   delegate->caller_nonce_.size);
  pinweaver_eal_hmac_sha256_update(&hmac,
                                   delegate->tpm_nonce_.buffer,
                                   delegate->tpm_nonce_.size);
  pinweaver_eal_hmac_sha256_update(&hmac,
                                   attributes_bytes.buffer,
                                   attributes_bytes.size);
  pinweaver_eal_hmac_sha256_final(&hmac, auth.hmac.buffer);
  auth.hmac.size = SHA256_DIGEST_LENGTH;

  TPM_RC serialize_error = Serialize_TPMS_AUTH_COMMAND(&auth, authorization);
  if (serialize_error != TPM_RC_SUCCESS) {
    return false;
  }
  return true;
}

bool CheckResponseAuthorizationHmac(
    HmacAuthorizationDelegate* delegate,
    const src_data_buf_t* response_hash,
    const src_data_buf_t* authorization) {
  if (!delegate->session_handle_) {
    return false;
  }
  TPMS_AUTH_RESPONSE auth_response;
  src_data_buf_t mutable_auth_string = {authorization->size,
                                        authorization->buffer};
  TPM_RC parse_error;
  parse_error = Parse_TPMS_AUTH_RESPONSE(&mutable_auth_string, &auth_response,
                                         NULL);
  if (parse_error != TPM_RC_SUCCESS) {
    return false;
  }
  if (mutable_auth_string.size != 0) {
    return false;
  }
  if (auth_response.hmac.size != kHashDigestSize) {
    return false;
  }
  if (auth_response.nonce.size < kNonceMinSize ||
      auth_response.nonce.size > kNonceMaxSize) {
    return false;
  }
  delegate->tpm_nonce_ = auth_response.nonce;
  UINT8 attributes_bytes_buf;
  dst_data_buf_t attributes_bytes = {sizeof(attributes_bytes_buf), 0,
                                     &attributes_bytes_buf};
  if (Serialize_TPMA_SESSION(&auth_response.session_attributes,
                             &attributes_bytes) != TPM_RC_SUCCESS) {
    return false;
  }

  hmac_key_t hmac_key;
  HmacKeyInit(&hmac_key);
  HmacKeyAppend(&hmac_key, &delegate->session_key_);
  if (!delegate->use_entity_authorization_for_encryption_only_) {
    // In a special case with TPM2_HierarchyChangeAuth, we need to use the
    // auth_value that was set.
    if (delegate->future_authorization_value_set_) {
      HmacKeyAppend(&hmac_key, &delegate->future_authorization_value_);
      delegate->future_authorization_value_set_ = false;
    } else {
      HmacKeyAppend(&hmac_key, &delegate->entity_authorization_value_);
    }
  }

  pinweaver_eal_hmac_sha256_ctx_t hmac;
  unsigned char digest[SHA256_DIGEST_LENGTH];

  pinweaver_eal_hmac_sha256_init(&hmac, hmac_key.buffer, hmac_key.size);
  pinweaver_eal_hmac_sha256_update(&hmac, response_hash->buffer,
                                   response_hash->size);
  pinweaver_eal_hmac_sha256_update(&hmac, delegate->tpm_nonce_.buffer,
                                   delegate->tpm_nonce_.size);
  pinweaver_eal_hmac_sha256_update(&hmac, delegate->caller_nonce_.buffer,
                                   delegate->caller_nonce_.size);
  pinweaver_eal_hmac_sha256_update(&hmac, attributes_bytes.buffer,
                                   attributes_bytes.size);
  pinweaver_eal_hmac_sha256_final(&hmac, digest);

  if (!pinweaver_eal_safe_memcmp(digest, auth_response.hmac.buffer,
                                 SHA256_DIGEST_LENGTH)) {
    return false;
  }
  return true;
}

bool EncryptCommandParameterHmac(
    HmacAuthorizationDelegate* delegate,
    src_data_buf_t* parameter) {
  if (!delegate->session_handle_) {
    return false;
  }
  if (!delegate->is_parameter_encryption_enabled_) {
    // No parameter encryption enabled.
    return true;
  }
  RegenerateCallerNonce(delegate);
  delegate->nonce_generated_ = true;
  return AesOperation(delegate, parameter,
                      delegate->caller_nonce_, delegate->tpm_nonce_,
                      PINWEAVER_EAL_ENCRYPT);
}

bool DecryptResponseParameterHmac(
    HmacAuthorizationDelegate* delegate,
    src_data_buf_t* parameter) {
  if (!delegate->session_handle_) {
    return false;
  }
  if (!delegate->is_parameter_encryption_enabled_) {
    // No parameter decryption enabled.
    return true;
  }
  return AesOperation(delegate, parameter,
                      delegate->tpm_nonce_, delegate->caller_nonce_,
                      PINWEAVER_EAL_DECRYPT);
}

bool GetTpmNonceHmac(
    HmacAuthorizationDelegate* delegate,
    dst_data_buf_t* nonce) {
  if (!delegate->tpm_nonce_.size)
    return false;
  if (nonce->max_size < delegate->tpm_nonce_.size)
    return false;
  memcpy(nonce->buffer, &delegate->tpm_nonce_.buffer,
         delegate->tpm_nonce_.size);
  nonce->size = delegate->tpm_nonce_.size;
  return true;
}

bool InitSession(
    HmacAuthorizationDelegate* delegate,
    TPM_HANDLE session_handle,
    const TPM2B_NONCE* tpm_nonce,
    const TPM2B_NONCE* caller_nonce,
    const TPM2B_DIGEST* salt,
    const TPM2B_DIGEST* bind_auth_value,
    bool enable_parameter_encryption) {
  memset((void *)delegate, 0, sizeof(HmacAuthorizationDelegate));
  delegate->session_handle_ = session_handle;
  if (caller_nonce->size < kNonceMinSize
      || caller_nonce->size > kNonceMaxSize
      || tpm_nonce->size < kNonceMinSize
      || tpm_nonce->size > kNonceMaxSize) {
    return false;
  }
  memcpy(&delegate->tpm_nonce_, tpm_nonce, sizeof(TPM2B_NONCE));
  memcpy(&delegate->caller_nonce_, caller_nonce, sizeof(TPM2B_NONCE));
  delegate->is_parameter_encryption_enabled_ = enable_parameter_encryption;
  if (salt->size == 0 && bind_auth_value->size == 0) {
    // SessionKey is set to the empty string for unsalted and
    // unbound sessions.
    delegate->session_key_.size = 0;
  } else {
    src_data_buf_t kLabelATH = {kLabelSize, (uint8_t *)"ATH"};
    hmac_key_t hmac_key;
    HmacKeyInit(&hmac_key);
    HmacKeyAppend(&hmac_key, bind_auth_value);
    HmacKeyAppend(&hmac_key, salt);
    if (!CreateKey(delegate, &hmac_key, &kLabelATH,
                   &delegate->tpm_nonce_, &delegate->caller_nonce_,
                   delegate->session_key_.buffer)) {
      return false;
    }
    delegate->session_key_.size = kSessionKeySize;
  }
  return true;
}