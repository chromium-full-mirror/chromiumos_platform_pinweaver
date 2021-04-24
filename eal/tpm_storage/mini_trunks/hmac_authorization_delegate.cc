// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstring>

#include "authorization_delegate.h"
#include "eal.h"
#include "eal_tpm.h"
#include "tpm_generated.h"

const uint32_t kDigestBits = 256;
const uint16_t kNonceMinSize = 16;
const uint16_t kNonceMaxSize = 32;
const uint8_t kDecryptSession = 1 << 5;
const uint8_t kEncryptSession = 1 << 6;
const uint8_t kLabelSize = 4;
const size_t kAesKeySize = 16;      // 128 bits is minimum AES key size.
const size_t kAesIVSize = 16;
const uint32_t kTpmBufferSize = 4096;
const uint8_t kContinueSession = 1;
const size_t kHashDigestSize = 32;  // 256 bits is SHA256 digest size.

// This method performs a FIPS198 HMAC operation on |data| using |key|
static std::string HmacSha256(
    const std::string& key,
    const std::string& data) {
	pinweaver_eal_hmac_sha256_ctx_t hmac;
  unsigned char digest[SHA256_DIGEST_LENGTH];

	pinweaver_eal_hmac_sha256_init(&hmac, key.data(), key.size());
	pinweaver_eal_hmac_sha256_update(&hmac, data.data(), data.size());
	pinweaver_eal_hmac_sha256_final(&hmac, digest);

  return std::string(reinterpret_cast<char*>(digest), SHA256_DIGEST_LENGTH);
}

// This method implements the key derivation function used in the TPM.
// NOTE: It only returns 32 byte keys.
static std::string CreateKey(
    HmacAuthorizationDelegate* delegate,
    const std::string& hmac_key,
    const std::string& label,
    const TPM2B_NONCE& nonce_newer,
    const TPM2B_NONCE& nonce_older) {
  std::string counter;
  std::string digest_size_bits;
  if (Serialize_uint32_t(1, &counter) != TPM_RC_SUCCESS ||
      Serialize_uint32_t(kDigestBits, &digest_size_bits) != TPM_RC_SUCCESS) {
    return std::string();
  }

  std::string data;
  data.append(counter);
  data.append(label);
  data.append(reinterpret_cast<const char*>(nonce_newer.buffer),
              nonce_newer.size);
  data.append(reinterpret_cast<const char*>(nonce_older.buffer),
              nonce_older.size);
  data.append(digest_size_bits);
  std::string key = HmacSha256(hmac_key, data);
  return key;
}

// This method performs an AES operation using a 128 bit key.
// |operation_type| can be either AES_ENCRYPT or AES_DECRYPT and it
// determines if the operation is an encryption or decryption.
static void AesOperation(
    HmacAuthorizationDelegate* delegate,
    std::string* parameter,
    const TPM2B_NONCE& nonce_newer,
    const TPM2B_NONCE& nonce_older,
    int operation_type) {
  std::string label("CFB", kLabelSize);
  std::string compound_key =
      CreateKey(delegate,
                delegate->session_key_ + delegate->entity_authorization_value_, 
                label, nonce_newer,
                nonce_older);
  unsigned char aes_key[kAesKeySize];
  unsigned char aes_iv[kAesIVSize];
  memcpy(aes_key, &compound_key[0], kAesKeySize);
  memcpy(aes_iv, &compound_key[kAesKeySize], kAesIVSize);
  unsigned char decrypted[kTpmBufferSize];
  pinweaver_eal_aes128_cfb(aes_key, kAesKeySize, aes_iv,
                           parameter->data(), parameter->size(), operation_type,
                           decrypted);
  char* dest = const_cast<char *>(parameter->data());
  memcpy(dest, decrypted, parameter->size());
}

// This method regenerates the caller nonce. The new nonce is the same
// length as the previous nonce. The buffer is filled with random data using
// openssl's |RAND_bytes| function.
// NOTE: This operation is DESTRUCTIVE, and rewrites the delegate->caller_nonce_ field.
static void RegenerateCallerNonce(HmacAuthorizationDelegate* delegate) {
  // RAND_bytes takes a signed number, but since nonce_size is guaranteed to be
  // less than 32 bytes and greater than 16 we dont have to worry about it.
  pinweaver_eal_rand_bytes(delegate->caller_nonce_.buffer, delegate->caller_nonce_.size);
}

// HmacAuthorizationDelegate::HmacAuthorizationDelegate()
//     : delegate->session_handle_(0),
//       delegate->is_parameter_encryption_enabled_(false),
//       delegate->nonce_generated_(false),
//       delegate->future_authorization_value_set_(false),
//       delegate->use_entity_authorization_for_encryption_only_(false) {
//   delegate->tpm_nonce_.size = 0;
//   delegate->caller_nonce_.size = 0;
// }

bool GetCommandAuthorizationHmac(
    HmacAuthorizationDelegate* delegate,
    const std::string& command_hash,
    bool is_command_parameter_encryption_possible,
    bool is_response_parameter_encryption_possible,
    std::string* authorization) {
  if (!delegate->session_handle_) {
    authorization->clear();
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
  std::string attributes_bytes;
  if (Serialize_TPMA_SESSION(auth.session_attributes, &attributes_bytes) !=
      TPM_RC_SUCCESS) {
    return false;
  }

  std::string hmac_data;
  std::string hmac_key;
  if (!delegate->use_entity_authorization_for_encryption_only_) {
    hmac_key = delegate->session_key_ + delegate->entity_authorization_value_;
  } else {
    hmac_key = delegate->session_key_;
  }
  hmac_data.append(command_hash);
  hmac_data.append(reinterpret_cast<const char*>(delegate->caller_nonce_.buffer),
                   delegate->caller_nonce_.size);
  hmac_data.append(reinterpret_cast<const char*>(delegate->tpm_nonce_.buffer),
                   delegate->tpm_nonce_.size);
  hmac_data.append(attributes_bytes);
  std::string digest = HmacSha256(hmac_key, hmac_data);

  auth.hmac.size = digest.size();
  memcpy(auth.hmac.buffer, digest.data(), digest.size());

  TPM_RC serialize_error = Serialize_TPMS_AUTH_COMMAND(auth, authorization);
  if (serialize_error != TPM_RC_SUCCESS) {
    return false;
  }
  return true;
}

bool CheckResponseAuthorizationHmac(
    HmacAuthorizationDelegate* delegate,
    const std::string& response_hash,
    const std::string& authorization) {
  if (!delegate->session_handle_) {
    return false;
  }
  TPMS_AUTH_RESPONSE auth_response;
  std::string mutable_auth_string(authorization);
  TPM_RC parse_error;
  std::string auth_bytes;
  parse_error = Parse_TPMS_AUTH_RESPONSE(&mutable_auth_string, &auth_response,
                                         &auth_bytes);
  if (authorization.size() != auth_bytes.size()) {
    return false;
  }
  if (parse_error != TPM_RC_SUCCESS) {
    return false;
  }
  if (!mutable_auth_string.empty()) {
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
  std::string attributes_bytes;
  if (Serialize_TPMA_SESSION(auth_response.session_attributes,
                             &attributes_bytes) != TPM_RC_SUCCESS) {
    return false;
  }

  std::string hmac_data;
  std::string hmac_key;
  if (!delegate->use_entity_authorization_for_encryption_only_) {
    // In a special case with TPM2_HierarchyChangeAuth, we need to use the
    // auth_value that was set.
    if (delegate->future_authorization_value_set_) {
      hmac_key = delegate->session_key_ + delegate->future_authorization_value_;
      delegate->future_authorization_value_set_ = false;
    } else {
      hmac_key = delegate->session_key_ + delegate->entity_authorization_value_;
    }
  } else {
    hmac_key = delegate->session_key_;
  }
  hmac_data.append(response_hash);
  hmac_data.append(reinterpret_cast<const char*>(delegate->tpm_nonce_.buffer),
                   delegate->tpm_nonce_.size);
  hmac_data.append(reinterpret_cast<const char*>(delegate->caller_nonce_.buffer),
                   delegate->caller_nonce_.size);
  hmac_data.append(attributes_bytes);
  std::string digest = HmacSha256(hmac_key, hmac_data);
  if (!pinweaver_eal_safe_memcmp(digest.data(), auth_response.hmac.buffer,
                                 digest.size())) {
    return false;
  }
  return true;
}

bool EncryptCommandParameterHmac(
    HmacAuthorizationDelegate* delegate,
    std::string* parameter) {
  if (!delegate->session_handle_) {
    return false;
  }
  if (!delegate->is_parameter_encryption_enabled_) {
    // No parameter encryption enabled.
    return true;
  }
  if (parameter->size() > kTpmBufferSize) {
    return false;
  }
  RegenerateCallerNonce(delegate);
  delegate->nonce_generated_ = true;
  AesOperation(delegate, parameter,
               delegate->caller_nonce_, delegate->tpm_nonce_,
               PINWEAVER_EAL_ENCRYPT);
  return true;
}

bool DecryptResponseParameterHmac(
    HmacAuthorizationDelegate* delegate,
    std::string* parameter) {
  if (!delegate->session_handle_) {
    return false;
  }
  if (!delegate->is_parameter_encryption_enabled_) {
    // No parameter decryption enabled.
    return true;
  }
  if (parameter->size() > kTpmBufferSize) {
    return false;
  }
  AesOperation(delegate, parameter,
               delegate->tpm_nonce_, delegate->caller_nonce_,
               PINWEAVER_EAL_DECRYPT);
  return true;
}

bool GetTpmNonceHmac(
    HmacAuthorizationDelegate* delegate,
    std::string* nonce) {
  if (!delegate->tpm_nonce_.size)
    return false;
  nonce->assign(delegate->tpm_nonce_.buffer, delegate->tpm_nonce_.buffer + delegate->tpm_nonce_.size);
  return true;
}

bool InitSession(
    HmacAuthorizationDelegate* delegate,
    TPM_HANDLE session_handle,
    const TPM2B_NONCE& tpm_nonce,
    const TPM2B_NONCE& caller_nonce,
    const std::string& salt,
    const std::string& bind_auth_value,
    bool enable_parameter_encryption) {
  delegate->session_handle_ = session_handle;
  if (caller_nonce.size < kNonceMinSize || caller_nonce.size > kNonceMaxSize ||
      tpm_nonce.size < kNonceMinSize || tpm_nonce.size > kNonceMaxSize) {
    return false;
  }
  delegate->tpm_nonce_ = tpm_nonce;
  delegate->caller_nonce_ = caller_nonce;
  std::string session_key_label("ATH", kLabelSize);
  delegate->is_parameter_encryption_enabled_ = enable_parameter_encryption;
  if (salt.length() == 0 && bind_auth_value.length() == 0) {
    // SessionKey is set to the empty string for unsalted and
    // unbound sessions.
    delegate->session_key_ = std::string();
  } else {
    delegate->session_key_ =
        CreateKey(delegate, bind_auth_value + salt, session_key_label,
                  delegate->tpm_nonce_, delegate->caller_nonce_);
  }
  return true;
}