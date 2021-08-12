// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "fuzzer_provider.h"

extern "C" {
#include "pinweaver_eal.h"
#include "pinweaver_eal_tpm.h"
} // extern "C"

extern "C" {

void pinweaver_eal_send_command_and_wait(const char *request, char *response) {
  // TODO: fuzz commands
}

int pinweaver_eal_sha256_init(pinweaver_eal_sha256_ctx_t *ctx) {
  if (g_data_provider->ConsumeBool())
    return -1;
  int rv = SHA256_Init(ctx);
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_sha256_update(pinweaver_eal_sha256_ctx_t *ctx,
                                const void *data, size_t size) {
  if (g_data_provider->ConsumeBool())
    return -1;
  int rv = SHA256_Update(ctx, data, size);
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_sha256_final(pinweaver_eal_sha256_ctx_t *ctx, void *res) {
  if (g_data_provider->ConsumeBool())
    return -1;
  int rv = SHA256_Final((unsigned char *)res, ctx);
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_hmac_sha256_init(pinweaver_eal_hmac_sha256_ctx_t *ctx,
                                   const void *key,
                                   size_t key_size /* in bytes */) {
  if (g_data_provider->ConsumeBool())
    return -1;
  *ctx = HMAC_CTX_new();
  if (!*ctx) {
    return -1;
  }
  int rv = HMAC_Init_ex(*ctx, key, key_size, EVP_sha256(), NULL);
  return rv == 1 ? 0 : -1;
}
int pinweaver_eal_hmac_sha256_update(pinweaver_eal_hmac_sha256_ctx_t *ctx,
                                     const void *data, size_t size) {
  if (g_data_provider->ConsumeBool())
    return -1;
  int rv = HMAC_Update(*ctx, (const unsigned char *)data, size);
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_hmac_sha256_final(pinweaver_eal_hmac_sha256_ctx_t *ctx,
                                    void *res) {
  if (g_data_provider->ConsumeBool())
    return -1;
  unsigned int len;
  int rv = HMAC_Final(*ctx, (unsigned char *)res, &len);
  HMAC_CTX_free(*ctx);
  *ctx = NULL;
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_aes128_cfb(const void *key, size_t key_size, /* in bytes */
                             const void *iv, const void *data, size_t size,
                             int op_type, /* PINWEAVER_EAL_{DE|EN}CRYPT */
                             void *res) {
  if (g_data_provider->ConsumeBool())
    return -1;

  EVP_CIPHER_CTX *ctx;
  int rv;
  int len, len_final;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return -1;
  switch (op_type) {
  case PINWEAVER_EAL_DECRYPT:
    rv = EVP_DecryptInit(ctx, EVP_aes_128_cfb(), (const unsigned char *)key,
                         (const unsigned char *)iv);
    if (rv != 1)
      break;
    rv = EVP_DecryptUpdate(ctx, (unsigned char *)res, &len,
                           (const unsigned char *)data, size);
    if (rv != 1)
      break;
    rv = EVP_DecryptFinal(ctx, ((unsigned char *)res) + len, &len_final);
    break;
  case PINWEAVER_EAL_ENCRYPT:
    rv = EVP_EncryptInit(ctx, EVP_aes_128_cfb(), (const unsigned char *)key,
                         (const unsigned char *)iv);
    if (rv != 1)
      break;
    rv = EVP_EncryptUpdate(ctx, (unsigned char *)res, &len,
                           (const unsigned char *)data, size);
    if (rv != 1)
      break;
    rv = EVP_EncryptFinal(ctx, ((unsigned char *)res) + len, &len_final);
    break;
  default:
    rv = 0;
  }
  EVP_CIPHER_CTX_free(ctx);
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_safe_memcmp(const void *s1, const void *s2, size_t len) {
  if (g_data_provider->ConsumeBool()) {
    return g_data_provider->ConsumeIntegralInRange(-1, 1);
  }
  return memcmp(s1, s2, len);
}

int pinweaver_eal_rand_bytes(void *buf, size_t size) {
  if (g_data_provider->ConsumeBool())
    return -1;
  std::string str = g_data_provider->ConsumeBytesAsString(size);
  memcpy(buf, str.data(), size);
  return 0;
}

int pinweaver_eal_memcpy_s(
    void * dest,
    size_t destsz,
    const void * src,
    size_t count
) {
	if (count == 0)
		return 0;

	if (dest == NULL) {
		abort();
  }

	if (src == NULL) {
		memset(dest, 0, destsz);
		abort();
	}

	if (destsz < count) {
		memset(dest, 0, destsz);
		abort();
	}

  memcpy(dest, src, count);
  return 0;
}

} // extern "C"
