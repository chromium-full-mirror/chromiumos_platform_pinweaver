/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/sysinfo.h>

#include "pinweaver_eal.h"
#include "pinweaver_eal_tpm.h"

int pinweaver_eal_sha256_init(pinweaver_eal_sha256_ctx_t *ctx)
{
	return SHA256_Init(ctx);
}

int pinweaver_eal_sha256_update(pinweaver_eal_sha256_ctx_t *ctx,
				const void *data,
				size_t size)
{
	return SHA256_Update(ctx, data, size);
}

int pinweaver_eal_sha256_final(pinweaver_eal_sha256_ctx_t *ctx,
			       void *res)
{
	return SHA256_Final(res, ctx);
}

int pinweaver_eal_hmac_sha256_init(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				   const void *key,
				   size_t key_size /* in bytes */)
{
	*ctx = HMAC_CTX_new();
	if (!*ctx)
		return -1;
	return HMAC_Init_ex(*ctx, key, key_size, EVP_sha256(), NULL);
}
int pinweaver_eal_hmac_sha256_update(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				     const void *data,
				     size_t size)
{
	return HMAC_Update(*ctx, data, size);
}

int pinweaver_eal_hmac_sha256_final(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				    void *res)
{
	unsigned int len;
	int rv = HMAC_Final(*ctx, res, &len);
	HMAC_CTX_free(*ctx);
	*ctx = NULL;
	return rv;
}

int pinweaver_eal_aes256_ctr(const void *key,
			     size_t key_size, /* in bytes */
			     const void *iv,
			     const void *data,
			     size_t size,
			     void *res)
{
	EVP_CIPHER_CTX *ctx;
	int rv;
	int len, len_final;

	if (key_size != 256/8)
		return -1;
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return -1;
	rv = EVP_EncryptInit(ctx, EVP_aes_256_ctr(), key, iv);
	if (rv)
		goto out;
	rv = EVP_EncryptUpdate(ctx, res, &len, data, size);
	if (rv)
		goto out;
	rv = EVP_EncryptFinal(ctx, res+len, &len_final);
out:
	EVP_CIPHER_CTX_free(ctx);
	return rv;
}

int pinweaver_eal_aes128_cfb(const void *key,
			     size_t key_size, /* in bytes */
			     const void *iv,
			     const void *data,
			     size_t size,
			     int op_type, /* PINWEAVER_EAL_{DE|EN}CRYPT */
			     void *res)
{
	EVP_CIPHER_CTX *ctx;
	int rv;
	int len, len_final;

	if (key_size != 128/8)
		return -1;
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return -1;
	switch (op_type) {
		case PINWEAVER_EAL_DECRYPT:
			rv = EVP_DecryptInit(ctx, EVP_aes_128_cfb(), key, iv);
			if (rv)
				break;
			rv = EVP_DecryptUpdate(ctx, res, &len, data, size);
			if (rv)
				break;
			rv = EVP_DecryptFinal(ctx, res+len, &len_final);
			break;
		case PINWEAVER_EAL_ENCRYPT:
			rv = EVP_EncryptInit(ctx, EVP_aes_128_cfb(), key, iv);
			if (rv)
				break;
			rv = EVP_EncryptUpdate(ctx, res, &len, data, size);
			if (rv)
				break;
			rv = EVP_EncryptFinal(ctx, res+len, &len_final);
			break;
		default:
			rv = -1;
	}
	EVP_CIPHER_CTX_free(ctx);
	return rv;
}


int pinweaver_eal_safe_memcmp(const void *s1, const void *s2, size_t len)
{
	const uint8_t *us1 = s1;
	const uint8_t *us2 = s2;
	int result = 0;

	while (len--)
		result |= *us1++ ^ *us2++;

	return result != 0;
}

int pinweaver_eal_rand_bytes(void *buf, size_t size)
{
	return RAND_bytes(buf, size);
}

uint64_t pinweaver_eal_seconds_since_boot()
{
	struct sysinfo si;
	if (sysinfo(&si))
		return 0;

	return (uint64_t)si.uptime;
}

int pinweaver_eal_get_device_key(int kind,
		void* key /* 256-bit */)
{
	/* TODO */
	return 0;
}

uint8_t pinweaver_eal_get_current_pcr_digest(
		const uint8_t bitmask[2],
		uint8_t sha256_of_selected_pcr[32])
{
	/* TODO */
	return 0;
}

