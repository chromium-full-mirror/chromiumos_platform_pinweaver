
/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __PINWEAVER_EAL_H
#define __PINWEAVER_EAL_H

#include <stddef.h>

#include "pinweaver.h"
#include "pinweaver_eal_types.h"

#ifndef PINWEAVER_EAL_INFO
#define PINWEAVER_EAL_INFO(...)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Implements memcpy_s on all platforms
 */
int pinweaver_eal_memcpy_s(
    void * dest,
    size_t destsz,
    const void * src,
    size_t count
);

/*
 * Derives wrap_key and hmac_key based on key_derivation_nonce.
 * Returns 0 on success.
 */
int pinweaver_eal_derive_keys(struct merkle_tree_t *merkle_tree);

/*
 * Functions for calculating SHA-256.
 * Returns 0 on success.
 */
int pinweaver_eal_sha256_init(pinweaver_eal_sha256_ctx_t *ctx);
int pinweaver_eal_sha256_update(pinweaver_eal_sha256_ctx_t *ctx,
				const void *data,
				size_t size);
int pinweaver_eal_sha256_final(pinweaver_eal_sha256_ctx_t *ctx,
			       void *res);

/*
 * Functions for calculating HMAC SHA-256.
 * Only 256 bit key size is used.
 * Returns 0 on success.
 */
int pinweaver_eal_hmac_sha256_init(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				   const void *key,
				   size_t key_size /* in bytes */);
int pinweaver_eal_hmac_sha256_update(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				     const void *data,
				     size_t size);
int pinweaver_eal_hmac_sha256_final(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				    void *res);

/*
 * Perform AES-256 CTR.
 * Only 256 bit key size is used.
 * Returns 0 on success.
 */
int pinweaver_eal_aes256_ctr(const void *key,
			     size_t key_size, /* in bytes */
			     const void *iv,
			     const void *data,
			     size_t size,
			     void *res);


/*
 * Constant time implementation of memcmp to avoid timing side channels.
 */
int pinweaver_eal_safe_memcmp(const void *s1, const void *s2, size_t len);

/*
 * Get random bytes.
 * Returns 0 on success.
 */
int pinweaver_eal_rand_bytes(void *buf, size_t size);

/*
 * Get number of seconds since cold boot.
 */
uint64_t pinweaver_eal_seconds_since_boot();

/*
 * Functions for calculating SHA256 of the values of the selected PCRs.
 * Returns 0 on success.
 */
uint8_t pinweaver_eal_get_current_pcr_digest(
		const uint8_t bitmask[2],
		uint8_t sha256_of_selected_pcr[32]);

/*
 * Storage functions.
 * Return 0 on success.
 */
int pinweaver_eal_storage_start();
int pinweaver_eal_storage_init_state(uint8_t root_hash[PW_HASH_SIZE],
				     uint32_t *restart_count);

int pinweaver_eal_storage_get_log(struct pw_log_storage_t *dest);
int pinweaver_eal_storage_set_log(const struct pw_log_storage_t *log);

int pinweaver_eal_storage_get_tree_data(struct pw_long_term_storage_t *dest);
int pinweaver_eal_storage_set_tree_data(
		const struct pw_long_term_storage_t *data);

#ifdef __cplusplus
}
#endif

#endif  /* __PINWEAVER_EAL_H */
