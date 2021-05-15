/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <common.h>
#include <extension.h>
#include <hooks.h>
#include <nvmem_vars.h>
#include <pinweaver_eal.h>
#include <timer.h>
#include <tpm_vendor_cmds.h>
#include <trng.h>
#include <tpm_registers.h>
#include <util.h>

/* Make sure the largest possible message would fit in
 * (struct tpm_register_file).data_fifo.
 */
BUILD_ASSERT(PW_MAX_MESSAGE_SIZE + sizeof(struct tpm_cmd_header) <= 2048);

int pinweaver_eal_derive_keys(struct merkle_tree_t *merkle_tree)
{
	struct APPKEY_CTX ctx;
	int ret = EC_SUCCESS;
	const uint32_t KEY_TYPE_AES = 0x0;
	const uint32_t KEY_TYPE_HMAC = 0xffffffff;
	union {
		uint32_t v[8];
		uint8_t bytes[sizeof(uint32_t) * 8];
	} input;
	uint32_t type_field;
	size_t seed_size = sizeof(input);
	size_t x;

	get_storage_seed(input.v, &seed_size);
	for (x = 0; x < ARRAY_SIZE(input.bytes) &&
		    x < ARRAY_SIZE(merkle_tree->key_derivation_nonce); ++x)
		input.bytes[x] ^= merkle_tree->key_derivation_nonce[x];
	type_field = input.v[6];

	if (!DCRYPTO_appkey_init(PINWEAVER, &ctx))
		return PW_ERR_CRYPTO_FAILURE;

	input.v[6] = type_field ^ KEY_TYPE_AES;
	if (!DCRYPTO_appkey_derive(PINWEAVER, input.v,
				  (uint32_t *)merkle_tree->wrap_key)) {
		ret = PW_ERR_CRYPTO_FAILURE;
		goto cleanup;
	}

	input.v[6] = type_field ^ KEY_TYPE_HMAC;
	if (!DCRYPTO_appkey_derive(PINWEAVER, input.v,
				  (uint32_t *)merkle_tree->hmac_key)) {
		ret = PW_ERR_CRYPTO_FAILURE;
	}
cleanup:
	DCRYPTO_appkey_finish(&ctx);
	return ret;
}

int pinweaver_eal_sha256_init(pinweaver_eal_sha256_ctx_t *ctx)
{
	DCRYPTO_SHA256_init(ctx, 0);
	return 0;
}

int pinweaver_eal_sha256_update(pinweaver_eal_sha256_ctx_t *ctx,
				const void *data,
				size_t size)
{
	HASH_update(ctx, data, size);
	return 0;
}

int pinweaver_eal_sha256_final(pinweaver_eal_sha256_ctx_t *ctx,
			       void *res)
{
	memcpy(res, HASH_final(ctx), SHA256_DIGEST_SIZE);
	return 0;
}

int pinweaver_eal_hmac_sha256_init(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				   const void *key,
				   size_t key_size /* in bytes */)
{
	if (key_size != 256/8)
		return -1;
	DCRYPTO_HMAC_SHA256_init(ctx, key, key_size);
	return 0;
}
int pinweaver_eal_hmac_sha256_update(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				     const void *data,
				     size_t size)
{
	HASH_update(&(ctx->hash), data, size);
	return 0;
}

int pinweaver_eal_hmac_sha256_final(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				    void *res)
{
	memcpy(res, DCRYPTO_HMAC_final(ctx), SHA256_DIGEST_SIZE);
	return 0;
}

int pinweaver_eal_aes256_ctr(const void *key,
			     size_t key_size, /* in bytes */
			     const void *iv,
			     const void *data,
			     size_t size,
			     void *res)
{
	return DCRYPTO_aes_ctr(res, key, key_size << 3, iv, data, size) == 1 ? 0 : -1;
}

int pinweaver_eal_safe_memcmp(const void *s1, const void *s2, size_t len)
{
	return safe_memcmp(s1, s2, len);
}

int pinweaver_eal_rand_bytes(void *buf, size_t size)
{
	rand_bytes(buf, size);
	return 0;
}

uint64_t pinweaver_eal_seconds_since_boot()
{
	return get_time().val / SECOND;
}

int pinweaver_eal_storage_start()
{
	return 0;
}

static int pinweaver_eal_storage_get_log_var(struct tuple **var_ptr,
					     struct pw_log_storage_t **log_ptr)
{
	struct pw_log_storage_t *log;
	struct tuple *ptr;

	*var_ptr = NULL;
	*log_ptr = NULL;

	ptr = getvar(PW_LOG_VAR0, sizeof(PW_LOG_VAR0) - 1);
	if (!ptr)
		return PW_ERR_NV_EMPTY;

	log = (void *)tuple_val(ptr);
	/* Add storage format updates here. */
	if (ptr->val_len != sizeof(struct pw_log_storage_t)) {
		freevar(ptr);
		return PW_ERR_NV_LENGTH_MISMATCH;
	}
	if (log->storage_version != PW_STORAGE_VERSION) {
		freevar(ptr);
		return PW_ERR_NV_VERSION_MISMATCH;
	}

	*var_ptr = ptr;
	*log_ptr = log;
	return EC_SUCCESS;
}

int pinweaver_eal_storage_init_state(uint8_t *root_hash,
				     uint32_t *restart_count)
{
	struct tuple *var;
	struct pw_log_storage_t *log;

	ret = pinweaver_eal_storage_get_log_var(&var, &log);
	if (ret != EC_SUCCESS)
		return ret;

	memcpy(root_hash, log->entries[0].root, PW_HASH_SIZE);

	/* This forces an NVRAM write for hard reboots for which the
	 * timer value gets reset. The TPM restart and reset counters
	 * were not used because they do not track the state of the
	 * counter.
	 *
	 * Pinweaver uses the restart_count to know when the time since
	 * boot can be used as the elapsed time for the delay schedule,
	 * versus when the elapsed time starts from a timestamp.
	 */
	if (pinweaver_eal_seconds_since_boot() < RESTART_TIMER_THRESHOLD) {
		++log->restart_count;
		ret = setvar(PW_LOG_VAR0, sizeof(PW_LOG_VAR0) - 1,
			     (uint8_t *)log, sizeof(struct pw_log_storage_t));
		if (ret != EC_SUCCESS) {
			freevar(var);
			return ret;
		}
	}
	*restart_count = log->restart_count;
	freevar(var);
	return EC_SUCCESS;
}

int pinweaver_eal_storage_get_log(struct pw_log_storage_t *dest)
{
	struct tuple *var;
	struct pw_log_storage_t *log;

	int rv = pinweaver_eal_storage_get_log_var(&var, &log);
	if (rv != EC_SUCCESS)
		return rv;

	memcpy(dest, log, sizeof(struct pw_log_storage_t));

	freevar(var);

	return EC_SUCCESS;
}

int pinweaver_eal_storage_set_log(const struct pw_log_storage_t *log)
{
	return setvar(PW_LOG_VAR0, sizeof(PW_LOG_VAR0) - 1, (uint8_t *)log,
		      sizeof(struct pw_log_storage_t));
}


int pinweaver_eal_storage_get_tree_data(struct pw_long_term_storage_t *dest)
{
	const struct pw_long_term_storage_t *tree;

	ptr = getvar(PW_TREE_VAR, sizeof(PW_TREE_VAR) - 1);
	if (!ptr)
		return PW_ERR_NV_EMPTY;

	tree = (void *)tuple_val(ptr);
	/* Add storage format updates here. */
	if (ptr->val_len != sizeof(*tree)) {
		freevar(ptr);
		return PW_ERR_NV_LENGTH_MISMATCH;
	}
	if (tree->storage_version != PW_STORAGE_VERSION) {
		freevar(ptr);
		return PW_ERR_NV_VERSION_MISMATCH;
	}

	memcpy(dest, tree, sizeof(struct pw_long_term_storage_t));
	freevar(ptr);
	return EC_SUCCESS;
}

int pinweaver_eal_storage_set_tree_data(
		const struct pw_long_term_storage_t *data)
{
	return setvar(PW_TREE_VAR, sizeof(PW_TREE_VAR) - 1,
		      (uint8_t *)data, sizeof(struct pw_long_term_storage_t));
}

uint8_t pinweaver_eal_get_current_pcr_digest(
		const uint8_t bitmask[2],
		uint8_t sha256_of_selected_pcr[32])
{
	return get_current_pcr_digest(bitmask, sha256_of_selected_pcr);
}

/*
 * Handle the VENDOR_CC_PINWEAVER command.
 */
static enum vendor_cmd_rc pw_vendor_specific_command(enum vendor_cmd_cc code,
						     void *buf,
						     size_t input_size,
						     size_t *response_size)
{
    	switch pinweaver_command(buf, input_size, buf, response_size) {
        	case PW_CMD_RES_SUCCESS:
        		return VENDOR_RC_SUCCESS;
        	case PW_CMD_RES_SIZE:
        		return VENDOR_RC_REQUEST_TOO_BIG;
        	default:
        		return VENDOR_RC_INTERNAL_ERROR;
    	}
}
DECLARE_VENDOR_COMMAND(VENDOR_CC_PINWEAVER,
		pw_vendor_specific_command);
