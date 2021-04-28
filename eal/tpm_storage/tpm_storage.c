/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdbool.h>
#include <string.h>

#include "mini_trunks/tss.h"
#include "pinweaver_eal.h"
#include "pinweaver_eal_tpm.h"
#include "tss_serde.h"

/* Make sure the largest possible message would fit in 2K
 */
BUILD_ASSERT(PW_MAX_MESSAGE_SIZE + 10 <= PINWEAVER_TSS_MAX_MESSAGE_SIZE);

typedef enum {
	TPMSS_NOT_STARTED = 0,		// initial state
	TPMSS_NOT_INITIALIZED = 1,	// NV indices not created after changing the owner
	TPMSS_READY = 2,		// ready for PinWeaver commands
} tpm_storage_state_t;
static tpm_storage_state_t g_storage_state = TPMSS_NOT_STARTED;

typedef struct tpm_session_t {
	TPM_HANDLE handle;
	TSS_AUTHORIZATION_DELEGATE delegate;
} tpm_session_t;
static tpm_session_t g_auth_session = { 0, };

const TPM2B_DIGEST kSaltingKeyName = {0, } /* TODO */;

static struct pw_long_term_storage_t g_tree_descriptor;
static bool g_tree_descriptor_filled = false;
const TPM2B_DIGEST kTreeDescriptorName = {0, } /* TODO */;

static bool g_auth_value_obtained[2] = {false, false};
static TPM2B_DIGEST g_auth_value[2];

#define DEVICE_KEY_SIZE SHA256_DIGEST_SIZE
static uint8_t g_device_key[2][DEVICE_KEY_SIZE];
static bool g_device_key_obtained[2] = {false, false};

#define DATA_KEY_SIZE SHA256_DIGEST_SIZE
static uint8_t g_data_key[2][DATA_KEY_SIZE];
static bool g_data_key_obtained[2] = {false, false};

typedef struct log_sensitive_data_t {
	struct pw_get_log_entry_t entry;
	uint8_t hash[SHA256_DIGEST_SIZE];
} log_sensitive_data_t;

#define LOG_ENTRY_IV_SIZE SHA256_DIGEST_SIZE
typedef struct tpm_storage_log_entry_t {
	uint16_t version;
	uint32_t counter;
	uint8_t iv[LOG_ENTRY_IV_SIZE];
	uint8_t encrypted_data[sizeof(log_sensitive_data_t)];
} tpm_storage_log_entry_t;

typedef struct cached_log_entry_t {
	uint32_t counter;
	struct pw_get_log_entry_t data;
} cached_log_entry_t;

#define MAX_LOG_ENTRIES 5
#define LOG_ENTRY_PERSIST MAX_LOG_ENTRIES
const TPM2B_DIGEST kLogEntryPersistName = {0, } /* TODO */;
const TPM2B_DIGEST kLogEntryName[MAX_LOG_ENTRIES] = {0, } /* TODO */;

static cached_log_entry_t g_cached_log_entries[MAX_LOG_ENTRIES];
static int g_cache_order[MAX_LOG_ENTRIES];
static uint32_t g_max_counter = 0;

static cached_log_entry_t* get_first_cached_log_entry()
{
	int num = g_cache_order[0];

	if (num < 0 || num >= MAX_LOG_ENTRIES)
		return NULL;
	return &g_cached_log_entries[num];
}

static int get_last_cached_log_entry_num()
{
	int num = g_cache_order[MAX_LOG_ENTRIES - 1];

	if (num < 0 || num >= MAX_LOG_ENTRIES)
		return -1;
	return num;
}

static int ensure_device_key(int kind) {
	kind = kind ? 1 : 0;
	if (g_device_key_obtained[kind])
		return 0;
	int res = pinweaver_eal_get_device_key(kind, g_device_key[kind]);
	if (res)
		return res;
	g_device_key_obtained[kind] = true;
	return 0;
}

static const TPM2B_DIGEST* get_auth_value(int kind) {
	const size_t kAuthValueLabelSize = 6;
	const char* kAuthValueLabel = "PW_ATH";

	kind = kind ? 1 : 0;
	if (g_auth_value_obtained[kind])
		return &g_auth_value[kind];
	if (ensure_device_key(kind))
		return NULL;

	pinweaver_eal_hmac_sha256_ctx_t hash;
	if (pinweaver_eal_hmac_sha256_init(&hash, g_device_key[kind], DEVICE_KEY_SIZE))
		return NULL;
	if (pinweaver_eal_hmac_sha256_update(&hash, kAuthValueLabel, kAuthValueLabelSize)) {
		pinweaver_eal_hmac_sha256_final(&hash, g_auth_value[kind].buffer);
		return NULL;
	}
	if (pinweaver_eal_hmac_sha256_final(&hash, g_auth_value[kind].buffer))
		return NULL;

	g_auth_value_obtained[kind] = true;
	return &g_auth_value[kind];
}

static const uint8_t* get_data_key(int kind) {
	kind = kind ? 1 : 0;
	if (g_data_key_obtained[kind])
		return g_data_key[kind];
	if (!g_tree_descriptor_filled)
		return NULL;
	if (ensure_device_key(kind))
		return NULL;

	pinweaver_eal_hmac_sha256_ctx_t hash;
	if (pinweaver_eal_hmac_sha256_init(&hash, g_device_key[kind], DEVICE_KEY_SIZE))
		return NULL;
	if (pinweaver_eal_hmac_sha256_update(&hash, g_tree_descriptor.key_derivation_nonce,
			sizeof(g_tree_descriptor.key_derivation_nonce))) {
		pinweaver_eal_hmac_sha256_final(&hash, g_data_key[kind]);
		return NULL;
	}
	if (pinweaver_eal_hmac_sha256_final(&hash, g_data_key[kind]))
		return NULL;

	g_data_key_obtained[kind] = true;
	return g_data_key[kind];
}

static void set_session_auth_value(tpm_session_t* session,
		const TPM2B_DIGEST* auth_value)
{
	session->delegate.hmac.entity_authorization_value_.size = auth_value->size;
	memcpy(session->delegate.hmac.entity_authorization_value_.buffer,
			auth_value->buffer, auth_value->size);
}

static void close_session(tpm_session_t* session)
{
	if (session->handle) {
		tss_FlushContext(session->handle, NULL);
		session->handle = 0;
	}
}

static int start_session(tpm_session_t* session,
		TPM_SE session_type,
		TPMI_DH_ENTITY bind_entity,
		const TPM2B_DIGEST* bind_authorization_value,
		bool salted,
		bool enable_encryption,
		bool force_restart);

static int get_salting_key_public(TPM2B_PUBLIC* public)
{
	TPM2B_NAME name;
	TPM2B_NAME qualified_name;
	TPM_RC rc = tss_ReadPublic(SALTING_KEY_HANDLE,
			NULL /* doesn't matter w/o auth */,
			public,
			&name,
			&qualified_name,
			/* delegate = */ NULL);
	return rc == TPM_RC_SUCCESS;
}

static int calc_salting_key_hash(TPM2B_PUBLIC* public,
		uint8_t* hash /* SHA256_DIGEST_SIZE */)
{
	TPMS_ECC_POINT* pub_key = &public->public_area.unique.ecc;
	pinweaver_eal_sha256_ctx_t ctx;
	if (pinweaver_eal_sha256_init(&ctx))
		return -1;
	if (pinweaver_eal_sha256_update(&ctx, pub_key->x.buffer, pub_key->x.size)) {
		pinweaver_eal_sha256_final(&ctx, hash);
		return -1;
	}
	if (pinweaver_eal_sha256_update(&ctx, pub_key->y.buffer, pub_key->y.size)) {
		pinweaver_eal_sha256_final(&ctx, hash);
		return -1;
	}
	return pinweaver_eal_sha256_final(&ctx, hash);
}

static int verify_salting_key_public(TPM2B_PUBLIC* public)
{
	uint8_t key_hash[SHA256_DIGEST_SIZE];
	uint8_t provisioned_hash[SHA256_DIGEST_SIZE];
	bool committed;

	if (pinweaver_get_tpm_key_hash(provisioned_hash, &committed))
		return -1;
	if (calc_salting_key_hash(public, key_hash))
		return -1;
	return pinweaver_eal_safe_memcmp(key_hash, provisioned_hash,
			SHA256_DIGEST_SIZE);
}

static int serialize_tpm_ec_point(
		const TPMS_ECC_POINT* point,
		TPM2B_ENCRYPTED_SECRET* serialized)
{
	TSS_DST_DATA_BUF buffer =
			{sizeof(serialized->secret), 0, serialized->secret};
			
	TPM_RC rc = tss_Serialize_TPMS_ECC_POINT(point, &buffer);
	if (rc != TPM_RC_SUCCESS)
		return -1;
	serialized->size = buffer.size;
	return 0;
}

static int generate_session_salt(TPM2B_DIGEST* salt,
		TPM2B_ENCRYPTED_SECRET* encrypted_salt)
{
	TPM2B_PUBLIC salting_key_public;
	if (get_salting_key_public(&salting_key_public))
		return -1;
	if (verify_salting_key_public(&salting_key_public))
		return -1;

	TPMS_ECC_POINT* pub_key = &salting_key_public.public_area.unique.ecc;
	TPMS_ECC_POINT ephemeral_point;
	TPMS_ECC_POINT z_point;

	if (pinweaver_eal_generate_ecdh_points(pub_key,
			&ephemeral_point, &z_point))
		return -1;

	if (serialize_tpm_ec_point(&ephemeral_point, encrypted_salt))
		return -1;

	const uint8_t kMarshaledCounter[4] = {0, 0, 0, 1}; /* big-endian 1 */
	const uint8_t kSessionKeyLabel[7] = {'S', 'E', 'C', 'R', 'E', 'T', 0};

	const TPM2B_ECC_PARAMETER* z_value = &z_point.x;
  	const TPM2B_ECC_PARAMETER* party_u_info = &ephemeral_point.x;
  	const TPM2B_ECC_PARAMETER* party_v_info = &pub_key->x;

	pinweaver_eal_sha256_ctx_t ctx;
	if (pinweaver_eal_sha256_init(&ctx))
		return -1;
	if (pinweaver_eal_sha256_update(&ctx, kMarshaledCounter, sizeof(kMarshaledCounter))) {
		pinweaver_eal_sha256_final(&ctx, salt->buffer);
		return -1;
	}
	if (pinweaver_eal_sha256_update(&ctx, z_value->buffer, z_value->size)) {
		pinweaver_eal_sha256_final(&ctx, salt->buffer);
		return -1;
	}
	if (pinweaver_eal_sha256_update(&ctx, kSessionKeyLabel, sizeof(kSessionKeyLabel))) {
		pinweaver_eal_sha256_final(&ctx, salt->buffer);
		return -1;
	}
	if (pinweaver_eal_sha256_update(&ctx, party_u_info->buffer, party_u_info->size)) {
		pinweaver_eal_sha256_final(&ctx, salt->buffer);
		return -1;
	}
	if (pinweaver_eal_sha256_update(&ctx, party_v_info->buffer, party_v_info->size)) {
		pinweaver_eal_sha256_final(&ctx, salt->buffer);
		return -1;
	}

	if (pinweaver_eal_sha256_final(&ctx, salt->buffer))
		return -1;
	salt->size = SHA256_DIGEST_SIZE;
	return 0;
}

static int start_session(tpm_session_t* session,
		TPM_SE session_type,
		TPMI_DH_ENTITY bind_entity,
		const TPM2B_DIGEST* bind_authorization_value,
		bool salted,
		bool enable_encryption,
		bool force_restart)
{
	TPM2B_DIGEST salt = { 0, };
	TPM2B_ENCRYPTED_SECRET encrypted_salt = { 0, };
  	TPMI_DH_OBJECT tpm_key = TPM_RH_NULL;

	if (session->handle) {
		if (!force_restart)
			return 0;
		close_session(session);
	}

	if (salted) {
		tpm_key = SALTING_KEY_HANDLE;
		int res = generate_session_salt(&salt, &encrypted_salt);
		if (res) {
			PINWEAVER_EAL_INFO("start_session: failed to create salt");
			return res;
		}
	}

	TPMT_SYM_DEF symmetric;
	if (enable_encryption) {
		symmetric.algorithm = TPM_ALG_AES;
		symmetric.key_bits.aes = 128;
		symmetric.mode.aes = TPM_ALG_CFB;
	} else {
		symmetric.algorithm = TPM_ALG_NULL;
	}

	TPM2B_NONCE nonce_caller;
	nonce_caller.size = SHA256_DIGEST_SIZE;
	int res = pinweaver_eal_rand_bytes(nonce_caller.buffer, nonce_caller.size);
	if (res) {
		PINWEAVER_EAL_INFO("Failed to generate nonce");
		return res;
	}

	TPM2B_NONCE nonce_tpm;

	TPM_RC rc = tss_StartAuthSession(
			tpm_key, NULL /* doesn't matter w/o auth */,
			bind_entity, NULL /* doesn't matter w/o auth */,
			&nonce_caller, &encrypted_salt,
			session_type, &symmetric,
			TPM_ALG_SHA256,
			&session->handle,
			&nonce_tpm,
			NULL);
	if (rc != TPM_RC_SUCCESS) {
		PINWEAVER_EAL_INFO("StartAuthSession failed: %#x", rc);
		return -1;
	}

	if (!tss_InitSessionHmac(&session->delegate.hmac,
			session->handle,
			&nonce_tpm, &nonce_caller,
			&salt, bind_authorization_value,
			enable_encryption)) {
		PINWEAVER_EAL_INFO("InitSession failed");
		tss_FlushContext(session->handle, NULL);
		session->handle = 0;
		return -1;
	}

	return 0;
}

static int start_auth_session(int kind, bool force_restart)
{
	const TPM2B_DIGEST* auth_value = get_auth_value(kind);
	if (!auth_value)
		return -1;
	int res = start_session(&g_auth_session, TPM_SE_HMAC, TPM_RH_NULL,
			/* bind_auth_value = */ NULL,
			/* salted = */ false, 
			/* enable_encryption = */ false,
			force_restart);
	if (res)
		return res;

	set_session_auth_value(&g_auth_session, auth_value);
	return 0;
}

static int calc_log_sensitive_data_hash(log_sensitive_data_t* data,
		uint8_t* res /* SHA256_DIGEST_SIZE */)
{
	pinweaver_eal_sha256_ctx_t ctx;
	if (pinweaver_eal_sha256_init(&ctx))
		return -1;
	if (pinweaver_eal_sha256_update(&ctx, &data->entry, sizeof(data->entry))) {
		pinweaver_eal_sha256_final(&ctx, res);
		return -1;
	}
	return pinweaver_eal_sha256_final(&ctx, res);
}

static int verify_log_sensitive_data(log_sensitive_data_t* data)
{
	uint8_t res[SHA256_DIGEST_SIZE];
	if (calc_log_sensitive_data_hash(data, res))
		return -1;
	if (pinweaver_eal_safe_memcmp(res, data->hash, SHA256_DIGEST_SIZE))
		return -1;
	return 0;
}

static int decrypt_log_entry(const tpm_storage_log_entry_t* tpm_entry, int kind, cached_log_entry_t* entry)
{
	const uint8_t* key = get_data_key(kind);
	if (key == NULL)
		return -1;

	log_sensitive_data_t plaintext;
	if (pinweaver_eal_aes256_ctr(key, DATA_KEY_SIZE, tpm_entry->iv,
			tpm_entry->encrypted_data, sizeof(log_sensitive_data_t),
			&plaintext)) {
		PINWEAVER_EAL_INFO("decrypt_log_entry(%d): AES failed", kind);
		return -1;
	}
	if (verify_log_sensitive_data(&plaintext) != 0) {
		PINWEAVER_EAL_INFO("decrypt_log_entry(%d): verification failed", kind);
		return -1;
	}

	memcpy(&entry->data, &plaintext.entry, sizeof(struct pw_get_log_entry_t));
	return 0;
}

static int encrypt_log_entry(const struct pw_get_log_entry_t* log_entry,
		uint32_t counter, tpm_storage_log_entry_t* tpm_entry)
{
	log_sensitive_data_t plaintext;
	const uint8_t* key = get_data_key(PINWEAVER_EAL_AUTH_CURRENT);
	if (key == NULL)
		return -1;

	memcpy(&plaintext.entry, log_entry, sizeof(struct pw_get_log_entry_t));
	if (calc_log_sensitive_data_hash(&plaintext, plaintext.hash)) {
		PINWEAVER_EAL_INFO("encrypt_log_entry: hash failed");
		return -1;
	}

	tpm_entry->counter = counter;
	tpm_entry->version = 0;
	pinweaver_eal_rand_bytes(tpm_entry->iv,
				 sizeof(tpm_entry->iv));
	if (pinweaver_eal_aes256_ctr(key, DATA_KEY_SIZE, tpm_entry->iv,
			&plaintext, sizeof(log_sensitive_data_t),
			tpm_entry->encrypted_data)) {
		PINWEAVER_EAL_INFO("encrypt_log_entry: AES failed");
		return -1;
	}

	return 0;
}

static int cache_order_ins(int pos, int entry_num)
{
	if (pos < 0 || pos >= MAX_LOG_ENTRIES)
		return -1;
	memmove(g_cache_order + pos + 1, g_cache_order + pos,
			(MAX_LOG_ENTRIES - pos - 1) * sizeof(g_cache_order[0]));
	g_cache_order[pos] = entry_num;
	return 0;
}

static int cache_order_ins_entry_num(cached_log_entry_t* entry, int entry_num)
{
	int pos;
	for (pos = 0; pos < MAX_LOG_ENTRIES; ++pos) {
		int other_entry_num = g_cache_order[pos];
		if (other_entry_num < 0)
			break;
		if (other_entry_num >= MAX_LOG_ENTRIES)
			return -1;
		cached_log_entry_t* other_entry =
				&g_cached_log_entries[other_entry_num];
		if (other_entry->counter < entry->counter) {
			break;
		} else if (other_entry->counter == entry->counter) {
			if (entry->counter != 0)
				return -1;
			break;
		}
	}
	return cache_order_ins(pos, entry_num);
}

static int cache_order_del(int pos)
{
	if (pos < 0 || pos >= MAX_LOG_ENTRIES)
		return -1;
	memmove(g_cache_order + pos, g_cache_order + pos + 1,
		(MAX_LOG_ENTRIES - pos - 1) * sizeof(g_cache_order[0]));
	g_cache_order[MAX_LOG_ENTRIES - 1] = -1;
	return 0;
}

static int cache_order_del_entry_num(int entry_num)
{
	int pos;
	for (pos = 0; pos < MAX_LOG_ENTRIES; ++pos) {
		if (g_cache_order[pos] == entry_num)
			return cache_order_del(pos);
	}
	return -1;
}

static int read_log_entry(TPM_HANDLE handle,
		const TPM2B_DIGEST* name,
		cached_log_entry_t* entry,
		int* is_old_key)
{
	TPM2B_MAX_NV_BUFFER buffer;
	tpm_storage_log_entry_t* tpm_entry =
			(tpm_storage_log_entry_t*)buffer.buffer;

	TPM_RC rc = tss_NV_Read(handle,
			name,
			handle,
			name,
			sizeof(tpm_storage_log_entry_t),
			0,
			&buffer,
			&g_auth_session.delegate);

	switch (rc) {
		case TPM_RC_SUCCESS:
			entry->counter = tpm_entry->counter;
			if (tpm_entry->counter > g_max_counter)
				g_max_counter = tpm_entry->counter;
			break;
		case TPM_RC_NV_UNINITIALIZED:
			PINWEAVER_EAL_INFO("read_log_entry %#x: uninitialized", handle);
			entry->counter = 0;
			break;
		default:
			PINWEAVER_EAL_INFO("read_log_entry %#x: error %#x", handle, rc);
			return -1;
	}

	if (entry->counter) {
		if (decrypt_log_entry(tpm_entry, PINWEAVER_EAL_AUTH_CURRENT, entry)) {
			PINWEAVER_EAL_INFO("read_log_entry %#x: trying old key", handle);
			if (decrypt_log_entry(tpm_entry, PINWEAVER_EAL_AUTH_PREVIOUS, entry)) {
				PINWEAVER_EAL_INFO("read_log_entry %#x: decrypt failed", handle);
				entry->counter = 0;
				return -1;
			}
			if (is_old_key)
				*is_old_key = 1;
		}
	}
	return 0;
}

static int read_and_insert_log_entry(int entry_num, int* need_writing)
{
	if (entry_num < 0 || entry_num >= MAX_LOG_ENTRIES)
		return -1;
	if (!need_writing)
		return -1;

	TPM_HANDLE handle = LOG_ENTRY_FIRST_HANDLE + entry_num;
	const TPM2B_DIGEST* name = &kLogEntryName[entry_num];
	cached_log_entry_t* entry = g_cached_log_entries + entry_num;
	int is_old_key = 0;

	if (read_log_entry(handle, name, entry, &is_old_key))
		return -1;

	need_writing[entry_num] = is_old_key;
	return cache_order_ins_entry_num(entry, entry_num);
}

static int write_log_entry(int entry_num, tpm_storage_log_entry_t* tpm_entry)
{
	TPM2B_MAX_NV_BUFFER tpm_data;
	memcpy(tpm_data.buffer, tpm_entry, sizeof(tpm_storage_log_entry_t));
	tpm_data.size = sizeof(tpm_storage_log_entry_t);

	const int kMaxRetries = 3;
	int retries;
	for (retries = 0; retries < kMaxRetries; ++retries) {
		if (start_auth_session(PINWEAVER_EAL_AUTH_CURRENT, retries > 0))
			return -1;

		TPM_HANDLE handle = LOG_ENTRY_FIRST_HANDLE + entry_num;
		const TPM2B_DIGEST* name = &kLogEntryName[entry_num];
		TPM_RC rc = tss_NV_Write(handle,
				name,
				handle,
				name,
				&tpm_data,
				/* offset = */ 0,
				&g_auth_session.delegate);
		if (rc == TPM_RC_SUCCESS)
			return 0;
		PINWEAVER_EAL_INFO("write_log_entry: write %#x attempt %d/%d failed %#x",
			handle, retries+1, kMaxRetries, res);
	}
	return -1;
}

static int read_log_entries()
{
	int entry_num;
	int need_writing[MAX_LOG_ENTRIES] = {0, };
	cached_log_entry_t* empty_entry = NULL;
	int empty_entry_num = -1;
	cached_log_entry_t* entry;

	if (g_storage_state == TPMSS_READY)
		return 0;
	
	for (entry_num = 0; entry_num < MAX_LOG_ENTRIES; ++entry_num) {
		if (read_and_insert_log_entry(entry_num, need_writing))
			return -1;
		if (empty_entry == NULL && entry->counter == 0) {
			empty_entry_num = entry_num;
			empty_entry = entry;
		}
	}

	if (empty_entry) {
		cached_log_entry_t persist_entry;

		if (read_log_entry(LOG_ENTRY_PERSIST_HANDLE,
				&kLogEntryPersistName, &persist_entry,
				NULL)) {
			return -1;
		}
		if (persist_entry.counter) {
			for (entry_num = 0; entry_num < MAX_LOG_ENTRIES; ++entry_num) {
				if (g_cached_log_entries[entry_num].counter == persist_entry.counter)
					break;
			}
			if (entry_num >= MAX_LOG_ENTRIES) {
				if (cache_order_del_entry_num(empty_entry_num))
					return -1;
				memcpy(empty_entry, &persist_entry, sizeof(cached_log_entry_t));
				if (cache_order_ins_entry_num(empty_entry, empty_entry_num))
					return -1;
				need_writing[empty_entry_num] = 1;
			}
		}
	}

	for (entry_num = 0; entry_num < MAX_LOG_ENTRIES; ++entry_num) {
		if (!need_writing[entry_num])
			continue;
		tpm_storage_log_entry_t tpm_entry;
		cached_log_entry_t* entry = &g_cached_log_entries[entry_num];
		if (encrypt_log_entry(&entry->data, entry->counter, &tpm_entry))
			return -1;
		if (write_log_entry(entry_num, &tpm_entry))
			return -1;
	}

	return 0;
}

static void set_initial_log_entries()
{
	int entry_num;
	for (entry_num = 0; entry_num < MAX_LOG_ENTRIES; ++entry_num) {
		memset(&g_cached_log_entries[entry_num], 0, sizeof(cached_log_entry_t));
		g_cache_order[entry_num] = MAX_LOG_ENTRIES - entry_num - 1;
	}
}

static void set_initial_tree_descr()
{
	memset(&g_tree_descriptor, 0, sizeof(g_tree_descriptor));
	g_tree_descriptor_filled = false;
}

static int read_tree_descr()
{
	TPM2B_MAX_NV_BUFFER buffer;

	TPM_RC rc = tss_NV_Read(TREE_DESCRIPTOR_HANDLE,
			&kTreeDescriptorName,
			TREE_DESCRIPTOR_HANDLE,
			&kTreeDescriptorName,
			sizeof(g_tree_descriptor),
			0,
			&buffer,
			&g_auth_session.delegate);
	switch (rc) {
		case TPM_RC_SUCCESS:
			if (buffer.size != sizeof(g_tree_descriptor)) {
				PINWEAVER_EAL_INFO("read_tree_descr: unexpected size (%u)", buffer.size);
				return -1;
			}
			memcpy(&g_tree_descriptor, buffer.buffer, sizeof(g_tree_descriptor));
			g_tree_descriptor_filled = true;
			break;
		case TPM_RC_NV_UNINITIALIZED:
			PINWEAVER_EAL_INFO("read_tree_descr: empty");
			set_initial_log_entries();
			set_initial_tree_descr();
			g_storage_state = TPMSS_READY;
			break;
		case TPM_RC_HANDLE + TPM_RC_H + TPM_RC_1:
		case TPM_RC_HANDLE + TPM_RC_H + TPM_RC_2:
			PINWEAVER_EAL_INFO("read_tree_descr: no tree descr: error %#x", rc);
			g_storage_state = TPMSS_NOT_INITIALIZED;
			return -1;
		case TPM_RC_BAD_AUTH + TPM_RC_S + TPM_RC_1:
			PINWEAVER_EAL_INFO("read_tree_descr: bad auth", handle);
			/* TODO: change auth old -> current */
			return -1;
		default:
			PINWEAVER_EAL_INFO("read_tree_descr: error %#x", rc);
			return -1;
	}
	return 0;
}

#define PW_OBJ_CONST_SIZE 8
#define PW_NONCE_SIZE (128/8)
static int derive_pw_key(const uint8_t* device_key /* DEVICE_KEY_SIZE=256-bit */,
		const uint8_t* object_const /* PW_OBJ_CONST_SIZE */,
		const uint8_t* nonce /* PW_NONCE_SIZE */,
		uint8_t* result /* SHA256_DIGEST_SIZE */)
{
	pinweaver_eal_hmac_sha256_ctx_t hash;
	if (pinweaver_eal_hmac_sha256_init(&hash, device_key, DEVICE_KEY_SIZE))
		return -1;
	if (pinweaver_eal_hmac_sha256_update(&hash, object_const, PW_OBJ_CONST_SIZE)) {
		pinweaver_eal_hmac_sha256_final(&hash, result);
		return -1;
	}
	if (pinweaver_eal_hmac_sha256_update(&hash, nonce, PW_NONCE_SIZE)) {
		pinweaver_eal_hmac_sha256_final(&hash, result);
		return -1;
	}
	return pinweaver_eal_hmac_sha256_final(&hash, result);
}

int pinweaver_eal_derive_keys(struct merkle_tree_t *merkle_tree)
{
	const uint8_t kWrapKeyConst[PW_OBJ_CONST_SIZE] = 
			{'W', 'R', 'A', 'P', 'W', 'R', 'A', 'P'};
	const uint8_t kHmacKeyConst[PW_OBJ_CONST_SIZE] =
			{'H', 'M', 'A', 'C', 'H', 'M', 'A', 'C'};
	uint8_t device_key[DEVICE_KEY_SIZE];
	if (pinweaver_eal_get_device_key(PINWEAVER_EAL_CONST, device_key))
		return -1;

	if (derive_pw_key(device_key, kWrapKeyConst,
			merkle_tree->key_derivation_nonce, merkle_tree->wrap_key))
		return -1;

	if (derive_pw_key(device_key, kHmacKeyConst,
			merkle_tree->key_derivation_nonce, merkle_tree->hmac_key))
		return -1;

	return 0;
}

int pinweaver_eal_storage_start()
{
	const int kMaxRetries = 10;
	int retries;
	bool read_failed = true;

	if (g_storage_state == TPMSS_READY)
		return 0;

	set_initial_log_entries();
	set_initial_tree_descr();
	g_storage_state = TPMSS_NOT_STARTED;

	for (retries = 0; read_failed && retries < kMaxRetries; ++retries) {
		if (start_auth_session(PINWEAVER_EAL_AUTH_CURRENT, true) != 0)
			return -1;
		read_failed = (read_tree_descr() != 0) ||
				(read_log_entries() != 0);
		if (g_storage_state == TPMSS_NOT_INITIALIZED)
			return -1;
	}
	if (read_failed)
		return -1;
	g_storage_state = TPMSS_READY;

	return 0;	
}

int pinweaver_eal_storage_init_state(uint8_t *root_hash,
				     uint32_t *restart_count)
{
	if (pinweaver_eal_storage_start())
		return -1;

	struct cached_log_entry_t* first = get_first_cached_log_entry();

	if (!first)
		return -1;

	memcpy(root_hash, first->data.root, PW_HASH_SIZE);

	/* TODO - get restart_count from TPM counter */
	*restart_count = 0;
	return 0;
}

static void log_entry_set_default(struct pw_get_log_entry_t* entry)
{
	memset(entry, 0, sizeof(struct pw_get_log_entry_t));
}

int pinweaver_eal_storage_get_log(struct pw_log_storage_t *dest)
{
	if (pinweaver_eal_storage_start())
		return -1;

	/* TODO: PW_LOG_ENTRY_COUNT vs MAX_LOG_ENTRIES */
	int entry_num;
	for (entry_num = 0;
			entry_num < PW_LOG_ENTRY_COUNT &&
			entry_num < MAX_LOG_ENTRIES; 
			++entry_num) {
		int nv_num = g_cache_order[entry_num];
		if (g_cached_log_entries[nv_num].counter != 0) {
			memcpy(&dest->entries[entry_num],
					&g_cached_log_entries[nv_num].data,
					sizeof(struct pw_get_log_entry_t));
		} else {
			log_entry_set_default(&dest->entries[entry_num]);
		}
	}
	return 0;
}

int pinweaver_eal_storage_set_log(const struct pw_log_storage_t *log)
{
	if (pinweaver_eal_storage_start())
		return -1;

	int entry_num = get_last_cached_log_entry_num();
	if (entry_num < 0)
		return -1;

	uint32_t counter = ++g_max_counter;

	tpm_storage_log_entry_t tpm_entry;
	if (encrypt_log_entry(&log->entries[0], counter, &tpm_entry))
		return -1;
	if (write_log_entry(entry_num, &tpm_entry))
		return -1;

	cached_log_entry_t* entry = &g_cached_log_entries[entry_num];
	memcpy(&entry->data, &log->entries[0], sizeof(struct pw_get_log_entry_t));
	entry->counter = counter;
	memmove(g_cache_order + 1, g_cache_order,
		(MAX_LOG_ENTRIES - 1) * sizeof(g_cache_order[0]));
	g_cache_order[0] = entry_num;

	return 0;
}

int pinweaver_eal_storage_get_tree_data(struct pw_long_term_storage_t *dest)
{
	pinweaver_eal_storage_start();
	memcpy(dest, &g_tree_descriptor, sizeof(struct pw_long_term_storage_t));
	return g_tree_descriptor_filled ? 0 : -1;
}

static int write_tree_descr(const struct pw_long_term_storage_t *data)
{
	TPM2B_MAX_NV_BUFFER tpm_data;
	memcpy(tpm_data.buffer, data, sizeof(struct pw_long_term_storage_t));
	tpm_data.size = sizeof(struct pw_long_term_storage_t);

	const int kMaxRetries = 3;
	int retries;
	for (retries = 0; retries < kMaxRetries; ++retries) {
		if (start_auth_session(PINWEAVER_EAL_AUTH_CURRENT, retries > 0))
			return -1;

		TPM_HANDLE handle = TREE_DESCRIPTOR_HANDLE;
		const TPM2B_DIGEST* name = &kTreeDescriptorName;
		TPM_RC rc = tss_NV_Write(handle,
				name,
				handle,
				name,
				&tpm_data,
				/* offset = */ 0,
				&g_auth_session.delegate);
		if (rc == TPM_RC_SUCCESS)
			return 0;
		PINWEAVER_EAL_INFO("write_tree_descr: write %#x attempt %d/%d failed %#x",
			handle, retries+1, kMaxRetries, res);
	}
	return -1;
}

int pinweaver_eal_storage_set_tree_data(
		const struct pw_long_term_storage_t *data)
{
	if (pinweaver_eal_storage_start())
		return -1;

	set_initial_log_entries();
	memcpy(&g_tree_descriptor, data, sizeof(struct pw_long_term_storage_t));
	g_tree_descriptor_filled = true;
	
	tpm_storage_log_entry_t tpm_entry;
	memset(&tpm_entry, 0, sizeof(tpm_entry));
	int res = 0;
	int entry_num;
	for (entry_num = 0; entry_num < MAX_LOG_ENTRIES; ++entry_num) {
		if (write_log_entry(entry_num, &tpm_entry))
			res = -1;
	}
	if (write_tree_descr(&g_tree_descriptor))
		res = -1;	

	return res;
}

// static void digest_copy(TPM2B_DIGEST* dest, TPM2B_DIGEST* src)
// {
// 	memcpy(dest, src, sizeof(TPM2B_DIGEST));
// }

static void digest_set_sha256(TPM2B_DIGEST* digest,
		const uint8_t* value /* SHA256_DIGEST_SIZE */)
{
	memcpy(digest->buffer, value, SHA256_DIGEST_SIZE);
	digest->size = SHA256_DIGEST_SIZE;
}

// static void digest_set_empty(TPM2B_DIGEST* digest)
// {
// 	memset(digest->buffer, 0, sizeof(TPMU_HA));
// 	digest->size = 0;
// }

static void digest_set_handle(TPM2B_DIGEST* digest, TPM_HANDLE handle)
{
	uint32_t serialized = htobe32(handle);
	memcpy(digest->buffer, &serialized, sizeof(serialized));
	digest->size = sizeof(serialized);
}

const uint8_t kNvPolicy[SHA256_DIGEST_SIZE] = {0, }; // TODO
static int define_space(tpm_session_t* session,
		TPM_HANDLE handle, size_t data_size)
{
	const TPM2B_DIGEST* auth_value = get_auth_value(0);
	if (!auth_value)
		return -1;

	TPM2B_NV_PUBLIC public_area;
	public_area.size = sizeof(TPMS_NV_PUBLIC);
	public_area.nv_public.nv_index = handle;
	public_area.nv_public.name_alg = TPM_ALG_SHA256;
	public_area.nv_public.attributes = TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE;
	digest_set_sha256(&public_area.nv_public.auth_policy, kNvPolicy);
	public_area.nv_public.data_size = data_size;

	TPM2B_DIGEST owner_name;
	digest_set_handle(&owner_name, TPM_RH_OWNER);
	TPM_RC rc = tss_NV_DefineSpace(TPM_RH_OWNER, &owner_name,
			auth_value, &public_area, &session->delegate);
	if (rc != TPM_RC_SUCCESS && rc != TPM_RC_NV_DEFINED) {
		PINWEAVER_EAL_INFO("define_space %#x failed %#x", handle, rc);
		return -1;
	}
	return 0;
}

static int create_nvmem_spaces()
{
	tpm_session_t salted_session = { 0, };
	if (start_session(&salted_session, TPM_SE_HMAC, TPM_RH_NULL,
			/* bind_auth_value = */ NULL,
			/* salted = */ true, 
			/* enable_encryption = */ true,
			/* force_restart = */ true))
		return -1;

	int entry_num;
	int res = -1;
	do {
		for (entry_num = 0; entry_num < MAX_LOG_ENTRIES; ++entry_num) {
			if (define_space(&salted_session,
					LOG_ENTRY_FIRST_HANDLE + entry_num,
					sizeof(tpm_storage_log_entry_t)))
				break;
		}
		if (entry_num < MAX_LOG_ENTRIES)
			break;

		if (define_space(&salted_session,
				LOG_ENTRY_PERSIST_HANDLE,
				sizeof(tpm_storage_log_entry_t)))
			break;
		if (define_space(&salted_session,
				TREE_DESCRIPTOR_HANDLE,
				sizeof(struct pw_long_term_storage_t)))
			break;

		PINWEAVER_EAL_INFO("create_nvmem_spaces: success");
		res = 0;
	} while(0);
	close_session(&salted_session);

	return res;
}

int pinweaver_eal_storage_initialize_owner()
{
	if (g_storage_state == TPMSS_NOT_STARTED)
		pinweaver_eal_storage_start();
	if (g_storage_state != TPMSS_NOT_INITIALIZED)
		return -1;

	const int kMaxRetries = 10;
	int retries;
	for (retries = 0; retries < kMaxRetries; ++retries) {
		if (create_nvmem_spaces() == 0) {
			g_storage_state = TPMSS_READY;
			return 0;
		}
	}
	return -1;
}