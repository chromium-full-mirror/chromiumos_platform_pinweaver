/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdbool.h>
#include <string.h>

#include "pinweaver_eal.h"

int pinweaver_eal_derive_keys(struct merkle_tree_t *merkle_tree)
{
	/* TODO */
	return 0;
}

int pinweaver_eal_storage_start()
{
	/* TODO */
	return 0;
}

int pinweaver_eal_storage_init_state(uint8_t *root_hash,
				     uint32_t *restart_count)
{
	/* TODO */
	*restart_count = 0;
	return 0;
}

int pinweaver_eal_storage_get_log(struct pw_log_storage_t *dest)
{
	/* TODO */
	return 0;
}

int pinweaver_eal_storage_set_log(const struct pw_log_storage_t *log)
{
	/* TODO */
	return 0;
}

int pinweaver_eal_storage_get_tree_data(struct pw_long_term_storage_t *dest)
{
	/* TODO */
	return 0;
}

int pinweaver_eal_storage_set_tree_data(
		const struct pw_long_term_storage_t *data)
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

int pinweaver_eal_get_auth_value(
		int kind, /* CURRENT/PREVIOUS */
		void* auth_value /* 256-bit */)
{
	/* TODO */
	memset(auth_value, 0xA5, 256/8);
	return 0;
}
