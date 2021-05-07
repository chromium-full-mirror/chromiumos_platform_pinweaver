
/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __PINWEAVER_EAL_TPM_H
#define __PINWEAVER_EAL_TPM_H

#include <stdbool.h>
#include <stddef.h>

#include "pinweaver_eal_types.h"
#include "pinweaver.h"

#define PINWEAVER_TSS_MAX_MESSAGE_SIZE 4096

int pinweaver_eal_tpm_initialize();

// Sends a TPM command synchronously and returns the response. If a transmission
// error occurs the response will be populated with a well-formed error
// response.
// Size/capacity of request is determined from the TPM command header. It must
// not exceed PINWEAVER_TSS_MAX_MESSAGE_SIZE bytes.
// Capacity of response must be at least PINWEAVER_TSS_MAX_MESSAGE_SIZE bytes.
// request and response are allowed to point to the same buffer.
void pinweaver_eal_send_command_and_wait(const char *request, char *response);

/*
 * Perform AES-128 CFB encrypt/decrypt.
 * Only 128 bit key size is used.
 */
#define PINWEAVER_EAL_DECRYPT 0
#define PINWEAVER_EAL_ENCRYPT 1
int pinweaver_eal_aes128_cfb(const void *key,
			     size_t key_size, /* in bytes */
			     const void *iv,
			     const void *data,
			     size_t size,
			     int op_type, /* PINWEAVER_EAL_{DE|EN}CRYPT */
			     void *res);

#define PINWEAVER_EAL_AUTH_CURRENT 0
#define PINWEAVER_EAL_AUTH_PREVIOUS 1
int pinweaver_eal_get_device_key(int kind,
				 void* key /* 256-bit */);

/*
 * Get Salting key hash from storage.
 * `*committed` is set to true if it is committed to write-once memory,
 * and false if it comes from SRAM.
 */
int pinweaver_get_tpm_key_hash(uint8_t tpm_key_hash[32], bool* committed);

#endif  /* __PINWEAVER_EAL_H */
