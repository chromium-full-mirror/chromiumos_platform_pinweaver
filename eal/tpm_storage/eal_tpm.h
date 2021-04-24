
/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __PINWEAVER_EAL_TPM_H
#define __PINWEAVER_EAL_TPM_H

#include <stddef.h>
#include <eal_types.h>
#include <pinweaver.h>

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif  /* __PINWEAVER_EAL_H */
