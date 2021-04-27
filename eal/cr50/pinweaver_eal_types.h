
/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __PINWEAVER_EAL_TYPES_H
#define __PINWEAVER_EAL_TYPES_H

#include <console.h>
#include <dcrypto.h>

typedef LITE_SHA256_CTX pinweaver_eal_sha256_ctx_t;
typedef LITE_HMAC_CTX pinweaver_eal_hmac_sha256_ctx_t;

#define PINWEAVER_EAL_INFO(...) cprints(CC_TASK, __VA_ARGS__)

#endif  /* __PINWEAVER_EAL_TYPES_H */
