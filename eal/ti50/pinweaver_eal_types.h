
/* Copyright 2022 The ChromiumOS Authors.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __PINWEAVER_EAL_TYPES_H
#define __PINWEAVER_EAL_TYPES_H

typedef uint32_t pinweaver_eal_sha256_ctx_t;
typedef uint32_t pinweaver_eal_hmac_sha256_ctx_t;

int printf(const char* format, ...);

#define PINWEAVER_EAL_INFO(...) \
    do { \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } while(0)

#endif  /* __PINWEAVER_EAL_TYPES_H */
