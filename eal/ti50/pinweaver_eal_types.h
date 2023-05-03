
/* Copyright 2022 The ChromiumOS Authors.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __PINWEAVER_EAL_TYPES_H
#define __PINWEAVER_EAL_TYPES_H

// pub struct KeyCtxHandle(usize);
// pub struct OwnedKeyCtxHandle(KeyCtxHandle);
// pub type HmacOpOwnedHandle = OwnedKeyCtxHandle;
// pub type HashOpOwnedHandle = OwnedKeyCtxHandle;
// pub type pinweaver_eal_sha256_ctx_t = HashOpOwnedHandle;
// pub type pinweaver_eal_hmac_sha256_ctx_t = HmacOpOwnedHandle;

typedef uintptr_t pinweaver_eal_sha256_ctx_t;
typedef uintptr_t pinweaver_eal_hmac_sha256_ctx_t;

#define PINWEAVER_EAL_INFO(...)

#endif  /* __PINWEAVER_EAL_TYPES_H */
