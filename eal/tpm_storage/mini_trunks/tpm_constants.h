// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINI_TRUNKS_TPM_CONSTANTS_H_
#define MINI_TRUNKS_TPM_CONSTANTS_H_

#include "tpm_generated.h"

// TPM Object Attributes.
const TPMA_OBJECT kFixedTPM = 1U << 1;
const TPMA_OBJECT kFixedParent = 1U << 4;
const TPMA_OBJECT kSensitiveDataOrigin = 1U << 5;
const TPMA_OBJECT kUserWithAuth = 1U << 6;
const TPMA_OBJECT kAdminWithPolicy = 1U << 7;
const TPMA_OBJECT kNoDA = 1U << 10;
const TPMA_OBJECT kRestricted = 1U << 16;
const TPMA_OBJECT kDecrypt = 1U << 17;
const TPMA_OBJECT kSign = 1U << 18;

// TPM NV Index Attributes, defined in TPM Spec Part 2 section 13.2.
const TPMA_NV TPMA_NV_PPWRITE = 1U << 0;
const TPMA_NV TPMA_NV_OWNERWRITE = 1U << 1;
const TPMA_NV TPMA_NV_AUTHWRITE = 1U << 2;
const TPMA_NV TPMA_NV_POLICYWRITE = 1U << 3;
const TPMA_NV TPMA_NV_COUNTER = 1U << 4;
const TPMA_NV TPMA_NV_BITS = 1U << 5;
const TPMA_NV TPMA_NV_EXTEND = 1U << 6;
const TPMA_NV TPMA_NV_POLICY_DELETE = 1U << 10;
const TPMA_NV TPMA_NV_WRITELOCKED = 1U << 11;
const TPMA_NV TPMA_NV_WRITEALL = 1U << 12;
const TPMA_NV TPMA_NV_WRITEDEFINE = 1U << 13;
const TPMA_NV TPMA_NV_WRITE_STCLEAR = 1U << 14;
const TPMA_NV TPMA_NV_GLOBALLOCK = 1U << 15;
const TPMA_NV TPMA_NV_PPREAD = 1U << 16;
const TPMA_NV TPMA_NV_OWNERREAD = 1U << 17;
const TPMA_NV TPMA_NV_AUTHREAD = 1U << 18;
const TPMA_NV TPMA_NV_POLICYREAD = 1U << 19;
const TPMA_NV TPMA_NV_NO_DA = 1U << 25;
const TPMA_NV TPMA_NV_ORDERLY = 1U << 26;
const TPMA_NV TPMA_NV_CLEAR_STCLEAR = 1U << 27;
const TPMA_NV TPMA_NV_READLOCKED = 1U << 28;
const TPMA_NV TPMA_NV_WRITTEN = 1U << 29;
const TPMA_NV TPMA_NV_PLATFORMCREATE = 1U << 30;
const TPMA_NV TPMA_NV_READ_STCLEAR = 1U << 31;

// TPM Vendor-Specific commands (TPM Spec Part 2, section 6.5.1)
const TPM_CC TPM_CC_VENDOR_SPECIFIC_MASK = 1U << 29;

// This needs to be used to be backwards compatible with older Cr50 versions.
const TPM_CC TPM_CC_CR50_EXTENSION_COMMAND = 0xbaccd00a;

#endif  // MINI_TRUNKS_TPM_CONSTANTS_H_
