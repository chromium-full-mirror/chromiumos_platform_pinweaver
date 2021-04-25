// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINI_TRUNKS_ERROR_CODES_H_
#define MINI_TRUNKS_ERROR_CODES_H_

#include "tss.h"  // For TPM_RC.

// Use the TPM_RC type but with different layer bits (12 - 15). Choose the layer
// value arbitrarily.
const TPM_RC kTrunksErrorBase = (7 << 12);

const TPM_RC TRUNKS_RC_AUTHORIZATION_FAILED = kTrunksErrorBase + 1;
const TPM_RC TRUNKS_RC_ENCRYPTION_FAILED = kTrunksErrorBase + 2;
const TPM_RC TRUNKS_RC_READ_ERROR = kTrunksErrorBase + 3;
const TPM_RC TRUNKS_RC_WRITE_ERROR = kTrunksErrorBase + 4;
const TPM_RC TRUNKS_RC_IPC_ERROR = kTrunksErrorBase + 5;
const TPM_RC TRUNKS_RC_SESSION_SETUP_ERROR = kTrunksErrorBase + 6;
const TPM_RC TRUNKS_RC_INVALID_TPM_CONFIGURATION = kTrunksErrorBase + 7;
const TPM_RC TRUNKS_RC_SERIALIZATION_ERROR = kTrunksErrorBase + 8;
const TPM_RC TRUNKS_RC_HASH_ERROR = kTrunksErrorBase + 9;

#endif  // MINI_TRUNKS_ERROR_CODES_H_
