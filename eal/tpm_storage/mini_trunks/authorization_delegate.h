// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINI_TRUNKS_AUTHORIZATION_DELEGATE_H_
#define MINI_TRUNKS_AUTHORIZATION_DELEGATE_H_

#include <string>
#include "hmac_authorization_delegate.h"

typedef struct AuthorizationDelegate {
  HmacAuthorizationDelegate hmac;
} AuthorizationDelegate;

// Provides authorization data for a command which has a cpHash value of
// |command_hash|. The availability of encryption for the command is indicated
// by |is_*_parameter_encryption_possible|. On success, |authorization| is
// populated with the exact octets for the Authorization Area of the command.
// Returns true on success.
bool GetCommandAuthorization(
    AuthorizationDelegate* delegate,
    const std::string& command_hash,
    bool is_command_parameter_encryption_possible,
    bool is_response_parameter_encryption_possible,
    std::string* authorization);

// Checks authorization data for a response which has a rpHash value of
// |response_hash|. The exact octets from the Authorization Area of the
// response are given in |authorization|. Returns true iff the authorization
// is valid.
bool CheckResponseAuthorization(
    AuthorizationDelegate* delegate,
    const std::string& response_hash,
    const std::string& authorization);

// Encrypts |parameter| if encryption is enabled. Returns true on success.
bool EncryptCommandParameter(
    AuthorizationDelegate* delegate,
    std::string* parameter);

// Decrypts |parameter| if encryption is enabled. Returns true on success.
bool DecryptResponseParameter(
    AuthorizationDelegate* delegate,
    std::string* parameter);

// Returns the current TPM-generated nonce that is associated with the
// authorization session. Returns true on success.
bool GetTpmNonce(
    AuthorizationDelegate* delegate,
    std::string* nonce);

#endif  // MINI_TRUNKS_AUTHORIZATION_DELEGATE_H_
