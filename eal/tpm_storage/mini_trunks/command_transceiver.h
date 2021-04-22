// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINI_TRUNKS_COMMAND_TRANSCEIVER_H_
#define MINI_TRUNKS_COMMAND_TRANSCEIVER_H_

#include <string>

#include <tpm_constants.h>

namespace mini_trunks {

// CommandTransceiver is an interface that sends commands to a TPM device and
// receives responses. It can operate synchronously or asynchronously.
class CommandTransceiver {
 public:
  virtual ~CommandTransceiver() {}

  // Sends a TPM |command| synchronously (i.e. waits for a response) and returns
  // the response. If a transmission error occurs the response will be populated
  // with a well-formed error response.
  virtual std::string SendCommandAndWait(const std::string& command) = 0;

  // Initializes the actual interface, replaced by the derived classes, where
  // needed.
  virtual bool Init() { return true; }
};

}  // namespace mini_trunks

#endif  // MINI_TRUNKS_COMMAND_TRANSCEIVER_H_
