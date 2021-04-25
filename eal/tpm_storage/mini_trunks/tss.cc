// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tss_internal.h"

#include <endian.h>
#include <cstring>
#include <memory>
#include <string>

#include "authorization_delegate.h"
#include "eal.h"
#include "error_codes.h"

// TODO(apronin): remove after de-C++-ification
extern "C" {
#include "pinweaver_tpm.h"
}

const size_t kSizeOffset = 2;
const size_t kMaxResponseSize = 4096;
char g_response[kMaxResponseSize];

void SendCommandAndWait(const std::string& command, std::string* response) {
  send_command_and_wait(command.data(), g_response);
  std::string buffer(g_response + kSizeOffset, sizeof(UINT32));
  UINT32 response_size;
  TPM_RC rc = Parse_UINT32(&buffer, &response_size, NULL);
  if (rc != TPM_RC_SUCCESS || response_size > kMaxResponseSize) {
    response->clear();
  } else {
    response->assign(g_response, response_size);
  }
}


size_t GetNumberOfRequestHandles(TPM_CC command_code) {
  switch (command_code) {
    case TPM_CC_Startup:
      return 0;
    case TPM_CC_Shutdown:
      return 0;
    case TPM_CC_SelfTest:
      return 0;
    case TPM_CC_IncrementalSelfTest:
      return 0;
    case TPM_CC_GetTestResult:
      return 0;
    case TPM_CC_StartAuthSession:
      return 2;
    case TPM_CC_PolicyRestart:
      return 1;
    case TPM_CC_Create:
      return 1;
    case TPM_CC_Load:
      return 1;
    case TPM_CC_LoadExternal:
      return 0;
    case TPM_CC_ReadPublic:
      return 1;
    case TPM_CC_ActivateCredential:
      return 2;
    case TPM_CC_MakeCredential:
      return 1;
    case TPM_CC_Unseal:
      return 1;
    case TPM_CC_ObjectChangeAuth:
      return 2;
    case TPM_CC_Duplicate:
      return 2;
    case TPM_CC_Rewrap:
      return 2;
    case TPM_CC_Import:
      return 1;
    case TPM_CC_RSA_Encrypt:
      return 1;
    case TPM_CC_RSA_Decrypt:
      return 1;
    case TPM_CC_ECDH_KeyGen:
      return 1;
    case TPM_CC_ECDH_ZGen:
      return 1;
    case TPM_CC_ECC_Parameters:
      return 0;
    case TPM_CC_ZGen_2Phase:
      return 1;
    case TPM_CC_EncryptDecrypt:
      return 1;
    case TPM_CC_Hash:
      return 0;
    case TPM_CC_HMAC:
      return 1;
    case TPM_CC_GetRandom:
      return 0;
    case TPM_CC_StirRandom:
      return 0;
    case TPM_CC_HMAC_Start:
      return 1;
    case TPM_CC_HashSequenceStart:
      return 0;
    case TPM_CC_SequenceUpdate:
      return 1;
    case TPM_CC_SequenceComplete:
      return 1;
    case TPM_CC_EventSequenceComplete:
      return 2;
    case TPM_CC_Certify:
      return 2;
    case TPM_CC_CertifyCreation:
      return 2;
    case TPM_CC_Quote:
      return 1;
    case TPM_CC_GetSessionAuditDigest:
      return 3;
    case TPM_CC_GetCommandAuditDigest:
      return 2;
    case TPM_CC_GetTime:
      return 2;
    case TPM_CC_Commit:
      return 1;
    case TPM_CC_EC_Ephemeral:
      return 0;
    case TPM_CC_VerifySignature:
      return 1;
    case TPM_CC_Sign:
      return 1;
    case TPM_CC_SetCommandCodeAuditStatus:
      return 1;
    case TPM_CC_PCR_Extend:
      return 1;
    case TPM_CC_PCR_Event:
      return 1;
    case TPM_CC_PCR_Read:
      return 0;
    case TPM_CC_PCR_Allocate:
      return 1;
    case TPM_CC_PCR_SetAuthPolicy:
      return 2;
    case TPM_CC_PCR_SetAuthValue:
      return 1;
    case TPM_CC_PCR_Reset:
      return 1;
    case TPM_CC_PolicySigned:
      return 2;
    case TPM_CC_PolicySecret:
      return 2;
    case TPM_CC_PolicyTicket:
      return 1;
    case TPM_CC_PolicyOR:
      return 1;
    case TPM_CC_PolicyPCR:
      return 1;
    case TPM_CC_PolicyLocality:
      return 1;
    case TPM_CC_PolicyNV:
      return 3;
    case TPM_CC_PolicyCounterTimer:
      return 1;
    case TPM_CC_PolicyCommandCode:
      return 1;
    case TPM_CC_PolicyPhysicalPresence:
      return 1;
    case TPM_CC_PolicyCpHash:
      return 1;
    case TPM_CC_PolicyNameHash:
      return 1;
    case TPM_CC_PolicyDuplicationSelect:
      return 1;
    case TPM_CC_PolicyAuthorize:
      return 1;
    case TPM_CC_PolicyAuthValue:
      return 1;
    case TPM_CC_PolicyPassword:
      return 1;
    case TPM_CC_PolicyGetDigest:
      return 1;
    case TPM_CC_PolicyNvWritten:
      return 1;
    case TPM_CC_CreatePrimary:
      return 1;
    case TPM_CC_HierarchyControl:
      return 1;
    case TPM_CC_SetPrimaryPolicy:
      return 1;
    case TPM_CC_ChangePPS:
      return 1;
    case TPM_CC_ChangeEPS:
      return 1;
    case TPM_CC_Clear:
      return 1;
    case TPM_CC_ClearControl:
      return 1;
    case TPM_CC_HierarchyChangeAuth:
      return 1;
    case TPM_CC_DictionaryAttackLockReset:
      return 1;
    case TPM_CC_DictionaryAttackParameters:
      return 1;
    case TPM_CC_PP_Commands:
      return 1;
    case TPM_CC_SetAlgorithmSet:
      return 1;
    case TPM_CC_FieldUpgradeStart:
      return 2;
    case TPM_CC_FieldUpgradeData:
      return 0;
    case TPM_CC_FirmwareRead:
      return 0;
    case TPM_CC_ContextSave:
      return 1;
    case TPM_CC_ContextLoad:
      return 0;
    case TPM_CC_FlushContext:
      return 0;
    case TPM_CC_EvictControl:
      return 2;
    case TPM_CC_ReadClock:
      return 0;
    case TPM_CC_ClockSet:
      return 1;
    case TPM_CC_ClockRateAdjust:
      return 1;
    case TPM_CC_GetCapability:
      return 0;
    case TPM_CC_TestParms:
      return 0;
    case TPM_CC_NV_DefineSpace:
      return 1;
    case TPM_CC_NV_UndefineSpace:
      return 2;
    case TPM_CC_NV_UndefineSpaceSpecial:
      return 2;
    case TPM_CC_NV_ReadPublic:
      return 1;
    case TPM_CC_NV_Write:
      return 2;
    case TPM_CC_NV_Increment:
      return 2;
    case TPM_CC_NV_Extend:
      return 2;
    case TPM_CC_NV_SetBits:
      return 2;
    case TPM_CC_NV_WriteLock:
      return 2;
    case TPM_CC_NV_GlobalWriteLock:
      return 1;
    case TPM_CC_NV_Read:
      return 2;
    case TPM_CC_NV_ReadLock:
      return 2;
    case TPM_CC_NV_ChangeAuth:
      return 1;
    case TPM_CC_NV_Certify:
      return 3;
    case TPM_CCE_PolicyFidoSigned:
      return 2;
    default:
      break;
  }
  return 0;
}

size_t GetNumberOfResponseHandles(TPM_CC command_code) {
  switch (command_code) {
    case TPM_CC_Startup:
      return 0;
    case TPM_CC_Shutdown:
      return 0;
    case TPM_CC_SelfTest:
      return 0;
    case TPM_CC_IncrementalSelfTest:
      return 0;
    case TPM_CC_GetTestResult:
      return 0;
    case TPM_CC_StartAuthSession:
      return 1;
    case TPM_CC_PolicyRestart:
      return 0;
    case TPM_CC_Create:
      return 0;
    case TPM_CC_Load:
      return 1;
    case TPM_CC_LoadExternal:
      return 1;
    case TPM_CC_ReadPublic:
      return 0;
    case TPM_CC_ActivateCredential:
      return 0;
    case TPM_CC_MakeCredential:
      return 0;
    case TPM_CC_Unseal:
      return 0;
    case TPM_CC_ObjectChangeAuth:
      return 0;
    case TPM_CC_Duplicate:
      return 0;
    case TPM_CC_Rewrap:
      return 0;
    case TPM_CC_Import:
      return 0;
    case TPM_CC_RSA_Encrypt:
      return 0;
    case TPM_CC_RSA_Decrypt:
      return 0;
    case TPM_CC_ECDH_KeyGen:
      return 0;
    case TPM_CC_ECDH_ZGen:
      return 0;
    case TPM_CC_ECC_Parameters:
      return 0;
    case TPM_CC_ZGen_2Phase:
      return 0;
    case TPM_CC_EncryptDecrypt:
      return 0;
    case TPM_CC_Hash:
      return 0;
    case TPM_CC_HMAC:
      return 0;
    case TPM_CC_GetRandom:
      return 0;
    case TPM_CC_StirRandom:
      return 0;
    case TPM_CC_HMAC_Start:
      return 1;
    case TPM_CC_HashSequenceStart:
      return 1;
    case TPM_CC_SequenceUpdate:
      return 0;
    case TPM_CC_SequenceComplete:
      return 0;
    case TPM_CC_EventSequenceComplete:
      return 0;
    case TPM_CC_Certify:
      return 0;
    case TPM_CC_CertifyCreation:
      return 0;
    case TPM_CC_Quote:
      return 0;
    case TPM_CC_GetSessionAuditDigest:
      return 0;
    case TPM_CC_GetCommandAuditDigest:
      return 0;
    case TPM_CC_GetTime:
      return 0;
    case TPM_CC_Commit:
      return 0;
    case TPM_CC_EC_Ephemeral:
      return 0;
    case TPM_CC_VerifySignature:
      return 0;
    case TPM_CC_Sign:
      return 0;
    case TPM_CC_SetCommandCodeAuditStatus:
      return 0;
    case TPM_CC_PCR_Extend:
      return 0;
    case TPM_CC_PCR_Event:
      return 0;
    case TPM_CC_PCR_Read:
      return 0;
    case TPM_CC_PCR_Allocate:
      return 0;
    case TPM_CC_PCR_SetAuthPolicy:
      return 0;
    case TPM_CC_PCR_SetAuthValue:
      return 0;
    case TPM_CC_PCR_Reset:
      return 0;
    case TPM_CC_PolicySigned:
      return 0;
    case TPM_CC_PolicySecret:
      return 0;
    case TPM_CC_PolicyTicket:
      return 0;
    case TPM_CC_PolicyOR:
      return 0;
    case TPM_CC_PolicyPCR:
      return 0;
    case TPM_CC_PolicyLocality:
      return 0;
    case TPM_CC_PolicyNV:
      return 0;
    case TPM_CC_PolicyCounterTimer:
      return 0;
    case TPM_CC_PolicyCommandCode:
      return 0;
    case TPM_CC_PolicyPhysicalPresence:
      return 0;
    case TPM_CC_PolicyCpHash:
      return 0;
    case TPM_CC_PolicyNameHash:
      return 0;
    case TPM_CC_PolicyDuplicationSelect:
      return 0;
    case TPM_CC_PolicyAuthorize:
      return 0;
    case TPM_CC_PolicyAuthValue:
      return 0;
    case TPM_CC_PolicyPassword:
      return 0;
    case TPM_CC_PolicyGetDigest:
      return 0;
    case TPM_CC_PolicyNvWritten:
      return 0;
    case TPM_CC_CreatePrimary:
      return 1;
    case TPM_CC_HierarchyControl:
      return 0;
    case TPM_CC_SetPrimaryPolicy:
      return 0;
    case TPM_CC_ChangePPS:
      return 0;
    case TPM_CC_ChangeEPS:
      return 0;
    case TPM_CC_Clear:
      return 0;
    case TPM_CC_ClearControl:
      return 0;
    case TPM_CC_HierarchyChangeAuth:
      return 0;
    case TPM_CC_DictionaryAttackLockReset:
      return 0;
    case TPM_CC_DictionaryAttackParameters:
      return 0;
    case TPM_CC_PP_Commands:
      return 0;
    case TPM_CC_SetAlgorithmSet:
      return 0;
    case TPM_CC_FieldUpgradeStart:
      return 0;
    case TPM_CC_FieldUpgradeData:
      return 0;
    case TPM_CC_FirmwareRead:
      return 0;
    case TPM_CC_ContextSave:
      return 0;
    case TPM_CC_ContextLoad:
      return 1;
    case TPM_CC_FlushContext:
      return 0;
    case TPM_CC_EvictControl:
      return 0;
    case TPM_CC_ReadClock:
      return 0;
    case TPM_CC_ClockSet:
      return 0;
    case TPM_CC_ClockRateAdjust:
      return 0;
    case TPM_CC_GetCapability:
      return 0;
    case TPM_CC_TestParms:
      return 0;
    case TPM_CC_NV_DefineSpace:
      return 0;
    case TPM_CC_NV_UndefineSpace:
      return 0;
    case TPM_CC_NV_UndefineSpaceSpecial:
      return 0;
    case TPM_CC_NV_ReadPublic:
      return 0;
    case TPM_CC_NV_Write:
      return 0;
    case TPM_CC_NV_Increment:
      return 0;
    case TPM_CC_NV_Extend:
      return 0;
    case TPM_CC_NV_SetBits:
      return 0;
    case TPM_CC_NV_WriteLock:
      return 0;
    case TPM_CC_NV_GlobalWriteLock:
      return 0;
    case TPM_CC_NV_Read:
      return 0;
    case TPM_CC_NV_ReadLock:
      return 0;
    case TPM_CC_NV_ChangeAuth:
      return 0;
    case TPM_CC_NV_Certify:
      return 0;
    case TPM_CCE_PolicyFidoSigned:
      return 0;
    default:
      break;
  }
  return 0;
}

TPM_RC Serialize_uint8_t(const uint8_t& value, std::string* buffer) {
  uint8_t value_net = value;
  switch (sizeof(uint8_t)) {
    case 2:
      value_net = htobe16(value);
      break;
    case 4:
      value_net = htobe32(value);
      break;
    case 8:
      value_net = htobe64(value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  buffer->append(value_bytes, sizeof(uint8_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_uint8_t(std::string* buffer,
                     uint8_t* value,
                     std::string* value_bytes) {
  if (buffer->size() < sizeof(uint8_t))
    return TPM_RC_INSUFFICIENT;
  uint8_t value_net = 0;
  memcpy(&value_net, buffer->data(), sizeof(uint8_t));
  switch (sizeof(uint8_t)) {
    case 2:
      *value = be16toh(value_net);
      break;
    case 4:
      *value = be32toh(value_net);
      break;
    case 8:
      *value = be64toh(value_net);
      break;
    default:
      *value = value_net;
  }
  if (value_bytes) {
    value_bytes->append(buffer->substr(0, sizeof(uint8_t)));
  }
  buffer->erase(0, sizeof(uint8_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_int8_t(const int8_t& value, std::string* buffer) {
  int8_t value_net = value;
  switch (sizeof(int8_t)) {
    case 2:
      value_net = htobe16(value);
      break;
    case 4:
      value_net = htobe32(value);
      break;
    case 8:
      value_net = htobe64(value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  buffer->append(value_bytes, sizeof(int8_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_int8_t(std::string* buffer,
                    int8_t* value,
                    std::string* value_bytes) {
  if (buffer->size() < sizeof(int8_t))
    return TPM_RC_INSUFFICIENT;
  int8_t value_net = 0;
  memcpy(&value_net, buffer->data(), sizeof(int8_t));
  switch (sizeof(int8_t)) {
    case 2:
      *value = be16toh(value_net);
      break;
    case 4:
      *value = be32toh(value_net);
      break;
    case 8:
      *value = be64toh(value_net);
      break;
    default:
      *value = value_net;
  }
  if (value_bytes) {
    value_bytes->append(buffer->substr(0, sizeof(int8_t)));
  }
  buffer->erase(0, sizeof(int8_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_int(const int& value, std::string* buffer) {
  int value_net = value;
  switch (sizeof(int)) {
    case 2:
      value_net = htobe16(value);
      break;
    case 4:
      value_net = htobe32(value);
      break;
    case 8:
      value_net = htobe64(value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  buffer->append(value_bytes, sizeof(int));
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_int(std::string* buffer, int* value, std::string* value_bytes) {
  if (buffer->size() < sizeof(int))
    return TPM_RC_INSUFFICIENT;
  int value_net = 0;
  memcpy(&value_net, buffer->data(), sizeof(int));
  switch (sizeof(int)) {
    case 2:
      *value = be16toh(value_net);
      break;
    case 4:
      *value = be32toh(value_net);
      break;
    case 8:
      *value = be64toh(value_net);
      break;
    default:
      *value = value_net;
  }
  if (value_bytes) {
    value_bytes->append(buffer->substr(0, sizeof(int)));
  }
  buffer->erase(0, sizeof(int));
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_uint16_t(const uint16_t& value, std::string* buffer) {
  uint16_t value_net = value;
  switch (sizeof(uint16_t)) {
    case 2:
      value_net = htobe16(value);
      break;
    case 4:
      value_net = htobe32(value);
      break;
    case 8:
      value_net = htobe64(value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  buffer->append(value_bytes, sizeof(uint16_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_uint16_t(std::string* buffer,
                      uint16_t* value,
                      std::string* value_bytes) {
  if (buffer->size() < sizeof(uint16_t))
    return TPM_RC_INSUFFICIENT;
  uint16_t value_net = 0;
  memcpy(&value_net, buffer->data(), sizeof(uint16_t));
  switch (sizeof(uint16_t)) {
    case 2:
      *value = be16toh(value_net);
      break;
    case 4:
      *value = be32toh(value_net);
      break;
    case 8:
      *value = be64toh(value_net);
      break;
    default:
      *value = value_net;
  }
  if (value_bytes) {
    value_bytes->append(buffer->substr(0, sizeof(uint16_t)));
  }
  buffer->erase(0, sizeof(uint16_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_int16_t(const int16_t& value, std::string* buffer) {
  int16_t value_net = value;
  switch (sizeof(int16_t)) {
    case 2:
      value_net = htobe16(value);
      break;
    case 4:
      value_net = htobe32(value);
      break;
    case 8:
      value_net = htobe64(value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  buffer->append(value_bytes, sizeof(int16_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_int16_t(std::string* buffer,
                     int16_t* value,
                     std::string* value_bytes) {
  if (buffer->size() < sizeof(int16_t))
    return TPM_RC_INSUFFICIENT;
  int16_t value_net = 0;
  memcpy(&value_net, buffer->data(), sizeof(int16_t));
  switch (sizeof(int16_t)) {
    case 2:
      *value = be16toh(value_net);
      break;
    case 4:
      *value = be32toh(value_net);
      break;
    case 8:
      *value = be64toh(value_net);
      break;
    default:
      *value = value_net;
  }
  if (value_bytes) {
    value_bytes->append(buffer->substr(0, sizeof(int16_t)));
  }
  buffer->erase(0, sizeof(int16_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_uint32_t(const uint32_t& value, std::string* buffer) {
  uint32_t value_net = value;
  switch (sizeof(uint32_t)) {
    case 2:
      value_net = htobe16(value);
      break;
    case 4:
      value_net = htobe32(value);
      break;
    case 8:
      value_net = htobe64(value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  buffer->append(value_bytes, sizeof(uint32_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_uint32_t(std::string* buffer,
                      uint32_t* value,
                      std::string* value_bytes) {
  if (buffer->size() < sizeof(uint32_t))
    return TPM_RC_INSUFFICIENT;
  uint32_t value_net = 0;
  memcpy(&value_net, buffer->data(), sizeof(uint32_t));
  switch (sizeof(uint32_t)) {
    case 2:
      *value = be16toh(value_net);
      break;
    case 4:
      *value = be32toh(value_net);
      break;
    case 8:
      *value = be64toh(value_net);
      break;
    default:
      *value = value_net;
  }
  if (value_bytes) {
    value_bytes->append(buffer->substr(0, sizeof(uint32_t)));
  }
  buffer->erase(0, sizeof(uint32_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_int32_t(const int32_t& value, std::string* buffer) {
  int32_t value_net = value;
  switch (sizeof(int32_t)) {
    case 2:
      value_net = htobe16(value);
      break;
    case 4:
      value_net = htobe32(value);
      break;
    case 8:
      value_net = htobe64(value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  buffer->append(value_bytes, sizeof(int32_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_int32_t(std::string* buffer,
                     int32_t* value,
                     std::string* value_bytes) {
  if (buffer->size() < sizeof(int32_t))
    return TPM_RC_INSUFFICIENT;
  int32_t value_net = 0;
  memcpy(&value_net, buffer->data(), sizeof(int32_t));
  switch (sizeof(int32_t)) {
    case 2:
      *value = be16toh(value_net);
      break;
    case 4:
      *value = be32toh(value_net);
      break;
    case 8:
      *value = be64toh(value_net);
      break;
    default:
      *value = value_net;
  }
  if (value_bytes) {
    value_bytes->append(buffer->substr(0, sizeof(int32_t)));
  }
  buffer->erase(0, sizeof(int32_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_uint64_t(const uint64_t& value, std::string* buffer) {
  uint64_t value_net = value;
  switch (sizeof(uint64_t)) {
    case 2:
      value_net = htobe16(value);
      break;
    case 4:
      value_net = htobe32(value);
      break;
    case 8:
      value_net = htobe64(value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  buffer->append(value_bytes, sizeof(uint64_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_uint64_t(std::string* buffer,
                      uint64_t* value,
                      std::string* value_bytes) {
  if (buffer->size() < sizeof(uint64_t))
    return TPM_RC_INSUFFICIENT;
  uint64_t value_net = 0;
  memcpy(&value_net, buffer->data(), sizeof(uint64_t));
  switch (sizeof(uint64_t)) {
    case 2:
      *value = be16toh(value_net);
      break;
    case 4:
      *value = be32toh(value_net);
      break;
    case 8:
      *value = be64toh(value_net);
      break;
    default:
      *value = value_net;
  }
  if (value_bytes) {
    value_bytes->append(buffer->substr(0, sizeof(uint64_t)));
  }
  buffer->erase(0, sizeof(uint64_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_int64_t(const int64_t& value, std::string* buffer) {
  int64_t value_net = value;
  switch (sizeof(int64_t)) {
    case 2:
      value_net = htobe16(value);
      break;
    case 4:
      value_net = htobe32(value);
      break;
    case 8:
      value_net = htobe64(value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  buffer->append(value_bytes, sizeof(int64_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Parse_int64_t(std::string* buffer,
                     int64_t* value,
                     std::string* value_bytes) {
  if (buffer->size() < sizeof(int64_t))
    return TPM_RC_INSUFFICIENT;
  int64_t value_net = 0;
  memcpy(&value_net, buffer->data(), sizeof(int64_t));
  switch (sizeof(int64_t)) {
    case 2:
      *value = be16toh(value_net);
      break;
    case 4:
      *value = be32toh(value_net);
      break;
    case 8:
      *value = be64toh(value_net);
      break;
    default:
      *value = value_net;
  }
  if (value_bytes) {
    value_bytes->append(buffer->substr(0, sizeof(int64_t)));
  }
  buffer->erase(0, sizeof(int64_t));
  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_UINT8(const UINT8& value, std::string* buffer) {
  return Serialize_uint8_t(value, buffer);
}

TPM_RC Parse_UINT8(std::string* buffer,
                   UINT8* value,
                   std::string* value_bytes) {
  return Parse_uint8_t(buffer, value, value_bytes);
}

TPM_RC Serialize_BYTE(const BYTE& value, std::string* buffer) {
  return Serialize_uint8_t(value, buffer);
}

TPM_RC Parse_BYTE(std::string* buffer, BYTE* value, std::string* value_bytes) {
  return Parse_uint8_t(buffer, value, value_bytes);
}

TPM_RC Serialize_INT8(const INT8& value, std::string* buffer) {
  return Serialize_int8_t(value, buffer);
}

TPM_RC Parse_INT8(std::string* buffer, INT8* value, std::string* value_bytes) {
  return Parse_int8_t(buffer, value, value_bytes);
}

TPM_RC Serialize_BOOL(const BOOL& value, std::string* buffer) {
  return Serialize_int(value, buffer);
}

TPM_RC Parse_BOOL(std::string* buffer, BOOL* value, std::string* value_bytes) {
  return Parse_int(buffer, value, value_bytes);
}

TPM_RC Serialize_UINT16(const UINT16& value, std::string* buffer) {
  return Serialize_uint16_t(value, buffer);
}

TPM_RC Parse_UINT16(std::string* buffer,
                    UINT16* value,
                    std::string* value_bytes) {
  return Parse_uint16_t(buffer, value, value_bytes);
}

TPM_RC Serialize_INT16(const INT16& value, std::string* buffer) {
  return Serialize_int16_t(value, buffer);
}

TPM_RC Parse_INT16(std::string* buffer,
                   INT16* value,
                   std::string* value_bytes) {
  return Parse_int16_t(buffer, value, value_bytes);
}

TPM_RC Serialize_UINT32(const UINT32& value, std::string* buffer) {
  return Serialize_uint32_t(value, buffer);
}

TPM_RC Parse_UINT32(std::string* buffer,
                    UINT32* value,
                    std::string* value_bytes) {
  return Parse_uint32_t(buffer, value, value_bytes);
}

TPM_RC Serialize_INT32(const INT32& value, std::string* buffer) {
  return Serialize_int32_t(value, buffer);
}

TPM_RC Parse_INT32(std::string* buffer,
                   INT32* value,
                   std::string* value_bytes) {
  return Parse_int32_t(buffer, value, value_bytes);
}

TPM_RC Serialize_UINT64(const UINT64& value, std::string* buffer) {
  return Serialize_uint64_t(value, buffer);
}

TPM_RC Parse_UINT64(std::string* buffer,
                    UINT64* value,
                    std::string* value_bytes) {
  return Parse_uint64_t(buffer, value, value_bytes);
}

TPM_RC Serialize_INT64(const INT64& value, std::string* buffer) {
  return Serialize_int64_t(value, buffer);
}

TPM_RC Parse_INT64(std::string* buffer,
                   INT64* value,
                   std::string* value_bytes) {
  return Parse_int64_t(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_ALGORITHM_ID(const TPM_ALGORITHM_ID& value,
                                  std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_ALGORITHM_ID(std::string* buffer,
                              TPM_ALGORITHM_ID* value,
                              std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_MODIFIER_INDICATOR(const TPM_MODIFIER_INDICATOR& value,
                                        std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_MODIFIER_INDICATOR(std::string* buffer,
                                    TPM_MODIFIER_INDICATOR* value,
                                    std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_AUTHORIZATION_SIZE(const TPM_AUTHORIZATION_SIZE& value,
                                        std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_AUTHORIZATION_SIZE(std::string* buffer,
                                    TPM_AUTHORIZATION_SIZE* value,
                                    std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_PARAMETER_SIZE(const TPM_PARAMETER_SIZE& value,
                                    std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_PARAMETER_SIZE(std::string* buffer,
                                TPM_PARAMETER_SIZE* value,
                                std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_KEY_SIZE(const TPM_KEY_SIZE& value, std::string* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_KEY_SIZE(std::string* buffer,
                          TPM_KEY_SIZE* value,
                          std::string* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_KEY_BITS(const TPM_KEY_BITS& value, std::string* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_KEY_BITS(std::string* buffer,
                          TPM_KEY_BITS* value,
                          std::string* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_HANDLE(const TPM_HANDLE& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_HANDLE(std::string* buffer,
                        TPM_HANDLE* value,
                        std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM2B_DIGEST(const TPM2B_DIGEST& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_DIGEST(std::string* buffer,
                          TPM2B_DIGEST* value,
                          std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_NONCE(const TPM2B_NONCE& value, std::string* buffer) {
  return Serialize_TPM2B_DIGEST(value, buffer);
}

TPM_RC Parse_TPM2B_NONCE(std::string* buffer,
                         TPM2B_NONCE* value,
                         std::string* value_bytes) {
  return Parse_TPM2B_DIGEST(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM2B_AUTH(const TPM2B_AUTH& value, std::string* buffer) {
  return Serialize_TPM2B_DIGEST(value, buffer);
}

TPM_RC Parse_TPM2B_AUTH(std::string* buffer,
                        TPM2B_AUTH* value,
                        std::string* value_bytes) {
  return Parse_TPM2B_DIGEST(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM2B_OPERAND(const TPM2B_OPERAND& value,
                               std::string* buffer) {
  return Serialize_TPM2B_DIGEST(value, buffer);
}

TPM_RC Parse_TPM2B_OPERAND(std::string* buffer,
                           TPM2B_OPERAND* value,
                           std::string* value_bytes) {
  return Parse_TPM2B_DIGEST(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_ALG_ID(const TPM_ALG_ID& value, std::string* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_ALG_ID(std::string* buffer,
                        TPM_ALG_ID* value,
                        std::string* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_HASH(const TPMI_ALG_HASH& value,
                               std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_HASH(std::string* buffer,
                           TPMI_ALG_HASH* value,
                           std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_SIGHASH(const TPMS_SCHEME_SIGHASH& value,
                                     std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_SIGHASH(std::string* buffer,
                                 TPMS_SCHEME_SIGHASH* value,
                                 std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_HMAC(const TPMS_SCHEME_HMAC& value,
                                  std::string* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_HMAC(std::string* buffer,
                              TPMS_SCHEME_HMAC* value,
                              std::string* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_RSASSA(const TPMS_SCHEME_RSASSA& value,
                                    std::string* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_RSASSA(std::string* buffer,
                                TPMS_SCHEME_RSASSA* value,
                                std::string* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_RSAPSS(const TPMS_SCHEME_RSAPSS& value,
                                    std::string* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_RSAPSS(std::string* buffer,
                                TPMS_SCHEME_RSAPSS* value,
                                std::string* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_ECDSA(const TPMS_SCHEME_ECDSA& value,
                                   std::string* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_ECDSA(std::string* buffer,
                               TPMS_SCHEME_ECDSA* value,
                               std::string* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_SM2(const TPMS_SCHEME_SM2& value,
                                 std::string* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_SM2(std::string* buffer,
                             TPMS_SCHEME_SM2* value,
                             std::string* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_ECSCHNORR(const TPMS_SCHEME_ECSCHNORR& value,
                                       std::string* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_ECSCHNORR(std::string* buffer,
                                   TPMS_SCHEME_ECSCHNORR* value,
                                   std::string* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_YES_NO(const TPMI_YES_NO& value, std::string* buffer) {
  return Serialize_BYTE(value, buffer);
}

TPM_RC Parse_TPMI_YES_NO(std::string* buffer,
                         TPMI_YES_NO* value,
                         std::string* value_bytes) {
  return Parse_BYTE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_DH_OBJECT(const TPMI_DH_OBJECT& value,
                                std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_DH_OBJECT(std::string* buffer,
                            TPMI_DH_OBJECT* value,
                            std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_DH_PERSISTENT(const TPMI_DH_PERSISTENT& value,
                                    std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_DH_PERSISTENT(std::string* buffer,
                                TPMI_DH_PERSISTENT* value,
                                std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_DH_ENTITY(const TPMI_DH_ENTITY& value,
                                std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_DH_ENTITY(std::string* buffer,
                            TPMI_DH_ENTITY* value,
                            std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_DH_PCR(const TPMI_DH_PCR& value, std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_DH_PCR(std::string* buffer,
                         TPMI_DH_PCR* value,
                         std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_SH_AUTH_SESSION(const TPMI_SH_AUTH_SESSION& value,
                                      std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_SH_AUTH_SESSION(std::string* buffer,
                                  TPMI_SH_AUTH_SESSION* value,
                                  std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_SH_HMAC(const TPMI_SH_HMAC& value, std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_SH_HMAC(std::string* buffer,
                          TPMI_SH_HMAC* value,
                          std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_SH_POLICY(const TPMI_SH_POLICY& value,
                                std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_SH_POLICY(std::string* buffer,
                            TPMI_SH_POLICY* value,
                            std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_DH_CONTEXT(const TPMI_DH_CONTEXT& value,
                                 std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_DH_CONTEXT(std::string* buffer,
                             TPMI_DH_CONTEXT* value,
                             std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_HIERARCHY(const TPMI_RH_HIERARCHY& value,
                                   std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_HIERARCHY(std::string* buffer,
                               TPMI_RH_HIERARCHY* value,
                               std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_ENABLES(const TPMI_RH_ENABLES& value,
                                 std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_ENABLES(std::string* buffer,
                             TPMI_RH_ENABLES* value,
                             std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_HIERARCHY_AUTH(const TPMI_RH_HIERARCHY_AUTH& value,
                                        std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_HIERARCHY_AUTH(std::string* buffer,
                                    TPMI_RH_HIERARCHY_AUTH* value,
                                    std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_PLATFORM(const TPMI_RH_PLATFORM& value,
                                  std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_PLATFORM(std::string* buffer,
                              TPMI_RH_PLATFORM* value,
                              std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_OWNER(const TPMI_RH_OWNER& value,
                               std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_OWNER(std::string* buffer,
                           TPMI_RH_OWNER* value,
                           std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_ENDORSEMENT(const TPMI_RH_ENDORSEMENT& value,
                                     std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_ENDORSEMENT(std::string* buffer,
                                 TPMI_RH_ENDORSEMENT* value,
                                 std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_PROVISION(const TPMI_RH_PROVISION& value,
                                   std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_PROVISION(std::string* buffer,
                               TPMI_RH_PROVISION* value,
                               std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_CLEAR(const TPMI_RH_CLEAR& value,
                               std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_CLEAR(std::string* buffer,
                           TPMI_RH_CLEAR* value,
                           std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_NV_AUTH(const TPMI_RH_NV_AUTH& value,
                                 std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_NV_AUTH(std::string* buffer,
                             TPMI_RH_NV_AUTH* value,
                             std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_LOCKOUT(const TPMI_RH_LOCKOUT& value,
                                 std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_LOCKOUT(std::string* buffer,
                             TPMI_RH_LOCKOUT* value,
                             std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_NV_INDEX(const TPMI_RH_NV_INDEX& value,
                                  std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_NV_INDEX(std::string* buffer,
                              TPMI_RH_NV_INDEX* value,
                              std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_ASYM(const TPMI_ALG_ASYM& value,
                               std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_ASYM(std::string* buffer,
                           TPMI_ALG_ASYM* value,
                           std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_SYM(const TPMI_ALG_SYM& value, std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_SYM(std::string* buffer,
                          TPMI_ALG_SYM* value,
                          std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_SYM_OBJECT(const TPMI_ALG_SYM_OBJECT& value,
                                     std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_SYM_OBJECT(std::string* buffer,
                                 TPMI_ALG_SYM_OBJECT* value,
                                 std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_SYM_MODE(const TPMI_ALG_SYM_MODE& value,
                                   std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_SYM_MODE(std::string* buffer,
                               TPMI_ALG_SYM_MODE* value,
                               std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_KDF(const TPMI_ALG_KDF& value, std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_KDF(std::string* buffer,
                          TPMI_ALG_KDF* value,
                          std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_SIG_SCHEME(const TPMI_ALG_SIG_SCHEME& value,
                                     std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_SIG_SCHEME(std::string* buffer,
                                 TPMI_ALG_SIG_SCHEME* value,
                                 std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ECC_KEY_EXCHANGE(const TPMI_ECC_KEY_EXCHANGE& value,
                                       std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ECC_KEY_EXCHANGE(std::string* buffer,
                                   TPMI_ECC_KEY_EXCHANGE* value,
                                   std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_ST(const TPM_ST& value, std::string* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_ST(std::string* buffer,
                    TPM_ST* value,
                    std::string* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ST_COMMAND_TAG(const TPMI_ST_COMMAND_TAG& value,
                                     std::string* buffer) {
  return Serialize_TPM_ST(value, buffer);
}

TPM_RC Parse_TPMI_ST_COMMAND_TAG(std::string* buffer,
                                 TPMI_ST_COMMAND_TAG* value,
                                 std::string* value_bytes) {
  return Parse_TPM_ST(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ST_ATTEST(const TPMI_ST_ATTEST& value,
                                std::string* buffer) {
  return Serialize_TPM_ST(value, buffer);
}

TPM_RC Parse_TPMI_ST_ATTEST(std::string* buffer,
                            TPMI_ST_ATTEST* value,
                            std::string* value_bytes) {
  return Parse_TPM_ST(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_AES_KEY_BITS(const TPMI_AES_KEY_BITS& value,
                                   std::string* buffer) {
  return Serialize_TPM_KEY_BITS(value, buffer);
}

TPM_RC Parse_TPMI_AES_KEY_BITS(std::string* buffer,
                               TPMI_AES_KEY_BITS* value,
                               std::string* value_bytes) {
  return Parse_TPM_KEY_BITS(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_SM4_KEY_BITS(const TPMI_SM4_KEY_BITS& value,
                                   std::string* buffer) {
  return Serialize_TPM_KEY_BITS(value, buffer);
}

TPM_RC Parse_TPMI_SM4_KEY_BITS(std::string* buffer,
                               TPMI_SM4_KEY_BITS* value,
                               std::string* value_bytes) {
  return Parse_TPM_KEY_BITS(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_KEYEDHASH_SCHEME(
    const TPMI_ALG_KEYEDHASH_SCHEME& value, std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_KEYEDHASH_SCHEME(std::string* buffer,
                                       TPMI_ALG_KEYEDHASH_SCHEME* value,
                                       std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_ASYM_SCHEME(const TPMI_ALG_ASYM_SCHEME& value,
                                      std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_ASYM_SCHEME(std::string* buffer,
                                  TPMI_ALG_ASYM_SCHEME* value,
                                  std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_RSA_SCHEME(const TPMI_ALG_RSA_SCHEME& value,
                                     std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_RSA_SCHEME(std::string* buffer,
                                 TPMI_ALG_RSA_SCHEME* value,
                                 std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_RSA_DECRYPT(const TPMI_ALG_RSA_DECRYPT& value,
                                      std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_RSA_DECRYPT(std::string* buffer,
                                  TPMI_ALG_RSA_DECRYPT* value,
                                  std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RSA_KEY_BITS(const TPMI_RSA_KEY_BITS& value,
                                   std::string* buffer) {
  return Serialize_TPM_KEY_BITS(value, buffer);
}

TPM_RC Parse_TPMI_RSA_KEY_BITS(std::string* buffer,
                               TPMI_RSA_KEY_BITS* value,
                               std::string* value_bytes) {
  return Parse_TPM_KEY_BITS(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_ECC_SCHEME(const TPMI_ALG_ECC_SCHEME& value,
                                     std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_ECC_SCHEME(std::string* buffer,
                                 TPMI_ALG_ECC_SCHEME* value,
                                 std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_ECC_CURVE(const TPM_ECC_CURVE& value,
                               std::string* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_ECC_CURVE(std::string* buffer,
                           TPM_ECC_CURVE* value,
                           std::string* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ECC_CURVE(const TPMI_ECC_CURVE& value,
                                std::string* buffer) {
  return Serialize_TPM_ECC_CURVE(value, buffer);
}

TPM_RC Parse_TPMI_ECC_CURVE(std::string* buffer,
                            TPMI_ECC_CURVE* value,
                            std::string* value_bytes) {
  return Parse_TPM_ECC_CURVE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_PUBLIC(const TPMI_ALG_PUBLIC& value,
                                 std::string* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_PUBLIC(std::string* buffer,
                             TPMI_ALG_PUBLIC* value,
                             std::string* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_ALGORITHM(const TPMA_ALGORITHM& value,
                                std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_ALGORITHM(std::string* buffer,
                            TPMA_ALGORITHM* value,
                            std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_OBJECT(const TPMA_OBJECT& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_OBJECT(std::string* buffer,
                         TPMA_OBJECT* value,
                         std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_SESSION(const TPMA_SESSION& value, std::string* buffer) {
  return Serialize_UINT8(value, buffer);
}

TPM_RC Parse_TPMA_SESSION(std::string* buffer,
                          TPMA_SESSION* value,
                          std::string* value_bytes) {
  return Parse_UINT8(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_LOCALITY(const TPMA_LOCALITY& value,
                               std::string* buffer) {
  return Serialize_UINT8(value, buffer);
}

TPM_RC Parse_TPMA_LOCALITY(std::string* buffer,
                           TPMA_LOCALITY* value,
                           std::string* value_bytes) {
  return Parse_UINT8(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_PERMANENT(const TPMA_PERMANENT& value,
                                std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_PERMANENT(std::string* buffer,
                            TPMA_PERMANENT* value,
                            std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_STARTUP_CLEAR(const TPMA_STARTUP_CLEAR& value,
                                    std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_STARTUP_CLEAR(std::string* buffer,
                                TPMA_STARTUP_CLEAR* value,
                                std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_MEMORY(const TPMA_MEMORY& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_MEMORY(std::string* buffer,
                         TPMA_MEMORY* value,
                         std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_CC(const TPM_CC& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_CC(std::string* buffer,
                    TPM_CC* value,
                    std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_CC(const TPMA_CC& value, std::string* buffer) {
  return Serialize_TPM_CC(value, buffer);
}

TPM_RC Parse_TPMA_CC(std::string* buffer,
                     TPMA_CC* value,
                     std::string* value_bytes) {
  return Parse_TPM_CC(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_NV_INDEX(const TPM_NV_INDEX& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_NV_INDEX(std::string* buffer,
                          TPM_NV_INDEX* value,
                          std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_NV(const TPMA_NV& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_NV(std::string* buffer,
                     TPMA_NV* value,
                     std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_SPEC(const TPM_SPEC& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_SPEC(std::string* buffer,
                      TPM_SPEC* value,
                      std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_GENERATED(const TPM_GENERATED& value,
                               std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_GENERATED(std::string* buffer,
                           TPM_GENERATED* value,
                           std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_RC(const TPM_RC& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_RC(std::string* buffer,
                    TPM_RC* value,
                    std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_CLOCK_ADJUST(const TPM_CLOCK_ADJUST& value,
                                  std::string* buffer) {
  return Serialize_INT8(value, buffer);
}

TPM_RC Parse_TPM_CLOCK_ADJUST(std::string* buffer,
                              TPM_CLOCK_ADJUST* value,
                              std::string* value_bytes) {
  return Parse_INT8(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_EO(const TPM_EO& value, std::string* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_EO(std::string* buffer,
                    TPM_EO* value,
                    std::string* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_SU(const TPM_SU& value, std::string* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_SU(std::string* buffer,
                    TPM_SU* value,
                    std::string* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_SE(const TPM_SE& value, std::string* buffer) {
  return Serialize_UINT8(value, buffer);
}

TPM_RC Parse_TPM_SE(std::string* buffer,
                    TPM_SE* value,
                    std::string* value_bytes) {
  return Parse_UINT8(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_CAP(const TPM_CAP& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_CAP(std::string* buffer,
                     TPM_CAP* value,
                     std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_PT(const TPM_PT& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_PT(std::string* buffer,
                    TPM_PT* value,
                    std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_PT_PCR(const TPM_PT_PCR& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_PT_PCR(std::string* buffer,
                        TPM_PT_PCR* value,
                        std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_PS(const TPM_PS& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_PS(std::string* buffer,
                    TPM_PS* value,
                    std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_HT(const TPM_HT& value, std::string* buffer) {
  return Serialize_UINT8(value, buffer);
}

TPM_RC Parse_TPM_HT(std::string* buffer,
                    TPM_HT* value,
                    std::string* value_bytes) {
  return Parse_UINT8(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_RH(const TPM_RH& value, std::string* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_RH(std::string* buffer,
                    TPM_RH* value,
                    std::string* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_HC(const TPM_HC& value, std::string* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPM_HC(std::string* buffer,
                    TPM_HC* value,
                    std::string* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_ALGORITHM_DESCRIPTION(
  const TPMS_ALGORITHM_DESCRIPTION& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ALG_ID(value.alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_ALGORITHM(value.attributes, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ALGORITHM_DESCRIPTION(std::string* buffer,
                                        TPMS_ALGORITHM_DESCRIPTION* value,
                                        std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM_ALG_ID(buffer, &value->alg, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMA_ALGORITHM(buffer, &value->attributes, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMU_HA(const TPMU_HA& value,
                         TPMI_ALG_HASH selector,
                         std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_SHA384) {
    if (sizeof(value.sha384) < SHA384_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA384_DIGEST_SIZE; ++i) {
      result = Serialize_BYTE(value.sha384[i], buffer);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_SHA1) {
    if (sizeof(value.sha1) < SHA1_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA1_DIGEST_SIZE; ++i) {
      result = Serialize_BYTE(value.sha1[i], buffer);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_SM3_256) {
    if (sizeof(value.sm3_256) < SM3_256_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SM3_256_DIGEST_SIZE; ++i) {
      result = Serialize_BYTE(value.sm3_256[i], buffer);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_SHA256) {
    if (sizeof(value.sha256) < SHA256_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA256_DIGEST_SIZE; ++i) {
      result = Serialize_BYTE(value.sha256[i], buffer);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_SHA512) {
    if (sizeof(value.sha512) < SHA512_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA512_DIGEST_SIZE; ++i) {
      result = Serialize_BYTE(value.sha512[i], buffer);
      if (result) {
        return result;
      }
    }
  }
  return result;
}

TPM_RC Parse_TPMU_HA(std::string* buffer,
                     TPMI_ALG_HASH selector,
                     TPMU_HA* value,
                     std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_SHA384) {
    if (sizeof(value->sha384) < SHA384_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA384_DIGEST_SIZE; ++i) {
      result = Parse_BYTE(buffer, &value->sha384[i], value_bytes);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_SHA1) {
    if (sizeof(value->sha1) < SHA1_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA1_DIGEST_SIZE; ++i) {
      result = Parse_BYTE(buffer, &value->sha1[i], value_bytes);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_SM3_256) {
    if (sizeof(value->sm3_256) < SM3_256_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SM3_256_DIGEST_SIZE; ++i) {
      result = Parse_BYTE(buffer, &value->sm3_256[i], value_bytes);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_SHA256) {
    if (sizeof(value->sha256) < SHA256_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA256_DIGEST_SIZE; ++i) {
      result = Parse_BYTE(buffer, &value->sha256[i], value_bytes);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_SHA512) {
    if (sizeof(value->sha512) < SHA512_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA512_DIGEST_SIZE; ++i) {
      result = Parse_BYTE(buffer, &value->sha512[i], value_bytes);
      if (result) {
        return result;
      }
    }
  }
  return result;
}

TPM_RC Serialize_TPMT_HA(const TPMT_HA& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_HA(value.digest, value.hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_HA(std::string* buffer,
                     TPMT_HA* value,
                     std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_HA(buffer, value->hash_alg, &value->digest, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_DATA(const TPM2B_DATA& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_DATA(std::string* buffer,
                        TPM2B_DATA* value,
                        std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_EVENT(const TPM2B_EVENT& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_EVENT(std::string* buffer,
                         TPM2B_EVENT* value,
                         std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_MAX_BUFFER(const TPM2B_MAX_BUFFER& value,
                                  std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_MAX_BUFFER(std::string* buffer,
                              TPM2B_MAX_BUFFER* value,
                              std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_MAX_NV_BUFFER(const TPM2B_MAX_NV_BUFFER& value,
                                     std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_MAX_NV_BUFFER(std::string* buffer,
                                 TPM2B_MAX_NV_BUFFER* value,
                                 std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_TIMEOUT(const TPM2B_TIMEOUT& value,
                               std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_TIMEOUT(std::string* buffer,
                           TPM2B_TIMEOUT* value,
                           std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_IV(const TPM2B_IV& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_IV(std::string* buffer,
                      TPM2B_IV* value,
                      std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_NAME(const TPM2B_NAME& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.name) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.name[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_NAME(std::string* buffer,
                        TPM2B_NAME* value,
                        std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->name) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->name[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_PCR_SELECT(const TPMS_PCR_SELECT& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT8(value.sizeof_select, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.pcr_select) < value.sizeof_select) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.sizeof_select; ++i) {
    result = Serialize_BYTE(value.pcr_select[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMS_PCR_SELECT(std::string* buffer,
                             TPMS_PCR_SELECT* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT8(buffer, &value->sizeof_select, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->pcr_select) < value->sizeof_select) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->sizeof_select; ++i) {
    result = Parse_BYTE(buffer, &value->pcr_select[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_PCR_SELECTION(const TPMS_PCR_SELECTION& value,
                                    std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT8(value.sizeof_select, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.pcr_select) < value.sizeof_select) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.sizeof_select; ++i) {
    result = Serialize_BYTE(value.pcr_select[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMS_PCR_SELECTION(std::string* buffer,
                                TPMS_PCR_SELECTION* value,
                                std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT8(buffer, &value->sizeof_select, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->pcr_select) < value->sizeof_select) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->sizeof_select; ++i) {
    result = Parse_BYTE(buffer, &value->pcr_select[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMT_TK_CREATION(const TPMT_TK_CREATION& value,
                                  std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ST(value.tag, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RH_HIERARCHY(value.hierarchy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_TK_CREATION(std::string* buffer,
                              TPMT_TK_CREATION* value,
                              std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM_ST(buffer, &value->tag, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_RH_HIERARCHY(buffer, &value->hierarchy, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->digest, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMT_TK_VERIFIED(const TPMT_TK_VERIFIED& value,
                                  std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ST(value.tag, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RH_HIERARCHY(value.hierarchy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_TK_VERIFIED(std::string* buffer,
                              TPMT_TK_VERIFIED* value,
                              std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM_ST(buffer, &value->tag, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_RH_HIERARCHY(buffer, &value->hierarchy, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->digest, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMT_TK_AUTH(const TPMT_TK_AUTH& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ST(value.tag, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RH_HIERARCHY(value.hierarchy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_TK_AUTH(std::string* buffer,
                          TPMT_TK_AUTH* value,
                          std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM_ST(buffer, &value->tag, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_RH_HIERARCHY(buffer, &value->hierarchy, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->digest, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMT_TK_HASHCHECK(const TPMT_TK_HASHCHECK& value,
                                   std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ST(value.tag, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RH_HIERARCHY(value.hierarchy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_TK_HASHCHECK(std::string* buffer,
                               TPMT_TK_HASHCHECK* value,
                               std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM_ST(buffer, &value->tag, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_RH_HIERARCHY(buffer, &value->hierarchy, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->digest, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_ALG_PROPERTY(const TPMS_ALG_PROPERTY& value,
                                   std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ALG_ID(value.alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_ALGORITHM(value.alg_properties, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ALG_PROPERTY(std::string* buffer,
                               TPMS_ALG_PROPERTY* value,
                               std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM_ALG_ID(buffer, &value->alg, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMA_ALGORITHM(buffer, &value->alg_properties, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_TAGGED_PROPERTY(const TPMS_TAGGED_PROPERTY& value,
                                      std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_PT(value.property, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT32(value.value, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_TAGGED_PROPERTY(std::string* buffer,
                                  TPMS_TAGGED_PROPERTY* value,
                                  std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM_PT(buffer, &value->property, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT32(buffer, &value->value, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_TAGGED_PCR_SELECT(const TPMS_TAGGED_PCR_SELECT& value,
                                        std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_PT(value.tag, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT8(value.sizeof_select, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.pcr_select) < value.sizeof_select) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.sizeof_select; ++i) {
    result = Serialize_BYTE(value.pcr_select[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMS_TAGGED_PCR_SELECT(std::string* buffer,
                                    TPMS_TAGGED_PCR_SELECT* value,
                                    std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM_PT(buffer, &value->tag, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT8(buffer, &value->sizeof_select, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->pcr_select) < value->sizeof_select) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->sizeof_select; ++i) {
    result = Parse_BYTE(buffer, &value->pcr_select[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPML_CC(const TPML_CC& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(value.count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.command_codes) < value.count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.count; ++i) {
    result = Serialize_TPM_CC(value.command_codes[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_CC(std::string* buffer,
                     TPML_CC* value,
                     std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT32(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->command_codes) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Parse_TPM_CC(buffer, &value->command_codes[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPML_CCA(const TPML_CCA& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(value.count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.command_attributes) < value.count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.count; ++i) {
    result = Serialize_TPMA_CC(value.command_attributes[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_CCA(std::string* buffer,
                      TPML_CCA* value,
                      std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT32(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->command_attributes) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Parse_TPMA_CC(buffer, &value->command_attributes[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPML_ALG(const TPML_ALG& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(value.count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.algorithms) < value.count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.count; ++i) {
    result = Serialize_TPM_ALG_ID(value.algorithms[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_ALG(std::string* buffer,
                      TPML_ALG* value,
                      std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT32(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->algorithms) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Parse_TPM_ALG_ID(buffer, &value->algorithms[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPML_HANDLE(const TPML_HANDLE& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(value.count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.handle) < value.count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.count; ++i) {
    result = Serialize_TPM_HANDLE(value.handle[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_HANDLE(std::string* buffer,
                         TPML_HANDLE* value,
                         std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT32(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->handle) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Parse_TPM_HANDLE(buffer, &value->handle[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPML_DIGEST(const TPML_DIGEST& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(value.count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.digests) < value.count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.count; ++i) {
    result = Serialize_TPM2B_DIGEST(value.digests[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_DIGEST(std::string* buffer,
                         TPML_DIGEST* value,
                         std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT32(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->digests) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Parse_TPM2B_DIGEST(buffer, &value->digests[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPML_DIGEST_VALUES(const TPML_DIGEST_VALUES& value,
                                    std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(value.count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.digests) < value.count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.count; ++i) {
    result = Serialize_TPMT_HA(value.digests[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_DIGEST_VALUES(std::string* buffer,
                                TPML_DIGEST_VALUES* value,
                                std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT32(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->digests) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Parse_TPMT_HA(buffer, &value->digests[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_DIGEST_VALUES(const TPM2B_DIGEST_VALUES& value,
                                     std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_DIGEST_VALUES(std::string* buffer,
                                 TPM2B_DIGEST_VALUES* value,
                                 std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPML_PCR_SELECTION(const TPML_PCR_SELECTION& value,
                                    std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(value.count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.pcr_selections) < value.count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.count; ++i) {
    result = Serialize_TPMS_PCR_SELECTION(value.pcr_selections[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_PCR_SELECTION(std::string* buffer,
                                TPML_PCR_SELECTION* value,
                                std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT32(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->pcr_selections) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Parse_TPMS_PCR_SELECTION(buffer, &value->pcr_selections[i],
                                      value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPML_ALG_PROPERTY(const TPML_ALG_PROPERTY& value,
                                   std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(value.count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.alg_properties) < value.count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.count; ++i) {
    result = Serialize_TPMS_ALG_PROPERTY(value.alg_properties[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_ALG_PROPERTY(std::string* buffer,
                               TPML_ALG_PROPERTY* value,
                               std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT32(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->alg_properties) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result =
        Parse_TPMS_ALG_PROPERTY(buffer, &value->alg_properties[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPML_TAGGED_TPM_PROPERTY(const TPML_TAGGED_TPM_PROPERTY& value,
                                          std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(value.count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.tpm_property) < value.count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.count; ++i) {
    result = Serialize_TPMS_TAGGED_PROPERTY(value.tpm_property[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_TAGGED_TPM_PROPERTY(std::string* buffer,
                                      TPML_TAGGED_TPM_PROPERTY* value,
                                      std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT32(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->tpm_property) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Parse_TPMS_TAGGED_PROPERTY(buffer, &value->tpm_property[i],
                                        value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPML_TAGGED_PCR_PROPERTY(const TPML_TAGGED_PCR_PROPERTY& value,
                                          std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(value.count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.pcr_property) < value.count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.count; ++i) {
    result = Serialize_TPMS_TAGGED_PCR_SELECT(value.pcr_property[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_TAGGED_PCR_PROPERTY(std::string* buffer,
                                      TPML_TAGGED_PCR_PROPERTY* value,
                                      std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT32(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->pcr_property) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Parse_TPMS_TAGGED_PCR_SELECT(buffer, &value->pcr_property[i],
                                          value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPML_ECC_CURVE(const TPML_ECC_CURVE& value,
                                std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(value.count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.ecc_curves) < value.count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.count; ++i) {
    result = Serialize_TPM_ECC_CURVE(value.ecc_curves[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_ECC_CURVE(std::string* buffer,
                            TPML_ECC_CURVE* value,
                            std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT32(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->ecc_curves) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Parse_TPM_ECC_CURVE(buffer, &value->ecc_curves[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMU_CAPABILITIES(const TPMU_CAPABILITIES& value,
                                   TPM_CAP selector,
                                   std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_CAP_PCRS) {
    result = Serialize_TPML_PCR_SELECTION(value.assigned_pcr, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_TPM_PROPERTIES) {
    result = Serialize_TPML_TAGGED_TPM_PROPERTY(value.tpm_properties, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_PP_COMMANDS) {
    result = Serialize_TPML_CC(value.pp_commands, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_AUDIT_COMMANDS) {
    result = Serialize_TPML_CC(value.audit_commands, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_COMMANDS) {
    result = Serialize_TPML_CCA(value.command, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_ECC_CURVES) {
    result = Serialize_TPML_ECC_CURVE(value.ecc_curves, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_PCR_PROPERTIES) {
    result = Serialize_TPML_TAGGED_PCR_PROPERTY(value.pcr_properties, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_HANDLES) {
    result = Serialize_TPML_HANDLE(value.handles, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_ALGS) {
    result = Serialize_TPML_ALG_PROPERTY(value.algorithms, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_CAPABILITIES(std::string* buffer,
                               TPM_CAP selector,
                               TPMU_CAPABILITIES* value,
                               std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_CAP_PCRS) {
    result =
        Parse_TPML_PCR_SELECTION(buffer, &value->assigned_pcr, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_TPM_PROPERTIES) {
    result = Parse_TPML_TAGGED_TPM_PROPERTY(buffer, &value->tpm_properties,
                                            value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_PP_COMMANDS) {
    result = Parse_TPML_CC(buffer, &value->pp_commands, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_AUDIT_COMMANDS) {
    result = Parse_TPML_CC(buffer, &value->audit_commands, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_COMMANDS) {
    result = Parse_TPML_CCA(buffer, &value->command, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_ECC_CURVES) {
    result = Parse_TPML_ECC_CURVE(buffer, &value->ecc_curves, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_PCR_PROPERTIES) {
    result = Parse_TPML_TAGGED_PCR_PROPERTY(buffer, &value->pcr_properties,
                                            value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_HANDLES) {
    result = Parse_TPML_HANDLE(buffer, &value->handles, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_ALGS) {
    result = Parse_TPML_ALG_PROPERTY(buffer, &value->algorithms, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_CAPABILITY_DATA(const TPMS_CAPABILITY_DATA& value,
                                      std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_CAP(value.capability, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_CAPABILITIES(value.data, value.capability, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CAPABILITY_DATA(std::string* buffer,
                                  TPMS_CAPABILITY_DATA* value,
                                  std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM_CAP(buffer, &value->capability, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_CAPABILITIES(buffer, value->capability, &value->data,
                                   value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_CLOCK_INFO(const TPMS_CLOCK_INFO& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT64(value.clock, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT32(value.reset_count, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT32(value.restart_count, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_YES_NO(value.safe, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CLOCK_INFO(std::string* buffer,
                             TPMS_CLOCK_INFO* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT64(buffer, &value->clock, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT32(buffer, &value->reset_count, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT32(buffer, &value->restart_count, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_YES_NO(buffer, &value->safe, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_TIME_INFO(const TPMS_TIME_INFO& value,
                                std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT64(value.time, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMS_CLOCK_INFO(value.clock_info, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_TIME_INFO(std::string* buffer,
                            TPMS_TIME_INFO* value,
                            std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT64(buffer, &value->time, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMS_CLOCK_INFO(buffer, &value->clock_info, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_TIME_ATTEST_INFO(const TPMS_TIME_ATTEST_INFO& value,
                                       std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMS_TIME_INFO(value.time, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT64(value.firmware_version, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_TIME_ATTEST_INFO(std::string* buffer,
                                   TPMS_TIME_ATTEST_INFO* value,
                                   std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMS_TIME_INFO(buffer, &value->time, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT64(buffer, &value->firmware_version, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_CERTIFY_INFO(const TPMS_CERTIFY_INFO& value,
                                   std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_NAME(value.name, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_NAME(value.qualified_name, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CERTIFY_INFO(std::string* buffer,
                               TPMS_CERTIFY_INFO* value,
                               std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM2B_NAME(buffer, &value->name, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_NAME(buffer, &value->qualified_name, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_QUOTE_INFO(const TPMS_QUOTE_INFO& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPML_PCR_SELECTION(value.pcr_select, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.pcr_digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_QUOTE_INFO(std::string* buffer,
                             TPMS_QUOTE_INFO* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPML_PCR_SELECTION(buffer, &value->pcr_select, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->pcr_digest, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_COMMAND_AUDIT_INFO(const TPMS_COMMAND_AUDIT_INFO& value,
                                         std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT64(value.audit_counter, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM_ALG_ID(value.digest_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.audit_digest, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.command_digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_COMMAND_AUDIT_INFO(std::string* buffer,
                                     TPMS_COMMAND_AUDIT_INFO* value,
                                     std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT64(buffer, &value->audit_counter, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM_ALG_ID(buffer, &value->digest_alg, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->audit_digest, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->command_digest, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SESSION_AUDIT_INFO(const TPMS_SESSION_AUDIT_INFO& value,
                                         std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_YES_NO(value.exclusive_session, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.session_digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SESSION_AUDIT_INFO(std::string* buffer,
                                     TPMS_SESSION_AUDIT_INFO* value,
                                     std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_YES_NO(buffer, &value->exclusive_session, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->session_digest, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_CREATION_INFO(const TPMS_CREATION_INFO& value,
                                    std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_NAME(value.object_name, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.creation_hash, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CREATION_INFO(std::string* buffer,
                                TPMS_CREATION_INFO* value,
                                std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM2B_NAME(buffer, &value->object_name, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->creation_hash, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_NV_CERTIFY_INFO(const TPMS_NV_CERTIFY_INFO& value,
                                      std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_NAME(value.index_name, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT16(value.offset, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_MAX_NV_BUFFER(value.nv_contents, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_NV_CERTIFY_INFO(std::string* buffer,
                                  TPMS_NV_CERTIFY_INFO* value,
                                  std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM2B_NAME(buffer, &value->index_name, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT16(buffer, &value->offset, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_MAX_NV_BUFFER(buffer, &value->nv_contents, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMU_ATTEST(const TPMU_ATTEST& value,
                             TPMI_ST_ATTEST selector,
                             std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ST_ATTEST_SESSION_AUDIT) {
    result = Serialize_TPMS_SESSION_AUDIT_INFO(value.session_audit, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_QUOTE) {
    result = Serialize_TPMS_QUOTE_INFO(value.quote, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_COMMAND_AUDIT) {
    result = Serialize_TPMS_COMMAND_AUDIT_INFO(value.command_audit, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_CERTIFY) {
    result = Serialize_TPMS_CERTIFY_INFO(value.certify, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_NV) {
    result = Serialize_TPMS_NV_CERTIFY_INFO(value.nv, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_TIME) {
    result = Serialize_TPMS_TIME_ATTEST_INFO(value.time, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_CREATION) {
    result = Serialize_TPMS_CREATION_INFO(value.creation, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_ATTEST(std::string* buffer,
                         TPMI_ST_ATTEST selector,
                         TPMU_ATTEST* value,
                         std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ST_ATTEST_SESSION_AUDIT) {
    result = Parse_TPMS_SESSION_AUDIT_INFO(buffer, &value->session_audit,
                                           value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_QUOTE) {
    result = Parse_TPMS_QUOTE_INFO(buffer, &value->quote, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_COMMAND_AUDIT) {
    result = Parse_TPMS_COMMAND_AUDIT_INFO(buffer, &value->command_audit,
                                           value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_CERTIFY) {
    result = Parse_TPMS_CERTIFY_INFO(buffer, &value->certify, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_NV) {
    result = Parse_TPMS_NV_CERTIFY_INFO(buffer, &value->nv, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_TIME) {
    result = Parse_TPMS_TIME_ATTEST_INFO(buffer, &value->time, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_CREATION) {
    result = Parse_TPMS_CREATION_INFO(buffer, &value->creation, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_ATTEST(const TPMS_ATTEST& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_GENERATED(value.magic, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_ST_ATTEST(value.type, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_NAME(value.qualified_signer, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DATA(value.extra_data, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMS_CLOCK_INFO(value.clock_info, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT64(value.firmware_version, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_ATTEST(value.attested, value.type, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ATTEST(std::string* buffer,
                         TPMS_ATTEST* value,
                         std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM_GENERATED(buffer, &value->magic, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_ST_ATTEST(buffer, &value->type, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_NAME(buffer, &value->qualified_signer, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DATA(buffer, &value->extra_data, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMS_CLOCK_INFO(buffer, &value->clock_info, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT64(buffer, &value->firmware_version, value_bytes);
  if (result) {
    return result;
  }

  result =
      Parse_TPMU_ATTEST(buffer, value->type, &value->attested, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_ATTEST(const TPM2B_ATTEST& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.attestation_data) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.attestation_data[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_ATTEST(std::string* buffer,
                          TPM2B_ATTEST* value,
                          std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->attestation_data) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->attestation_data[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_AUTH_COMMAND(const TPMS_AUTH_COMMAND& value,
                                   std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_SH_AUTH_SESSION(value.session_handle, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_NONCE(value.nonce, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_SESSION(value.session_attributes, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_AUTH(value.hmac, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_AUTH_COMMAND(std::string* buffer,
                               TPMS_AUTH_COMMAND* value,
                               std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result =
      Parse_TPMI_SH_AUTH_SESSION(buffer, &value->session_handle, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_NONCE(buffer, &value->nonce, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMA_SESSION(buffer, &value->session_attributes, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_AUTH(buffer, &value->hmac, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_AUTH_RESPONSE(const TPMS_AUTH_RESPONSE& value,
                                    std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_NONCE(value.nonce, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_SESSION(value.session_attributes, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_AUTH(value.hmac, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_AUTH_RESPONSE(std::string* buffer,
                                TPMS_AUTH_RESPONSE* value,
                                std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM2B_NONCE(buffer, &value->nonce, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMA_SESSION(buffer, &value->session_attributes, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_AUTH(buffer, &value->hmac, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMU_SYM_KEY_BITS(const TPMU_SYM_KEY_BITS& value,
                                   TPMI_ALG_SYM selector,
                                   std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_SM4) {
    result = Serialize_TPMI_SM4_KEY_BITS(value.sm4, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_AES) {
    result = Serialize_TPMI_AES_KEY_BITS(value.aes, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_XOR) {
    result = Serialize_TPMI_ALG_HASH(value.xor_, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_SYM_KEY_BITS(std::string* buffer,
                               TPMI_ALG_SYM selector,
                               TPMU_SYM_KEY_BITS* value,
                               std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_SM4) {
    result = Parse_TPMI_SM4_KEY_BITS(buffer, &value->sm4, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_AES) {
    result = Parse_TPMI_AES_KEY_BITS(buffer, &value->aes, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_XOR) {
    result = Parse_TPMI_ALG_HASH(buffer, &value->xor_, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMU_SYM_MODE(const TPMU_SYM_MODE& value,
                               TPMI_ALG_SYM selector,
                               std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_SM4) {
    result = Serialize_TPMI_ALG_SYM_MODE(value.sm4, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_AES) {
    result = Serialize_TPMI_ALG_SYM_MODE(value.aes, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_XOR) {
    // Do nothing.
  }
  return result;
}

TPM_RC Parse_TPMU_SYM_MODE(std::string* buffer,
                           TPMI_ALG_SYM selector,
                           TPMU_SYM_MODE* value,
                           std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_SM4) {
    result = Parse_TPMI_ALG_SYM_MODE(buffer, &value->sm4, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_AES) {
    result = Parse_TPMI_ALG_SYM_MODE(buffer, &value->aes, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_XOR) {
    // Do nothing.
  }
  return result;
}

TPM_RC Serialize_TPMU_SYM_DETAILS(const TPMU_SYM_DETAILS& value,
                                  TPMI_ALG_SYM selector,
                                  std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;
    return result;
}

TPM_RC Parse_TPMU_SYM_DETAILS(std::string* buffer,
                              TPMI_ALG_SYM selector,
                              TPMU_SYM_DETAILS* value,
                              std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;
    return result;
}

TPM_RC Serialize_TPMT_SYM_DEF(const TPMT_SYM_DEF& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_SYM(value.algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_KEY_BITS(value.key_bits, value.algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_MODE(value.mode, value.algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_DETAILS(value.details, value.algorithm, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_SYM_DEF(std::string* buffer,
                          TPMT_SYM_DEF* value,
                          std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_SYM(buffer, &value->algorithm, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_SYM_KEY_BITS(buffer, value->algorithm, &value->key_bits,
                                   value_bytes);
  if (result) {
    return result;
  }

  result =
      Parse_TPMU_SYM_MODE(buffer, value->algorithm, &value->mode, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_SYM_DETAILS(buffer, value->algorithm, &value->details,
                                  value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMT_SYM_DEF_OBJECT(const TPMT_SYM_DEF_OBJECT& value,
                                     std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_SYM_OBJECT(value.algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_KEY_BITS(value.key_bits, value.algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_MODE(value.mode, value.algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_DETAILS(value.details, value.algorithm, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_SYM_DEF_OBJECT(std::string* buffer,
                                 TPMT_SYM_DEF_OBJECT* value,
                                 std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_SYM_OBJECT(buffer, &value->algorithm, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_SYM_KEY_BITS(buffer, value->algorithm, &value->key_bits,
                                   value_bytes);
  if (result) {
    return result;
  }

  result =
      Parse_TPMU_SYM_MODE(buffer, value->algorithm, &value->mode, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_SYM_DETAILS(buffer, value->algorithm, &value->details,
                                  value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_SYM_KEY(const TPM2B_SYM_KEY& value,
                               std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_SYM_KEY(std::string* buffer,
                           TPM2B_SYM_KEY* value,
                           std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_SYMCIPHER_PARMS(const TPMS_SYMCIPHER_PARMS& value,
                                      std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMT_SYM_DEF_OBJECT(value.sym, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SYMCIPHER_PARMS(std::string* buffer,
                                  TPMS_SYMCIPHER_PARMS* value,
                                  std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMT_SYM_DEF_OBJECT(buffer, &value->sym, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_SENSITIVE_DATA(const TPM2B_SENSITIVE_DATA& value,
                                      std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_SENSITIVE_DATA(std::string* buffer,
                                  TPM2B_SENSITIVE_DATA* value,
                                  std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_SENSITIVE_CREATE(const TPMS_SENSITIVE_CREATE& value,
                                       std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_AUTH(value.user_auth, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_SENSITIVE_DATA(value.data, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SENSITIVE_CREATE(std::string* buffer,
                                   TPMS_SENSITIVE_CREATE* value,
                                   std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM2B_AUTH(buffer, &value->user_auth, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_SENSITIVE_DATA(buffer, &value->data, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_SENSITIVE_CREATE(const TPM2B_SENSITIVE_CREATE& value,
                                        std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  std::string field_bytes;
  if (value.size) {
    if (value.size != sizeof(TPMS_SENSITIVE_CREATE)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMS_SENSITIVE_CREATE(value.sensitive, &field_bytes);
    if (result) {
      return result;
    }
  }
  std::string size_bytes;
  result = Serialize_UINT16(field_bytes.size(), &size_bytes);
  if (result) {
    return result;
  }
  buffer->append(size_bytes + field_bytes);
  return result;
}

TPM_RC Parse_TPM2B_SENSITIVE_CREATE(std::string* buffer,
                                    TPM2B_SENSITIVE_CREATE* value,
                                    std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  UINT16 parsed_size = 0;
  result = Parse_UINT16(buffer, &parsed_size, value_bytes);
  if (result) {
    return result;
  }
  if (!parsed_size) {
    value->size = 0;
  } else {
    value->size = sizeof(TPMS_SENSITIVE_CREATE);
    result =
        Parse_TPMS_SENSITIVE_CREATE(buffer, &value->sensitive, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_XOR(const TPMS_SCHEME_XOR& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_ALG_KDF(value.kdf, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_XOR(std::string* buffer,
                             TPMS_SCHEME_XOR* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_ALG_KDF(buffer, &value->kdf, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMU_SCHEME_KEYEDHASH(const TPMU_SCHEME_KEYEDHASH& value,
                                       TPMI_ALG_KEYEDHASH_SCHEME selector,
                                       std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_HMAC) {
    result = Serialize_TPMS_SCHEME_HMAC(value.hmac, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_XOR) {
    result = Serialize_TPMS_SCHEME_XOR(value.xor_, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_SCHEME_KEYEDHASH(std::string* buffer,
                                   TPMI_ALG_KEYEDHASH_SCHEME selector,
                                   TPMU_SCHEME_KEYEDHASH* value,
                                   std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_HMAC) {
    result = Parse_TPMS_SCHEME_HMAC(buffer, &value->hmac, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_XOR) {
    result = Parse_TPMS_SCHEME_XOR(buffer, &value->xor_, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMT_KEYEDHASH_SCHEME(const TPMT_KEYEDHASH_SCHEME& value,
                                       std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_KEYEDHASH_SCHEME(value.scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SCHEME_KEYEDHASH(value.details, value.scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_KEYEDHASH_SCHEME(std::string* buffer,
                                   TPMT_KEYEDHASH_SCHEME* value,
                                   std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_KEYEDHASH_SCHEME(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_SCHEME_KEYEDHASH(buffer, value->scheme, &value->details,
                                       value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_ECDAA(const TPMS_SCHEME_ECDAA& value,
                                   std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT16(value.count, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_ECDAA(std::string* buffer,
                               TPMS_SCHEME_ECDAA* value,
                               std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT16(buffer, &value->count, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMU_SIG_SCHEME(const TPMU_SIG_SCHEME& value,
                                 TPMI_ALG_SIG_SCHEME selector,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_HMAC) {
    result = Serialize_TPMS_SCHEME_HMAC(value.hmac, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECSCHNORR) {
    result = Serialize_TPMS_SCHEME_ECSCHNORR(value.ec_schnorr, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSAPSS) {
    result = Serialize_TPMS_SCHEME_RSAPSS(value.rsapss, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDAA) {
    result = Serialize_TPMS_SCHEME_ECDAA(value.ecdaa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSASSA) {
    result = Serialize_TPMS_SCHEME_RSASSA(value.rsassa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SM2) {
    result = Serialize_TPMS_SCHEME_SM2(value.sm2, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDSA) {
    result = Serialize_TPMS_SCHEME_ECDSA(value.ecdsa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }
  return result;
}

TPM_RC Parse_TPMU_SIG_SCHEME(std::string* buffer,
                             TPMI_ALG_SIG_SCHEME selector,
                             TPMU_SIG_SCHEME* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_HMAC) {
    result = Parse_TPMS_SCHEME_HMAC(buffer, &value->hmac, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECSCHNORR) {
    result =
        Parse_TPMS_SCHEME_ECSCHNORR(buffer, &value->ec_schnorr, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSAPSS) {
    result = Parse_TPMS_SCHEME_RSAPSS(buffer, &value->rsapss, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDAA) {
    result = Parse_TPMS_SCHEME_ECDAA(buffer, &value->ecdaa, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSASSA) {
    result = Parse_TPMS_SCHEME_RSASSA(buffer, &value->rsassa, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SM2) {
    result = Parse_TPMS_SCHEME_SM2(buffer, &value->sm2, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDSA) {
    result = Parse_TPMS_SCHEME_ECDSA(buffer, &value->ecdsa, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }
  return result;
}

TPM_RC Serialize_TPMT_SIG_SCHEME(const TPMT_SIG_SCHEME& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_SIG_SCHEME(value.scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SIG_SCHEME(value.details, value.scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_SIG_SCHEME(std::string* buffer,
                             TPMT_SIG_SCHEME* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_SIG_SCHEME(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_SIG_SCHEME(buffer, value->scheme, &value->details,
                                 value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_OAEP(const TPMS_SCHEME_OAEP& value,
                                  std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_OAEP(std::string* buffer,
                              TPMS_SCHEME_OAEP* value,
                              std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_ECDH(const TPMS_SCHEME_ECDH& value,
                                  std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_ECDH(std::string* buffer,
                              TPMS_SCHEME_ECDH* value,
                              std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_MGF1(const TPMS_SCHEME_MGF1& value,
                                  std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_MGF1(std::string* buffer,
                              TPMS_SCHEME_MGF1* value,
                              std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_KDF1_SP800_56a(
    const TPMS_SCHEME_KDF1_SP800_56a& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_KDF1_SP800_56a(std::string* buffer,
                                        TPMS_SCHEME_KDF1_SP800_56a* value,
                                        std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_KDF2(const TPMS_SCHEME_KDF2& value,
                                  std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_KDF2(std::string* buffer,
                              TPMS_SCHEME_KDF2* value,
                              std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_KDF1_SP800_108(
    const TPMS_SCHEME_KDF1_SP800_108& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_KDF1_SP800_108(std::string* buffer,
                                        TPMS_SCHEME_KDF1_SP800_108* value,
                                        std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMU_KDF_SCHEME(const TPMU_KDF_SCHEME& value,
                                 TPMI_ALG_KDF selector,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KDF1_SP800_56a) {
    result = Serialize_TPMS_SCHEME_KDF1_SP800_56a(value.kdf1_sp800_56a, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_MGF1) {
    result = Serialize_TPMS_SCHEME_MGF1(value.mgf1, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_KDF1_SP800_108) {
    result = Serialize_TPMS_SCHEME_KDF1_SP800_108(value.kdf1_sp800_108, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_KDF2) {
    result = Serialize_TPMS_SCHEME_KDF2(value.kdf2, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }
  return result;
}

TPM_RC Parse_TPMU_KDF_SCHEME(std::string* buffer,
                             TPMI_ALG_KDF selector,
                             TPMU_KDF_SCHEME* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KDF1_SP800_56a) {
    result = Parse_TPMS_SCHEME_KDF1_SP800_56a(buffer, &value->kdf1_sp800_56a,
                                              value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_MGF1) {
    result = Parse_TPMS_SCHEME_MGF1(buffer, &value->mgf1, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_KDF1_SP800_108) {
    result = Parse_TPMS_SCHEME_KDF1_SP800_108(buffer, &value->kdf1_sp800_108,
                                              value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_KDF2) {
    result = Parse_TPMS_SCHEME_KDF2(buffer, &value->kdf2, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }
  return result;
}

TPM_RC Serialize_TPMT_KDF_SCHEME(const TPMT_KDF_SCHEME& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_KDF(value.scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_KDF_SCHEME(value.details, value.scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_KDF_SCHEME(std::string* buffer,
                             TPMT_KDF_SCHEME* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_KDF(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_KDF_SCHEME(buffer, value->scheme, &value->details,
                                 value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMU_ASYM_SCHEME(const TPMU_ASYM_SCHEME& value,
                                  TPMI_ALG_ASYM_SCHEME selector,
                                  std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_RSAES) {
    // Do nothing.
  }

  if (selector == TPM_ALG_ECSCHNORR) {
    result = Serialize_TPMS_SCHEME_ECSCHNORR(value.ec_schnorr, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_ECDH) {
    result = Serialize_TPMS_SCHEME_ECDH(value.ecdh, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_OAEP) {
    result = Serialize_TPMS_SCHEME_OAEP(value.oaep, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSAPSS) {
    result = Serialize_TPMS_SCHEME_RSAPSS(value.rsapss, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDAA) {
    result = Serialize_TPMS_SCHEME_ECDAA(value.ecdaa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSASSA) {
    result = Serialize_TPMS_SCHEME_RSASSA(value.rsassa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SM2) {
    result = Serialize_TPMS_SCHEME_SM2(value.sm2, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDSA) {
    result = Serialize_TPMS_SCHEME_ECDSA(value.ecdsa, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_ASYM_SCHEME(std::string* buffer,
                              TPMI_ALG_ASYM_SCHEME selector,
                              TPMU_ASYM_SCHEME* value,
                              std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_RSAES) {
    // Do nothing.
  }

  if (selector == TPM_ALG_ECSCHNORR) {
    result =
        Parse_TPMS_SCHEME_ECSCHNORR(buffer, &value->ec_schnorr, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_ECDH) {
    result = Parse_TPMS_SCHEME_ECDH(buffer, &value->ecdh, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_OAEP) {
    result = Parse_TPMS_SCHEME_OAEP(buffer, &value->oaep, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSAPSS) {
    result = Parse_TPMS_SCHEME_RSAPSS(buffer, &value->rsapss, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDAA) {
    result = Parse_TPMS_SCHEME_ECDAA(buffer, &value->ecdaa, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSASSA) {
    result = Parse_TPMS_SCHEME_RSASSA(buffer, &value->rsassa, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SM2) {
    result = Parse_TPMS_SCHEME_SM2(buffer, &value->sm2, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDSA) {
    result = Parse_TPMS_SCHEME_ECDSA(buffer, &value->ecdsa, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMT_ASYM_SCHEME(const TPMT_ASYM_SCHEME& value,
                                  std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_ASYM_SCHEME(value.scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_ASYM_SCHEME(value.details, value.scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_ASYM_SCHEME(std::string* buffer,
                              TPMT_ASYM_SCHEME* value,
                              std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_ASYM_SCHEME(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_ASYM_SCHEME(buffer, value->scheme, &value->details,
                                  value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMT_RSA_SCHEME(const TPMT_RSA_SCHEME& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_RSA_SCHEME(value.scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_ASYM_SCHEME(value.details, value.scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_RSA_SCHEME(std::string* buffer,
                             TPMT_RSA_SCHEME* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_RSA_SCHEME(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_ASYM_SCHEME(buffer, value->scheme, &value->details,
                                  value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMT_RSA_DECRYPT(const TPMT_RSA_DECRYPT& value,
                                  std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_RSA_DECRYPT(value.scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_ASYM_SCHEME(value.details, value.scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_RSA_DECRYPT(std::string* buffer,
                              TPMT_RSA_DECRYPT* value,
                              std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_RSA_DECRYPT(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_ASYM_SCHEME(buffer, value->scheme, &value->details,
                                  value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_PUBLIC_KEY_RSA(const TPM2B_PUBLIC_KEY_RSA& value,
                                      std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_PUBLIC_KEY_RSA(std::string* buffer,
                                  TPM2B_PUBLIC_KEY_RSA* value,
                                  std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_PRIVATE_KEY_RSA(const TPM2B_PRIVATE_KEY_RSA& value,
                                       std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_PRIVATE_KEY_RSA(std::string* buffer,
                                   TPM2B_PRIVATE_KEY_RSA* value,
                                   std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_ECC_PARAMETER(const TPM2B_ECC_PARAMETER& value,
                                     std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_ECC_PARAMETER(std::string* buffer,
                                 TPM2B_ECC_PARAMETER* value,
                                 std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_ECC_POINT(const TPMS_ECC_POINT& value,
                                std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_ECC_PARAMETER(value.x, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(value.y, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ECC_POINT(std::string* buffer,
                            TPMS_ECC_POINT* value,
                            std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->x, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->y, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_ECC_POINT(const TPM2B_ECC_POINT& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  std::string field_bytes;
  if (value.size) {
    if (value.size != sizeof(TPMS_ECC_POINT)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMS_ECC_POINT(value.point, &field_bytes);
    if (result) {
      return result;
    }
  }
  std::string size_bytes;
  result = Serialize_UINT16(field_bytes.size(), &size_bytes);
  if (result) {
    return result;
  }
  buffer->append(size_bytes + field_bytes);
  return result;
}

TPM_RC Parse_TPM2B_ECC_POINT(std::string* buffer,
                             TPM2B_ECC_POINT* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  UINT16 parsed_size = 0;
  result = Parse_UINT16(buffer, &parsed_size, value_bytes);
  if (result) {
    return result;
  }
  if (!parsed_size) {
    value->size = 0;
  } else {
    value->size = sizeof(TPMS_ECC_POINT);
    result = Parse_TPMS_ECC_POINT(buffer, &value->point, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMT_ECC_SCHEME(const TPMT_ECC_SCHEME& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_ECC_SCHEME(value.scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SIG_SCHEME(value.details, value.scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_ECC_SCHEME(std::string* buffer,
                             TPMT_ECC_SCHEME* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_ECC_SCHEME(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_SIG_SCHEME(buffer, value->scheme, &value->details,
                                 value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_ALGORITHM_DETAIL_ECC(
    const TPMS_ALGORITHM_DETAIL_ECC& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ECC_CURVE(value.curve_id, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT16(value.key_size, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_KDF_SCHEME(value.kdf, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_ECC_SCHEME(value.sign, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(value.p, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(value.a, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(value.b, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(value.g_x, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(value.g_y, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(value.n, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(value.h, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ALGORITHM_DETAIL_ECC(std::string* buffer,
                                       TPMS_ALGORITHM_DETAIL_ECC* value,
                                       std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM_ECC_CURVE(buffer, &value->curve_id, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT16(buffer, &value->key_size, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMT_KDF_SCHEME(buffer, &value->kdf, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMT_ECC_SCHEME(buffer, &value->sign, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->p, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->a, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->b, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->g_x, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->g_y, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->n, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->h, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SIGNATURE_RSASSA(const TPMS_SIGNATURE_RSASSA& value,
                                       std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_PUBLIC_KEY_RSA(value.sig, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SIGNATURE_RSASSA(std::string* buffer,
                                   TPMS_SIGNATURE_RSASSA* value,
                                   std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_PUBLIC_KEY_RSA(buffer, &value->sig, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SIGNATURE_RSAPSS(const TPMS_SIGNATURE_RSAPSS& value,
                                       std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_PUBLIC_KEY_RSA(value.sig, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SIGNATURE_RSAPSS(std::string* buffer,
                                   TPMS_SIGNATURE_RSAPSS* value,
                                   std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_PUBLIC_KEY_RSA(buffer, &value->sig, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SIGNATURE_ECDSA(const TPMS_SIGNATURE_ECDSA& value,
                                      std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(value.hash, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(value.signature_r, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(value.signature_s, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SIGNATURE_ECDSA(std::string* buffer,
                                  TPMS_SIGNATURE_ECDSA* value,
                                  std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->signature_r, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->signature_s, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMU_SIGNATURE(const TPMU_SIGNATURE& value,
                                TPMI_ALG_SIG_SCHEME selector,
                                std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_HMAC) {
    result = Serialize_TPMT_HA(value.hmac, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECSCHNORR) {
    result = Serialize_TPMS_SIGNATURE_ECDSA(value.ecschnorr, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSAPSS) {
    result = Serialize_TPMS_SIGNATURE_RSAPSS(value.rsapss, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDAA) {
    result = Serialize_TPMS_SIGNATURE_ECDSA(value.ecdaa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSASSA) {
    result = Serialize_TPMS_SIGNATURE_RSASSA(value.rsassa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SM2) {
    result = Serialize_TPMS_SIGNATURE_ECDSA(value.sm2, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDSA) {
    result = Serialize_TPMS_SIGNATURE_ECDSA(value.ecdsa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }
  return result;
}

TPM_RC Parse_TPMU_SIGNATURE(std::string* buffer,
                            TPMI_ALG_SIG_SCHEME selector,
                            TPMU_SIGNATURE* value,
                            std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_HMAC) {
    result = Parse_TPMT_HA(buffer, &value->hmac, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECSCHNORR) {
    result = Parse_TPMS_SIGNATURE_ECDSA(buffer, &value->ecschnorr, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSAPSS) {
    result = Parse_TPMS_SIGNATURE_RSAPSS(buffer, &value->rsapss, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDAA) {
    result = Parse_TPMS_SIGNATURE_ECDSA(buffer, &value->ecdaa, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSASSA) {
    result = Parse_TPMS_SIGNATURE_RSASSA(buffer, &value->rsassa, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SM2) {
    result = Parse_TPMS_SIGNATURE_ECDSA(buffer, &value->sm2, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDSA) {
    result = Parse_TPMS_SIGNATURE_ECDSA(buffer, &value->ecdsa, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }
  return result;
}

TPM_RC Serialize_TPMT_SIGNATURE(const TPMT_SIGNATURE& value,
                                std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_SIG_SCHEME(value.sig_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SIGNATURE(value.signature, value.sig_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_SIGNATURE(std::string* buffer,
                            TPMT_SIGNATURE* value,
                            std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_SIG_SCHEME(buffer, &value->sig_alg, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_SIGNATURE(buffer, value->sig_alg, &value->signature,
                                value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_ENCRYPTED_SECRET(const TPM2B_ENCRYPTED_SECRET& value,
                                        std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.secret) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.secret[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_ENCRYPTED_SECRET(std::string* buffer,
                                    TPM2B_ENCRYPTED_SECRET* value,
                                    std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->secret) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->secret[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_KEYEDHASH_PARMS(const TPMS_KEYEDHASH_PARMS& value,
                                      std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMT_KEYEDHASH_SCHEME(value.scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_KEYEDHASH_PARMS(std::string* buffer,
                                  TPMS_KEYEDHASH_PARMS* value,
                                  std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMT_KEYEDHASH_SCHEME(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_ASYM_PARMS(const TPMS_ASYM_PARMS& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMT_SYM_DEF_OBJECT(value.symmetric, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_ASYM_SCHEME(value.scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ASYM_PARMS(std::string* buffer,
                             TPMS_ASYM_PARMS* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMT_SYM_DEF_OBJECT(buffer, &value->symmetric, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMT_ASYM_SCHEME(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_RSA_PARMS(const TPMS_RSA_PARMS& value,
                                std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMT_SYM_DEF_OBJECT(value.symmetric, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_RSA_SCHEME(value.scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RSA_KEY_BITS(value.key_bits, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT32(value.exponent, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_RSA_PARMS(std::string* buffer,
                            TPMS_RSA_PARMS* value,
                            std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMT_SYM_DEF_OBJECT(buffer, &value->symmetric, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMT_RSA_SCHEME(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_RSA_KEY_BITS(buffer, &value->key_bits, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT32(buffer, &value->exponent, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_ECC_PARMS(const TPMS_ECC_PARMS& value,
                                std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMT_SYM_DEF_OBJECT(value.symmetric, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_ECC_SCHEME(value.scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_ECC_CURVE(value.curve_id, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_KDF_SCHEME(value.kdf, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ECC_PARMS(std::string* buffer,
                            TPMS_ECC_PARMS* value,
                            std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMT_SYM_DEF_OBJECT(buffer, &value->symmetric, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMT_ECC_SCHEME(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_ECC_CURVE(buffer, &value->curve_id, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMT_KDF_SCHEME(buffer, &value->kdf, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMU_PUBLIC_PARMS(const TPMU_PUBLIC_PARMS& value,
                                   TPMI_ALG_PUBLIC selector,
                                   std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KEYEDHASH) {
    result = Serialize_TPMS_KEYEDHASH_PARMS(value.keyed_hash_detail, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSA) {
    result = Serialize_TPMS_RSA_PARMS(value.rsa_detail, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SYMCIPHER) {
    result = Serialize_TPMS_SYMCIPHER_PARMS(value.sym_detail, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECC) {
    result = Serialize_TPMS_ECC_PARMS(value.ecc_detail, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_PUBLIC_PARMS(std::string* buffer,
                               TPMI_ALG_PUBLIC selector,
                               TPMU_PUBLIC_PARMS* value,
                               std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KEYEDHASH) {
    result = Parse_TPMS_KEYEDHASH_PARMS(buffer, &value->keyed_hash_detail,
                                        value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSA) {
    result = Parse_TPMS_RSA_PARMS(buffer, &value->rsa_detail, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SYMCIPHER) {
    result =
        Parse_TPMS_SYMCIPHER_PARMS(buffer, &value->sym_detail, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECC) {
    result = Parse_TPMS_ECC_PARMS(buffer, &value->ecc_detail, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMT_PUBLIC_PARMS(const TPMT_PUBLIC_PARMS& value,
                                   std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_PUBLIC(value.type, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_PUBLIC_PARMS(value.parameters, value.type, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_PUBLIC_PARMS(std::string* buffer,
                               TPMT_PUBLIC_PARMS* value,
                               std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_PUBLIC(buffer, &value->type, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_PUBLIC_PARMS(buffer, value->type, &value->parameters,
                                   value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMU_PUBLIC_ID(const TPMU_PUBLIC_ID& value,
                                TPMI_ALG_PUBLIC selector,
                                std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KEYEDHASH) {
    result = Serialize_TPM2B_DIGEST(value.keyed_hash, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSA) {
    result = Serialize_TPM2B_PUBLIC_KEY_RSA(value.rsa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SYMCIPHER) {
    result = Serialize_TPM2B_DIGEST(value.sym, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECC) {
    result = Serialize_TPMS_ECC_POINT(value.ecc, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_PUBLIC_ID(std::string* buffer,
                            TPMI_ALG_PUBLIC selector,
                            TPMU_PUBLIC_ID* value,
                            std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KEYEDHASH) {
    result = Parse_TPM2B_DIGEST(buffer, &value->keyed_hash, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSA) {
    result = Parse_TPM2B_PUBLIC_KEY_RSA(buffer, &value->rsa, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SYMCIPHER) {
    result = Parse_TPM2B_DIGEST(buffer, &value->sym, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECC) {
    result = Parse_TPMS_ECC_POINT(buffer, &value->ecc, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMT_PUBLIC(const TPMT_PUBLIC& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_PUBLIC(value.type, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_ALG_HASH(value.name_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_OBJECT(value.object_attributes, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.auth_policy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_PUBLIC_PARMS(value.parameters, value.type, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_PUBLIC_ID(value.unique, value.type, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_PUBLIC(std::string* buffer,
                         TPMT_PUBLIC* value,
                         std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_PUBLIC(buffer, &value->type, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_ALG_HASH(buffer, &value->name_alg, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMA_OBJECT(buffer, &value->object_attributes, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->auth_policy, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_PUBLIC_PARMS(buffer, value->type, &value->parameters,
                                   value_bytes);
  if (result) {
    return result;
  }

  result =
      Parse_TPMU_PUBLIC_ID(buffer, value->type, &value->unique, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_PUBLIC(const TPM2B_PUBLIC& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  std::string field_bytes;
  if (value.size) {
    if (value.size != sizeof(TPMT_PUBLIC)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMT_PUBLIC(value.public_area, &field_bytes);
    if (result) {
      return result;
    }
  }
  std::string size_bytes;
  result = Serialize_UINT16(field_bytes.size(), &size_bytes);
  if (result) {
    return result;
  }
  buffer->append(size_bytes + field_bytes);
  return result;
}

TPM_RC Parse_TPM2B_PUBLIC(std::string* buffer,
                          TPM2B_PUBLIC* value,
                          std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  UINT16 parsed_size = 0;
  result = Parse_UINT16(buffer, &parsed_size, value_bytes);
  if (result) {
    return result;
  }
  if (!parsed_size) {
    value->size = 0;
  } else {
    value->size = sizeof(TPMT_PUBLIC);
    result = Parse_TPMT_PUBLIC(buffer, &value->public_area, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_PRIVATE_VENDOR_SPECIFIC(
    const TPM2B_PRIVATE_VENDOR_SPECIFIC& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_PRIVATE_VENDOR_SPECIFIC(std::string* buffer,
                                           TPM2B_PRIVATE_VENDOR_SPECIFIC* value,
                                           std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMU_SENSITIVE_COMPOSITE(const TPMU_SENSITIVE_COMPOSITE& value,
                                          TPMI_ALG_PUBLIC selector,
                                          std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KEYEDHASH) {
    result = Serialize_TPM2B_SENSITIVE_DATA(value.bits, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSA) {
    result = Serialize_TPM2B_PRIVATE_KEY_RSA(value.rsa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SYMCIPHER) {
    result = Serialize_TPM2B_SYM_KEY(value.sym, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECC) {
    result = Serialize_TPM2B_ECC_PARAMETER(value.ecc, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_SENSITIVE_COMPOSITE(std::string* buffer,
                                      TPMI_ALG_PUBLIC selector,
                                      TPMU_SENSITIVE_COMPOSITE* value,
                                      std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KEYEDHASH) {
    result = Parse_TPM2B_SENSITIVE_DATA(buffer, &value->bits, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSA) {
    result = Parse_TPM2B_PRIVATE_KEY_RSA(buffer, &value->rsa, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SYMCIPHER) {
    result = Parse_TPM2B_SYM_KEY(buffer, &value->sym, value_bytes);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECC) {
    result = Parse_TPM2B_ECC_PARAMETER(buffer, &value->ecc, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMT_SENSITIVE(const TPMT_SENSITIVE& value,
                                std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_PUBLIC(value.sensitive_type, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_AUTH(value.auth_value, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.seed_value, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SENSITIVE_COMPOSITE(value.sensitive,
                                              value.sensitive_type, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_SENSITIVE(std::string* buffer,
                            TPMT_SENSITIVE* value,
                            std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_PUBLIC(buffer, &value->sensitive_type, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_AUTH(buffer, &value->auth_value, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->seed_value, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMU_SENSITIVE_COMPOSITE(buffer, value->sensitive_type,
                                          &value->sensitive, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_SENSITIVE(const TPM2B_SENSITIVE& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  std::string field_bytes;
  if (value.size) {
    if (value.size != sizeof(TPMT_SENSITIVE)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMT_SENSITIVE(value.sensitive_area, &field_bytes);
    if (result) {
      return result;
    }
  }
  std::string size_bytes;
  result = Serialize_UINT16(field_bytes.size(), &size_bytes);
  if (result) {
    return result;
  }
  buffer->append(size_bytes + field_bytes);
  return result;
}

TPM_RC Parse_TPM2B_SENSITIVE(std::string* buffer,
                             TPM2B_SENSITIVE* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  UINT16 parsed_size = 0;
  result = Parse_UINT16(buffer, &parsed_size, value_bytes);
  if (result) {
    return result;
  }
  if (!parsed_size) {
    value->size = 0;
  } else {
    value->size = sizeof(TPMT_SENSITIVE);
    result = Parse_TPMT_SENSITIVE(buffer, &value->sensitive_area, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize__PRIVATE(const _PRIVATE& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_DIGEST(value.integrity_outer, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.integrity_inner, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_SENSITIVE(value.sensitive, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse__PRIVATE(std::string* buffer,
                      _PRIVATE* value,
                      std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM2B_DIGEST(buffer, &value->integrity_outer, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->integrity_inner, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMT_SENSITIVE(buffer, &value->sensitive, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_PRIVATE(const TPM2B_PRIVATE& value,
                               std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_PRIVATE(std::string* buffer,
                           TPM2B_PRIVATE* value,
                           std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize__ID_OBJECT(const _ID_OBJECT& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_DIGEST(value.integrity_hmac, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.enc_identity, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse__ID_OBJECT(std::string* buffer,
                        _ID_OBJECT* value,
                        std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM2B_DIGEST(buffer, &value->integrity_hmac, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->enc_identity, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_ID_OBJECT(const TPM2B_ID_OBJECT& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.credential) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.credential[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_ID_OBJECT(std::string* buffer,
                             TPM2B_ID_OBJECT* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->credential) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->credential[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_NV_PUBLIC(const TPMS_NV_PUBLIC& value,
                                std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_RH_NV_INDEX(value.nv_index, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_ALG_HASH(value.name_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_NV(value.attributes, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.auth_policy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT16(value.data_size, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_NV_PUBLIC(std::string* buffer,
                            TPMS_NV_PUBLIC* value,
                            std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_RH_NV_INDEX(buffer, &value->nv_index, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_ALG_HASH(buffer, &value->name_alg, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMA_NV(buffer, &value->attributes, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->auth_policy, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_UINT16(buffer, &value->data_size, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_NV_PUBLIC(const TPM2B_NV_PUBLIC& value,
                                 std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  std::string field_bytes;
  if (value.size) {
    if (value.size != sizeof(TPMS_NV_PUBLIC)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMS_NV_PUBLIC(value.nv_public, &field_bytes);
    if (result) {
      return result;
    }
  }
  std::string size_bytes;
  result = Serialize_UINT16(field_bytes.size(), &size_bytes);
  if (result) {
    return result;
  }
  buffer->append(size_bytes + field_bytes);
  return result;
}

TPM_RC Parse_TPM2B_NV_PUBLIC(std::string* buffer,
                             TPM2B_NV_PUBLIC* value,
                             std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  UINT16 parsed_size = 0;
  result = Parse_UINT16(buffer, &parsed_size, value_bytes);
  if (result) {
    return result;
  }
  if (!parsed_size) {
    value->size = 0;
  } else {
    value->size = sizeof(TPMS_NV_PUBLIC);
    result = Parse_TPMS_NV_PUBLIC(buffer, &value->nv_public, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPM2B_CONTEXT_SENSITIVE(const TPM2B_CONTEXT_SENSITIVE& value,
                                         std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_CONTEXT_SENSITIVE(std::string* buffer,
                                     TPM2B_CONTEXT_SENSITIVE* value,
                                     std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_CONTEXT_DATA(const TPMS_CONTEXT_DATA& value,
                                   std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_DIGEST(value.integrity, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_CONTEXT_SENSITIVE(value.encrypted, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CONTEXT_DATA(std::string* buffer,
                               TPMS_CONTEXT_DATA* value,
                               std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPM2B_DIGEST(buffer, &value->integrity, value_bytes);
  if (result) {
    return result;
  }

  result =
      Parse_TPM2B_CONTEXT_SENSITIVE(buffer, &value->encrypted, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_CONTEXT_DATA(const TPM2B_CONTEXT_DATA& value,
                                    std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(value.size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value.buffer) < value.size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value.size; ++i) {
    result = Serialize_BYTE(value.buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_CONTEXT_DATA(std::string* buffer,
                                TPM2B_CONTEXT_DATA* value,
                                std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT16(buffer, &value->size, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Parse_BYTE(buffer, &value->buffer[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_CONTEXT(const TPMS_CONTEXT& value, std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT64(value.sequence, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_DH_CONTEXT(value.saved_handle, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RH_HIERARCHY(value.hierarchy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_CONTEXT_DATA(value.context_blob, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CONTEXT(std::string* buffer,
                          TPMS_CONTEXT* value,
                          std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT64(buffer, &value->sequence, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_DH_CONTEXT(buffer, &value->saved_handle, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMI_RH_HIERARCHY(buffer, &value->hierarchy, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_CONTEXT_DATA(buffer, &value->context_blob, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_CREATION_DATA(const TPMS_CREATION_DATA& value,
                                    std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPML_PCR_SELECTION(value.pcr_select, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(value.pcr_digest, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_LOCALITY(value.locality, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM_ALG_ID(value.parent_name_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_NAME(value.parent_name, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_NAME(value.parent_qualified_name, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DATA(value.outside_info, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CREATION_DATA(std::string* buffer,
                                TPMS_CREATION_DATA* value,
                                std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPML_PCR_SELECTION(buffer, &value->pcr_select, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DIGEST(buffer, &value->pcr_digest, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPMA_LOCALITY(buffer, &value->locality, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM_ALG_ID(buffer, &value->parent_name_alg, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_NAME(buffer, &value->parent_name, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_NAME(buffer, &value->parent_qualified_name, value_bytes);
  if (result) {
    return result;
  }

  result = Parse_TPM2B_DATA(buffer, &value->outside_info, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_CREATION_DATA(const TPM2B_CREATION_DATA& value,
                                     std::string* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  std::string field_bytes;
  if (value.size) {
    if (value.size != sizeof(TPMS_CREATION_DATA)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMS_CREATION_DATA(value.creation_data, &field_bytes);
    if (result) {
      return result;
    }
  }
  std::string size_bytes;
  result = Serialize_UINT16(field_bytes.size(), &size_bytes);
  if (result) {
    return result;
  }
  buffer->append(size_bytes + field_bytes);
  return result;
}

TPM_RC Parse_TPM2B_CREATION_DATA(std::string* buffer,
                                 TPM2B_CREATION_DATA* value,
                                 std::string* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  UINT16 parsed_size = 0;
  result = Parse_UINT16(buffer, &parsed_size, value_bytes);
  if (result) {
    return result;
  }
  if (!parsed_size) {
    value->size = 0;
  } else {
    value->size = sizeof(TPMS_CREATION_DATA);
    result =
        Parse_TPMS_CREATION_DATA(buffer, &value->creation_data, value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

static TPM_RC SerializeCommand_StartAuthSession(
    const TPMI_DH_OBJECT& tpm_key,
    const std::string& tpm_key_name,
    const TPMI_DH_ENTITY& bind,
    const std::string& bind_name,
    const TPM2B_NONCE& nonce_caller,
    const TPM2B_ENCRYPTED_SECRET& encrypted_salt,
    const TPM_SE& session_type,
    const TPMT_SYM_DEF& symmetric,
    const TPMI_ALG_HASH& auth_hash,
    std::string* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  UINT32 command_size = 10;  // Header size.
  std::string handle_section_bytes;
  std::string parameter_section_bytes;
  TPM_CC command_code = TPM_CC_StartAuthSession;
  bool is_command_parameter_encryption_possible = true;
  bool is_response_parameter_encryption_possible = true;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string tpm_key_bytes;
  rc = Serialize_TPMI_DH_OBJECT(tpm_key, &tpm_key_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string bind_bytes;
  rc = Serialize_TPMI_DH_ENTITY(bind, &bind_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string nonce_caller_bytes;
  rc = Serialize_TPM2B_NONCE(nonce_caller, &nonce_caller_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string encrypted_salt_bytes;
  rc = Serialize_TPM2B_ENCRYPTED_SECRET(encrypted_salt, &encrypted_salt_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string session_type_bytes;
  rc = Serialize_TPM_SE(session_type, &session_type_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string symmetric_bytes;
  rc = Serialize_TPMT_SYM_DEF(symmetric, &symmetric_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string auth_hash_bytes;
  rc = Serialize_TPMI_ALG_HASH(auth_hash, &auth_hash_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (authorization_delegate) {
    // Encrypt just the parameter data, not the size.
    std::string tmp = nonce_caller_bytes.substr(2);
    if (!EncryptCommandParameter(authorization_delegate, &tmp)) {
      return TRUNKS_RC_ENCRYPTION_FAILED;
    }
    nonce_caller_bytes.replace(2, std::string::npos, tmp);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, tpm_key_name.data(), tpm_key_name.size());
  handle_section_bytes += tpm_key_bytes;
  command_size += tpm_key_bytes.size();
  pinweaver_eal_sha256_update(&hash, bind_name.data(), bind_name.size());
  handle_section_bytes += bind_bytes;
  command_size += bind_bytes.size();
  pinweaver_eal_sha256_update(&hash, nonce_caller_bytes.data(), nonce_caller_bytes.size());
  parameter_section_bytes += nonce_caller_bytes;
  command_size += nonce_caller_bytes.size();
  pinweaver_eal_sha256_update(&hash, encrypted_salt_bytes.data(), encrypted_salt_bytes.size());
  parameter_section_bytes += encrypted_salt_bytes;
  command_size += encrypted_salt_bytes.size();
  pinweaver_eal_sha256_update(&hash, session_type_bytes.data(), session_type_bytes.size());
  parameter_section_bytes += session_type_bytes;
  command_size += session_type_bytes.size();
  pinweaver_eal_sha256_update(&hash, symmetric_bytes.data(), symmetric_bytes.size());
  parameter_section_bytes += symmetric_bytes;
  command_size += symmetric_bytes.size();
  pinweaver_eal_sha256_update(&hash, auth_hash_bytes.data(), auth_hash_bytes.size());
  parameter_section_bytes += auth_hash_bytes;
  command_size += auth_hash_bytes.size();
  std::string command_hash(32, 0);
  char* hash_ptr = const_cast<char *>(command_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  std::string authorization_section_bytes;
  std::string authorization_size_bytes;
  if (authorization_delegate) {
    if (!GetCommandAuthorization(authorization_delegate, 
            command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!authorization_section_bytes.empty()) {
      tag = TPM_ST_SESSIONS;
      std::string tmp;
      rc = Serialize_UINT32(authorization_section_bytes.size(),
                            &authorization_size_bytes);
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      command_size +=
          authorization_size_bytes.size() + authorization_section_bytes.size();
    }
  }
  std::string tag_bytes;
  rc = Serialize_TPMI_ST_COMMAND_TAG(tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string command_size_bytes;
  rc = Serialize_UINT32(command_size, &command_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  *serialized_command = tag_bytes + command_size_bytes + command_code_bytes +
                        handle_section_bytes + authorization_size_bytes +
                        authorization_section_bytes + parameter_section_bytes;
  if (serialized_command->size() != command_size) {
    return TRUNKS_RC_SERIALIZATION_ERROR;
  }
  return TPM_RC_SUCCESS;
}

static TPM_RC ParseResponse_StartAuthSession(
    const std::string& response,
    TPMI_SH_AUTH_SESSION* session_handle,
    TPM2B_NONCE* nonce_tpm,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  std::string buffer(response);
  TPM_ST tag;
  std::string tag_bytes;
  rc = Parse_TPM_ST(&buffer, &tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  UINT32 response_size;
  std::string response_size_bytes;
  rc = Parse_UINT32(&buffer, &response_size, &response_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  TPM_RC response_code;
  std::string response_code_bytes;
  rc = Parse_TPM_RC(&buffer, &response_code, &response_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (response_size != response.size()) {
    return TPM_RC_SIZE;
  }
  if (response_code != TPM_RC_SUCCESS) {
    return response_code;
  }
  std::string session_handle_bytes;
  rc = Parse_TPMI_SH_AUTH_SESSION(&buffer, session_handle,
                                  &session_handle_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  TPM_CC command_code = TPM_CC_StartAuthSession;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string authorization_section_bytes;
  if (tag == TPM_ST_SESSIONS) {
    UINT32 parameter_section_size = buffer.size();
    rc = Parse_UINT32(&buffer, &parameter_section_size, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
    if (parameter_section_size > buffer.size()) {
      return TPM_RC_INSUFFICIENT;
    }
    authorization_section_bytes = buffer.substr(parameter_section_size);
    // Keep the parameter section in |buffer|.
    buffer.erase(parameter_section_size);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, response_code_bytes.data(), response_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, buffer.data(), buffer.size());
  std::string response_hash(32, 0);
  char* hash_ptr = const_cast<char *>(response_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!CheckResponseAuthorization(authorization_delegate, 
            response_hash, authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
  }
  std::string nonce_tpm_bytes;
  rc = Parse_TPM2B_NONCE(&buffer, nonce_tpm, &nonce_tpm_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    // Decrypt just the parameter data, not the size.
    std::string tmp = nonce_tpm_bytes.substr(2);
    if (!DecryptResponseParameter(authorization_delegate, &tmp)) {
      return TRUNKS_RC_ENCRYPTION_FAILED;
    }
    nonce_tpm_bytes.replace(2, std::string::npos, tmp);
    rc = Parse_TPM2B_NONCE(&nonce_tpm_bytes, nonce_tpm, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC StartAuthSession(
    const TPMI_DH_OBJECT& tpm_key,
    const std::string& tpm_key_name,
    const TPMI_DH_ENTITY& bind,
    const std::string& bind_name,
    const TPM2B_NONCE& nonce_caller,
    const TPM2B_ENCRYPTED_SECRET& encrypted_salt,
    const TPM_SE& session_type,
    const TPMT_SYM_DEF& symmetric,
    const TPMI_ALG_HASH& auth_hash,
    TPMI_SH_AUTH_SESSION* session_handle,
    TPM2B_NONCE* nonce_tpm,
    AuthorizationDelegate* authorization_delegate) {
  std::string command;
  TPM_RC rc = SerializeCommand_StartAuthSession(
      tpm_key, tpm_key_name, bind, bind_name, nonce_caller, encrypted_salt,
      session_type, symmetric, auth_hash, &command, authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string response;
  SendCommandAndWait(command, &response);
  rc = ParseResponse_StartAuthSession(response, session_handle, nonce_tpm,
                                      authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_ReadPublic(
    const TPMI_DH_OBJECT& object_handle,
    const std::string& object_handle_name,
    std::string* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  UINT32 command_size = 10;  // Header size.
  std::string handle_section_bytes;
  std::string parameter_section_bytes;
  TPM_CC command_code = TPM_CC_ReadPublic;
  bool is_command_parameter_encryption_possible = false;
  bool is_response_parameter_encryption_possible = true;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string object_handle_bytes;
  rc = Serialize_TPMI_DH_OBJECT(object_handle, &object_handle_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, object_handle_name.data(), object_handle_name.size());
  handle_section_bytes += object_handle_bytes;
  command_size += object_handle_bytes.size();
  std::string command_hash(32, 0);
  char* hash_ptr = const_cast<char *>(command_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  std::string authorization_section_bytes;
  std::string authorization_size_bytes;
  if (authorization_delegate) {
    if (!GetCommandAuthorization(authorization_delegate, 
            command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!authorization_section_bytes.empty()) {
      tag = TPM_ST_SESSIONS;
      std::string tmp;
      rc = Serialize_UINT32(authorization_section_bytes.size(),
                            &authorization_size_bytes);
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      command_size +=
          authorization_size_bytes.size() + authorization_section_bytes.size();
    }
  }
  std::string tag_bytes;
  rc = Serialize_TPMI_ST_COMMAND_TAG(tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string command_size_bytes;
  rc = Serialize_UINT32(command_size, &command_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  *serialized_command = tag_bytes + command_size_bytes + command_code_bytes +
                        handle_section_bytes + authorization_size_bytes +
                        authorization_section_bytes + parameter_section_bytes;
  if (serialized_command->size() != command_size) {
    return TRUNKS_RC_SERIALIZATION_ERROR;
  }
  return TPM_RC_SUCCESS;
}

static TPM_RC ParseResponse_ReadPublic(
    const std::string& response,
    TPM2B_PUBLIC* out_public,
    TPM2B_NAME* name,
    TPM2B_NAME* qualified_name,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  std::string buffer(response);
  TPM_ST tag;
  std::string tag_bytes;
  rc = Parse_TPM_ST(&buffer, &tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  UINT32 response_size;
  std::string response_size_bytes;
  rc = Parse_UINT32(&buffer, &response_size, &response_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  TPM_RC response_code;
  std::string response_code_bytes;
  rc = Parse_TPM_RC(&buffer, &response_code, &response_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (response_size != response.size()) {
    return TPM_RC_SIZE;
  }
  if (response_code != TPM_RC_SUCCESS) {
    return response_code;
  }
  TPM_CC command_code = TPM_CC_ReadPublic;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string authorization_section_bytes;
  if (tag == TPM_ST_SESSIONS) {
    UINT32 parameter_section_size = buffer.size();
    rc = Parse_UINT32(&buffer, &parameter_section_size, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
    if (parameter_section_size > buffer.size()) {
      return TPM_RC_INSUFFICIENT;
    }
    authorization_section_bytes = buffer.substr(parameter_section_size);
    // Keep the parameter section in |buffer|.
    buffer.erase(parameter_section_size);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, response_code_bytes.data(), response_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, buffer.data(), buffer.size());
  std::string response_hash(32, 0);
  char* hash_ptr = const_cast<char *>(response_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!CheckResponseAuthorization(authorization_delegate, 
            response_hash, authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
  }
  std::string out_public_bytes;
  rc = Parse_TPM2B_PUBLIC(&buffer, out_public, &out_public_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string name_bytes;
  rc = Parse_TPM2B_NAME(&buffer, name, &name_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string qualified_name_bytes;
  rc = Parse_TPM2B_NAME(&buffer, qualified_name, &qualified_name_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    // Decrypt just the parameter data, not the size.
    std::string tmp = out_public_bytes.substr(2);
    if (!DecryptResponseParameter(authorization_delegate, &tmp)) {
      return TRUNKS_RC_ENCRYPTION_FAILED;
    }
    out_public_bytes.replace(2, std::string::npos, tmp);
    rc = Parse_TPM2B_PUBLIC(&out_public_bytes, out_public, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC ReadPublic(const TPMI_DH_OBJECT& object_handle,
                  const std::string& object_handle_name,
                  TPM2B_PUBLIC* out_public,
                  TPM2B_NAME* name,
                  TPM2B_NAME* qualified_name,
                  AuthorizationDelegate* authorization_delegate) {
  std::string command;
  TPM_RC rc = SerializeCommand_ReadPublic(object_handle, object_handle_name,
                                          &command, authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string response;
  SendCommandAndWait(command, &response);

  rc = ParseResponse_ReadPublic(response, out_public, name, qualified_name,
                                authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_PolicyCommandCode(
    const TPMI_SH_POLICY& policy_session,
    const std::string& policy_session_name,
    const TPM_CC& code,
    std::string* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  UINT32 command_size = 10;  // Header size.
  std::string handle_section_bytes;
  std::string parameter_section_bytes;
  TPM_CC command_code = TPM_CC_PolicyCommandCode;
  bool is_command_parameter_encryption_possible = false;
  bool is_response_parameter_encryption_possible = false;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string policy_session_bytes;
  rc = Serialize_TPMI_SH_POLICY(policy_session, &policy_session_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string code_bytes;
  rc = Serialize_TPM_CC(code, &code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, policy_session_name.data(), policy_session_name.size());
  handle_section_bytes += policy_session_bytes;
  command_size += policy_session_bytes.size();
  pinweaver_eal_sha256_update(&hash, code_bytes.data(), code_bytes.size());
  parameter_section_bytes += code_bytes;
  command_size += code_bytes.size();
  std::string command_hash(32, 0);
  char* hash_ptr = const_cast<char *>(command_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  std::string authorization_section_bytes;
  std::string authorization_size_bytes;
  if (authorization_delegate) {
    if (!GetCommandAuthorization(authorization_delegate, 
            command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!authorization_section_bytes.empty()) {
      tag = TPM_ST_SESSIONS;
      std::string tmp;
      rc = Serialize_UINT32(authorization_section_bytes.size(),
                            &authorization_size_bytes);
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      command_size +=
          authorization_size_bytes.size() + authorization_section_bytes.size();
    }
  }
  std::string tag_bytes;
  rc = Serialize_TPMI_ST_COMMAND_TAG(tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string command_size_bytes;
  rc = Serialize_UINT32(command_size, &command_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  *serialized_command = tag_bytes + command_size_bytes + command_code_bytes +
                        handle_section_bytes + authorization_size_bytes +
                        authorization_section_bytes + parameter_section_bytes;
  if (serialized_command->size() != command_size) {
    return TRUNKS_RC_SERIALIZATION_ERROR;
  }
  return TPM_RC_SUCCESS;
}

static TPM_RC ParseResponse_PolicyCommandCode(
    const std::string& response,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  std::string buffer(response);
  TPM_ST tag;
  std::string tag_bytes;
  rc = Parse_TPM_ST(&buffer, &tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  UINT32 response_size;
  std::string response_size_bytes;
  rc = Parse_UINT32(&buffer, &response_size, &response_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  TPM_RC response_code;
  std::string response_code_bytes;
  rc = Parse_TPM_RC(&buffer, &response_code, &response_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (response_size != response.size()) {
    return TPM_RC_SIZE;
  }
  if (response_code != TPM_RC_SUCCESS) {
    return response_code;
  }
  TPM_CC command_code = TPM_CC_PolicyCommandCode;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string authorization_section_bytes;
  if (tag == TPM_ST_SESSIONS) {
    UINT32 parameter_section_size = buffer.size();
    rc = Parse_UINT32(&buffer, &parameter_section_size, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
    if (parameter_section_size > buffer.size()) {
      return TPM_RC_INSUFFICIENT;
    }
    authorization_section_bytes = buffer.substr(parameter_section_size);
    // Keep the parameter section in |buffer|.
    buffer.erase(parameter_section_size);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, response_code_bytes.data(), response_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, buffer.data(), buffer.size());
  std::string response_hash(32, 0);
  char* hash_ptr = const_cast<char *>(response_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!CheckResponseAuthorization(authorization_delegate, 
            response_hash, authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC PolicyCommandCode(
    const TPMI_SH_POLICY& policy_session,
    const std::string& policy_session_name,
    const TPM_CC& code,
    AuthorizationDelegate* authorization_delegate) {
  std::string command;
  TPM_RC rc = SerializeCommand_PolicyCommandCode(
      policy_session, policy_session_name, code, &command,
      authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string response;
  SendCommandAndWait(command, &response);

  rc = ParseResponse_PolicyCommandCode(response, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_PolicyAuthValue(
    const TPMI_SH_POLICY& policy_session,
    const std::string& policy_session_name,
    std::string* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  UINT32 command_size = 10;  // Header size.
  std::string handle_section_bytes;
  std::string parameter_section_bytes;
  TPM_CC command_code = TPM_CC_PolicyAuthValue;
  bool is_command_parameter_encryption_possible = false;
  bool is_response_parameter_encryption_possible = false;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string policy_session_bytes;
  rc = Serialize_TPMI_SH_POLICY(policy_session, &policy_session_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, policy_session_name.data(), policy_session_name.size());
  handle_section_bytes += policy_session_bytes;
  command_size += policy_session_bytes.size();
  std::string command_hash(32, 0);
  char* hash_ptr = const_cast<char *>(command_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  std::string authorization_section_bytes;
  std::string authorization_size_bytes;
  if (authorization_delegate) {
    if (!GetCommandAuthorization(authorization_delegate, 
            command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!authorization_section_bytes.empty()) {
      tag = TPM_ST_SESSIONS;
      std::string tmp;
      rc = Serialize_UINT32(authorization_section_bytes.size(),
                            &authorization_size_bytes);
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      command_size +=
          authorization_size_bytes.size() + authorization_section_bytes.size();
    }
  }
  std::string tag_bytes;
  rc = Serialize_TPMI_ST_COMMAND_TAG(tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string command_size_bytes;
  rc = Serialize_UINT32(command_size, &command_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  *serialized_command = tag_bytes + command_size_bytes + command_code_bytes +
                        handle_section_bytes + authorization_size_bytes +
                        authorization_section_bytes + parameter_section_bytes;
  if (serialized_command->size() != command_size) {
    return TRUNKS_RC_SERIALIZATION_ERROR;
  }
  return TPM_RC_SUCCESS;
}

static TPM_RC ParseResponse_PolicyAuthValue(
    const std::string& response,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  std::string buffer(response);
  TPM_ST tag;
  std::string tag_bytes;
  rc = Parse_TPM_ST(&buffer, &tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  UINT32 response_size;
  std::string response_size_bytes;
  rc = Parse_UINT32(&buffer, &response_size, &response_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  TPM_RC response_code;
  std::string response_code_bytes;
  rc = Parse_TPM_RC(&buffer, &response_code, &response_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (response_size != response.size()) {
    return TPM_RC_SIZE;
  }
  if (response_code != TPM_RC_SUCCESS) {
    return response_code;
  }
  TPM_CC command_code = TPM_CC_PolicyAuthValue;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string authorization_section_bytes;
  if (tag == TPM_ST_SESSIONS) {
    UINT32 parameter_section_size = buffer.size();
    rc = Parse_UINT32(&buffer, &parameter_section_size, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
    if (parameter_section_size > buffer.size()) {
      return TPM_RC_INSUFFICIENT;
    }
    authorization_section_bytes = buffer.substr(parameter_section_size);
    // Keep the parameter section in |buffer|.
    buffer.erase(parameter_section_size);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, response_code_bytes.data(), response_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, buffer.data(), buffer.size());
  std::string response_hash(32, 0);
  char* hash_ptr = const_cast<char *>(response_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!CheckResponseAuthorization(authorization_delegate, 
            response_hash, authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC PolicyAuthValue(const TPMI_SH_POLICY& policy_session,
                       const std::string& policy_session_name,
                       AuthorizationDelegate* authorization_delegate) {
  std::string command;
  TPM_RC rc = SerializeCommand_PolicyAuthValue(
      policy_session, policy_session_name, &command, authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string response;
  SendCommandAndWait(command, &response);

  rc = ParseResponse_PolicyAuthValue(response, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_FlushContext(
    const TPMI_DH_CONTEXT& flush_handle,
    std::string* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  UINT32 command_size = 10;  // Header size.
  std::string handle_section_bytes;
  std::string parameter_section_bytes;
  TPM_CC command_code = TPM_CC_FlushContext;
  bool is_command_parameter_encryption_possible = false;
  bool is_response_parameter_encryption_possible = false;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string flush_handle_bytes;
  rc = Serialize_TPMI_DH_CONTEXT(flush_handle, &flush_handle_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, flush_handle_bytes.data(), flush_handle_bytes.size());
  parameter_section_bytes += flush_handle_bytes;
  command_size += flush_handle_bytes.size();
  std::string command_hash(32, 0);
  char* hash_ptr = const_cast<char *>(command_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  std::string authorization_section_bytes;
  std::string authorization_size_bytes;
  if (authorization_delegate) {
    if (!GetCommandAuthorization(authorization_delegate, 
            command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!authorization_section_bytes.empty()) {
      tag = TPM_ST_SESSIONS;
      std::string tmp;
      rc = Serialize_UINT32(authorization_section_bytes.size(),
                            &authorization_size_bytes);
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      command_size +=
          authorization_size_bytes.size() + authorization_section_bytes.size();
    }
  }
  std::string tag_bytes;
  rc = Serialize_TPMI_ST_COMMAND_TAG(tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string command_size_bytes;
  rc = Serialize_UINT32(command_size, &command_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  *serialized_command = tag_bytes + command_size_bytes + command_code_bytes +
                        handle_section_bytes + authorization_size_bytes +
                        authorization_section_bytes + parameter_section_bytes;
  if (serialized_command->size() != command_size) {
    return TRUNKS_RC_SERIALIZATION_ERROR;
  }
  return TPM_RC_SUCCESS;
}

static TPM_RC ParseResponse_FlushContext(
    const std::string& response,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  std::string buffer(response);
  TPM_ST tag;
  std::string tag_bytes;
  rc = Parse_TPM_ST(&buffer, &tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  UINT32 response_size;
  std::string response_size_bytes;
  rc = Parse_UINT32(&buffer, &response_size, &response_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  TPM_RC response_code;
  std::string response_code_bytes;
  rc = Parse_TPM_RC(&buffer, &response_code, &response_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (response_size != response.size()) {
    return TPM_RC_SIZE;
  }
  if (response_code != TPM_RC_SUCCESS) {
    return response_code;
  }
  TPM_CC command_code = TPM_CC_FlushContext;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string authorization_section_bytes;
  if (tag == TPM_ST_SESSIONS) {
    UINT32 parameter_section_size = buffer.size();
    rc = Parse_UINT32(&buffer, &parameter_section_size, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
    if (parameter_section_size > buffer.size()) {
      return TPM_RC_INSUFFICIENT;
    }
    authorization_section_bytes = buffer.substr(parameter_section_size);
    // Keep the parameter section in |buffer|.
    buffer.erase(parameter_section_size);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, response_code_bytes.data(), response_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, buffer.data(), buffer.size());
  std::string response_hash(32, 0);
  char* hash_ptr = const_cast<char *>(response_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!CheckResponseAuthorization(authorization_delegate, 
            response_hash, authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC FlushContext(const TPMI_DH_CONTEXT& flush_handle,
                    AuthorizationDelegate* authorization_delegate) {
  std::string command;
  TPM_RC rc = SerializeCommand_FlushContext(flush_handle, &command,
                                            authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string response;
  SendCommandAndWait(command, &response);

  rc = ParseResponse_FlushContext(response, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_NV_DefineSpace(
    const TPMI_RH_PROVISION& auth_handle,
    const std::string& auth_handle_name,
    const TPM2B_AUTH& auth,
    const TPM2B_NV_PUBLIC& public_info,
    std::string* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  UINT32 command_size = 10;  // Header size.
  std::string handle_section_bytes;
  std::string parameter_section_bytes;
  TPM_CC command_code = TPM_CC_NV_DefineSpace;
  bool is_command_parameter_encryption_possible = true;
  bool is_response_parameter_encryption_possible = false;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string auth_handle_bytes;
  rc = Serialize_TPMI_RH_PROVISION(auth_handle, &auth_handle_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string auth_bytes;
  rc = Serialize_TPM2B_AUTH(auth, &auth_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string public_info_bytes;
  rc = Serialize_TPM2B_NV_PUBLIC(public_info, &public_info_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (authorization_delegate) {
    // Encrypt just the parameter data, not the size.
    std::string tmp = auth_bytes.substr(2);
    if (!EncryptCommandParameter(authorization_delegate, &tmp)) {
      return TRUNKS_RC_ENCRYPTION_FAILED;
    }
    auth_bytes.replace(2, std::string::npos, tmp);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, auth_handle_name.data(), auth_handle_name.size());
  handle_section_bytes += auth_handle_bytes;
  command_size += auth_handle_bytes.size();
  pinweaver_eal_sha256_update(&hash, auth_bytes.data(), auth_bytes.size());
  parameter_section_bytes += auth_bytes;
  command_size += auth_bytes.size();
  pinweaver_eal_sha256_update(&hash, public_info_bytes.data(), public_info_bytes.size());
  parameter_section_bytes += public_info_bytes;
  command_size += public_info_bytes.size();
  std::string command_hash(32, 0);
  char* hash_ptr = const_cast<char *>(command_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  std::string authorization_section_bytes;
  std::string authorization_size_bytes;
  if (authorization_delegate) {
    if (!GetCommandAuthorization(authorization_delegate, 
            command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!authorization_section_bytes.empty()) {
      tag = TPM_ST_SESSIONS;
      std::string tmp;
      rc = Serialize_UINT32(authorization_section_bytes.size(),
                            &authorization_size_bytes);
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      command_size +=
          authorization_size_bytes.size() + authorization_section_bytes.size();
    }
  }
  std::string tag_bytes;
  rc = Serialize_TPMI_ST_COMMAND_TAG(tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string command_size_bytes;
  rc = Serialize_UINT32(command_size, &command_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  *serialized_command = tag_bytes + command_size_bytes + command_code_bytes +
                        handle_section_bytes + authorization_size_bytes +
                        authorization_section_bytes + parameter_section_bytes;
  if (serialized_command->size() != command_size) {
    return TRUNKS_RC_SERIALIZATION_ERROR;
  }
  return TPM_RC_SUCCESS;
}

static TPM_RC ParseResponse_NV_DefineSpace(
    const std::string& response,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  std::string buffer(response);
  TPM_ST tag;
  std::string tag_bytes;
  rc = Parse_TPM_ST(&buffer, &tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  UINT32 response_size;
  std::string response_size_bytes;
  rc = Parse_UINT32(&buffer, &response_size, &response_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  TPM_RC response_code;
  std::string response_code_bytes;
  rc = Parse_TPM_RC(&buffer, &response_code, &response_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (response_size != response.size()) {
    return TPM_RC_SIZE;
  }
  if (response_code != TPM_RC_SUCCESS) {
    return response_code;
  }
  TPM_CC command_code = TPM_CC_NV_DefineSpace;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string authorization_section_bytes;
  if (tag == TPM_ST_SESSIONS) {
    UINT32 parameter_section_size = buffer.size();
    rc = Parse_UINT32(&buffer, &parameter_section_size, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
    if (parameter_section_size > buffer.size()) {
      return TPM_RC_INSUFFICIENT;
    }
    authorization_section_bytes = buffer.substr(parameter_section_size);
    // Keep the parameter section in |buffer|.
    buffer.erase(parameter_section_size);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, response_code_bytes.data(), response_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, buffer.data(), buffer.size());
  std::string response_hash(32, 0);
  char* hash_ptr = const_cast<char *>(response_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!CheckResponseAuthorization(authorization_delegate, 
            response_hash, authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC NV_DefineSpace(const TPMI_RH_PROVISION& auth_handle,
                      const std::string& auth_handle_name,
                      const TPM2B_AUTH& auth,
                      const TPM2B_NV_PUBLIC& public_info,
                      AuthorizationDelegate* authorization_delegate) {
  std::string command;
  TPM_RC rc = SerializeCommand_NV_DefineSpace(auth_handle, auth_handle_name,
                                              auth, public_info, &command,
                                              authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string response;
  SendCommandAndWait(command, &response);

  rc = ParseResponse_NV_DefineSpace(response, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_NV_ReadPublic(
    const TPMI_RH_NV_INDEX& nv_index,
    const std::string& nv_index_name,
    std::string* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  UINT32 command_size = 10;  // Header size.
  std::string handle_section_bytes;
  std::string parameter_section_bytes;
  TPM_CC command_code = TPM_CC_NV_ReadPublic;
  bool is_command_parameter_encryption_possible = false;
  bool is_response_parameter_encryption_possible = true;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string nv_index_bytes;
  rc = Serialize_TPMI_RH_NV_INDEX(nv_index, &nv_index_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, nv_index_name.data(), nv_index_name.size());
  handle_section_bytes += nv_index_bytes;
  command_size += nv_index_bytes.size();
  std::string command_hash(32, 0);
  char* hash_ptr = const_cast<char *>(command_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  std::string authorization_section_bytes;
  std::string authorization_size_bytes;
  if (authorization_delegate) {
    if (!GetCommandAuthorization(authorization_delegate, 
            command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!authorization_section_bytes.empty()) {
      tag = TPM_ST_SESSIONS;
      std::string tmp;
      rc = Serialize_UINT32(authorization_section_bytes.size(),
                            &authorization_size_bytes);
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      command_size +=
          authorization_size_bytes.size() + authorization_section_bytes.size();
    }
  }
  std::string tag_bytes;
  rc = Serialize_TPMI_ST_COMMAND_TAG(tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string command_size_bytes;
  rc = Serialize_UINT32(command_size, &command_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  *serialized_command = tag_bytes + command_size_bytes + command_code_bytes +
                        handle_section_bytes + authorization_size_bytes +
                        authorization_section_bytes + parameter_section_bytes;
  if (serialized_command->size() != command_size) {
    return TRUNKS_RC_SERIALIZATION_ERROR;
  }
  return TPM_RC_SUCCESS;
}

static TPM_RC ParseResponse_NV_ReadPublic(
    const std::string& response,
    TPM2B_NV_PUBLIC* nv_public,
    TPM2B_NAME* nv_name,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  std::string buffer(response);
  TPM_ST tag;
  std::string tag_bytes;
  rc = Parse_TPM_ST(&buffer, &tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  UINT32 response_size;
  std::string response_size_bytes;
  rc = Parse_UINT32(&buffer, &response_size, &response_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  TPM_RC response_code;
  std::string response_code_bytes;
  rc = Parse_TPM_RC(&buffer, &response_code, &response_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (response_size != response.size()) {
    return TPM_RC_SIZE;
  }
  if (response_code != TPM_RC_SUCCESS) {
    return response_code;
  }
  TPM_CC command_code = TPM_CC_NV_ReadPublic;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string authorization_section_bytes;
  if (tag == TPM_ST_SESSIONS) {
    UINT32 parameter_section_size = buffer.size();
    rc = Parse_UINT32(&buffer, &parameter_section_size, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
    if (parameter_section_size > buffer.size()) {
      return TPM_RC_INSUFFICIENT;
    }
    authorization_section_bytes = buffer.substr(parameter_section_size);
    // Keep the parameter section in |buffer|.
    buffer.erase(parameter_section_size);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, response_code_bytes.data(), response_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, buffer.data(), buffer.size());
  std::string response_hash(32, 0);
  char* hash_ptr = const_cast<char *>(response_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!CheckResponseAuthorization(authorization_delegate, 
            response_hash, authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
  }
  std::string nv_public_bytes;
  rc = Parse_TPM2B_NV_PUBLIC(&buffer, nv_public, &nv_public_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string nv_name_bytes;
  rc = Parse_TPM2B_NAME(&buffer, nv_name, &nv_name_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    // Decrypt just the parameter data, not the size.
    std::string tmp = nv_public_bytes.substr(2);
    if (!DecryptResponseParameter(authorization_delegate, &tmp)) {
      return TRUNKS_RC_ENCRYPTION_FAILED;
    }
    nv_public_bytes.replace(2, std::string::npos, tmp);
    rc = Parse_TPM2B_NV_PUBLIC(&nv_public_bytes, nv_public, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC NV_ReadPublic(const TPMI_RH_NV_INDEX& nv_index,
                     const std::string& nv_index_name,
                     TPM2B_NV_PUBLIC* nv_public,
                     TPM2B_NAME* nv_name,
                     AuthorizationDelegate* authorization_delegate) {
  std::string command;
  TPM_RC rc = SerializeCommand_NV_ReadPublic(nv_index, nv_index_name, &command,
                                             authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string response;
  SendCommandAndWait(command, &response);

  rc = ParseResponse_NV_ReadPublic(response, nv_public, nv_name,
                                   authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_NV_Write(
    const TPMI_RH_NV_AUTH& auth_handle,
    const std::string& auth_handle_name,
    const TPMI_RH_NV_INDEX& nv_index,
    const std::string& nv_index_name,
    const TPM2B_MAX_NV_BUFFER& data,
    const UINT16& offset,
    std::string* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  UINT32 command_size = 10;  // Header size.
  std::string handle_section_bytes;
  std::string parameter_section_bytes;
  TPM_CC command_code = TPM_CC_NV_Write;
  bool is_command_parameter_encryption_possible = true;
  bool is_response_parameter_encryption_possible = false;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string auth_handle_bytes;
  rc = Serialize_TPMI_RH_NV_AUTH(auth_handle, &auth_handle_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string nv_index_bytes;
  rc = Serialize_TPMI_RH_NV_INDEX(nv_index, &nv_index_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string data_bytes;
  rc = Serialize_TPM2B_MAX_NV_BUFFER(data, &data_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string offset_bytes;
  rc = Serialize_UINT16(offset, &offset_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (authorization_delegate) {
    // Encrypt just the parameter data, not the size.
    std::string tmp = data_bytes.substr(2);
    if (!EncryptCommandParameter(authorization_delegate, &tmp)) {
      return TRUNKS_RC_ENCRYPTION_FAILED;
    }
    data_bytes.replace(2, std::string::npos, tmp);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, auth_handle_name.data(), auth_handle_name.size());
  handle_section_bytes += auth_handle_bytes;
  command_size += auth_handle_bytes.size();
  pinweaver_eal_sha256_update(&hash, nv_index_name.data(), nv_index_name.size());
  handle_section_bytes += nv_index_bytes;
  command_size += nv_index_bytes.size();
  pinweaver_eal_sha256_update(&hash, data_bytes.data(), data_bytes.size());
  parameter_section_bytes += data_bytes;
  command_size += data_bytes.size();
  pinweaver_eal_sha256_update(&hash, offset_bytes.data(), offset_bytes.size());
  parameter_section_bytes += offset_bytes;
  command_size += offset_bytes.size();
  std::string command_hash(32, 0);
  char* hash_ptr = const_cast<char *>(command_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  std::string authorization_section_bytes;
  std::string authorization_size_bytes;
  if (authorization_delegate) {
    if (!GetCommandAuthorization(authorization_delegate, 
            command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!authorization_section_bytes.empty()) {
      tag = TPM_ST_SESSIONS;
      std::string tmp;
      rc = Serialize_UINT32(authorization_section_bytes.size(),
                            &authorization_size_bytes);
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      command_size +=
          authorization_size_bytes.size() + authorization_section_bytes.size();
    }
  }
  std::string tag_bytes;
  rc = Serialize_TPMI_ST_COMMAND_TAG(tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string command_size_bytes;
  rc = Serialize_UINT32(command_size, &command_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  *serialized_command = tag_bytes + command_size_bytes + command_code_bytes +
                        handle_section_bytes + authorization_size_bytes +
                        authorization_section_bytes + parameter_section_bytes;
  if (serialized_command->size() != command_size) {
    return TRUNKS_RC_SERIALIZATION_ERROR;
  }
  return TPM_RC_SUCCESS;
}

static TPM_RC ParseResponse_NV_Write(
    const std::string& response,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  std::string buffer(response);
  TPM_ST tag;
  std::string tag_bytes;
  rc = Parse_TPM_ST(&buffer, &tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  UINT32 response_size;
  std::string response_size_bytes;
  rc = Parse_UINT32(&buffer, &response_size, &response_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  TPM_RC response_code;
  std::string response_code_bytes;
  rc = Parse_TPM_RC(&buffer, &response_code, &response_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (response_size != response.size()) {
    return TPM_RC_SIZE;
  }
  if (response_code != TPM_RC_SUCCESS) {
    return response_code;
  }
  TPM_CC command_code = TPM_CC_NV_Write;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string authorization_section_bytes;
  if (tag == TPM_ST_SESSIONS) {
    UINT32 parameter_section_size = buffer.size();
    rc = Parse_UINT32(&buffer, &parameter_section_size, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
    if (parameter_section_size > buffer.size()) {
      return TPM_RC_INSUFFICIENT;
    }
    authorization_section_bytes = buffer.substr(parameter_section_size);
    // Keep the parameter section in |buffer|.
    buffer.erase(parameter_section_size);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, response_code_bytes.data(), response_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, buffer.data(), buffer.size());
  std::string response_hash(32, 0);
  char* hash_ptr = const_cast<char *>(response_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!CheckResponseAuthorization(authorization_delegate, 
            response_hash, authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC NV_Write(const TPMI_RH_NV_AUTH& auth_handle,
                const std::string& auth_handle_name,
                const TPMI_RH_NV_INDEX& nv_index,
                const std::string& nv_index_name,
                const TPM2B_MAX_NV_BUFFER& data,
                const UINT16& offset,
                AuthorizationDelegate* authorization_delegate) {
  std::string command;
  TPM_RC rc = SerializeCommand_NV_Write(auth_handle, auth_handle_name, nv_index,
                                        nv_index_name, data, offset, &command,
                                        authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string response;
  SendCommandAndWait(command, &response);

  rc = ParseResponse_NV_Write(response, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_NV_Read(
    const TPMI_RH_NV_AUTH& auth_handle,
    const std::string& auth_handle_name,
    const TPMI_RH_NV_INDEX& nv_index,
    const std::string& nv_index_name,
    const UINT16& size,
    const UINT16& offset,
    std::string* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  UINT32 command_size = 10;  // Header size.
  std::string handle_section_bytes;
  std::string parameter_section_bytes;
  TPM_CC command_code = TPM_CC_NV_Read;
  bool is_command_parameter_encryption_possible = false;
  bool is_response_parameter_encryption_possible = true;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string auth_handle_bytes;
  rc = Serialize_TPMI_RH_NV_AUTH(auth_handle, &auth_handle_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string nv_index_bytes;
  rc = Serialize_TPMI_RH_NV_INDEX(nv_index, &nv_index_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string size_bytes;
  rc = Serialize_UINT16(size, &size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string offset_bytes;
  rc = Serialize_UINT16(offset, &offset_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, auth_handle_name.data(), auth_handle_name.size());
  handle_section_bytes += auth_handle_bytes;
  command_size += auth_handle_bytes.size();
  pinweaver_eal_sha256_update(&hash, nv_index_name.data(), nv_index_name.size());
  handle_section_bytes += nv_index_bytes;
  command_size += nv_index_bytes.size();
  pinweaver_eal_sha256_update(&hash, size_bytes.data(), size_bytes.size());
  parameter_section_bytes += size_bytes;
  command_size += size_bytes.size();
  pinweaver_eal_sha256_update(&hash, offset_bytes.data(), offset_bytes.size());
  parameter_section_bytes += offset_bytes;
  command_size += offset_bytes.size();
  std::string command_hash(32, 0);
  char* hash_ptr = const_cast<char *>(command_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  std::string authorization_section_bytes;
  std::string authorization_size_bytes;
  if (authorization_delegate) {
    if (!GetCommandAuthorization(authorization_delegate, 
            command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!authorization_section_bytes.empty()) {
      tag = TPM_ST_SESSIONS;
      std::string tmp;
      rc = Serialize_UINT32(authorization_section_bytes.size(),
                            &authorization_size_bytes);
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      command_size +=
          authorization_size_bytes.size() + authorization_section_bytes.size();
    }
  }
  std::string tag_bytes;
  rc = Serialize_TPMI_ST_COMMAND_TAG(tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string command_size_bytes;
  rc = Serialize_UINT32(command_size, &command_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  *serialized_command = tag_bytes + command_size_bytes + command_code_bytes +
                        handle_section_bytes + authorization_size_bytes +
                        authorization_section_bytes + parameter_section_bytes;
  if (serialized_command->size() != command_size) {
    return TRUNKS_RC_SERIALIZATION_ERROR;
  }
  return TPM_RC_SUCCESS;
}

static TPM_RC ParseResponse_NV_Read(
    const std::string& response,
    TPM2B_MAX_NV_BUFFER* data,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  std::string buffer(response);
  TPM_ST tag;
  std::string tag_bytes;
  rc = Parse_TPM_ST(&buffer, &tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  UINT32 response_size;
  std::string response_size_bytes;
  rc = Parse_UINT32(&buffer, &response_size, &response_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  TPM_RC response_code;
  std::string response_code_bytes;
  rc = Parse_TPM_RC(&buffer, &response_code, &response_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (response_size != response.size()) {
    return TPM_RC_SIZE;
  }
  if (response_code != TPM_RC_SUCCESS) {
    return response_code;
  }
  TPM_CC command_code = TPM_CC_NV_Read;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string authorization_section_bytes;
  if (tag == TPM_ST_SESSIONS) {
    UINT32 parameter_section_size = buffer.size();
    rc = Parse_UINT32(&buffer, &parameter_section_size, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
    if (parameter_section_size > buffer.size()) {
      return TPM_RC_INSUFFICIENT;
    }
    authorization_section_bytes = buffer.substr(parameter_section_size);
    // Keep the parameter section in |buffer|.
    buffer.erase(parameter_section_size);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, response_code_bytes.data(), response_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, buffer.data(), buffer.size());
  std::string response_hash(32, 0);
  char* hash_ptr = const_cast<char *>(response_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!CheckResponseAuthorization(authorization_delegate, 
            response_hash, authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
  }
  std::string data_bytes;
  rc = Parse_TPM2B_MAX_NV_BUFFER(&buffer, data, &data_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    // Decrypt just the parameter data, not the size.
    std::string tmp = data_bytes.substr(2);
    if (!DecryptResponseParameter(authorization_delegate, &tmp)) {
      return TRUNKS_RC_ENCRYPTION_FAILED;
    }
    data_bytes.replace(2, std::string::npos, tmp);
    rc = Parse_TPM2B_MAX_NV_BUFFER(&data_bytes, data, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC NV_Read(const TPMI_RH_NV_AUTH& auth_handle,
               const std::string& auth_handle_name,
               const TPMI_RH_NV_INDEX& nv_index,
               const std::string& nv_index_name,
               const UINT16& size,
               const UINT16& offset,
               TPM2B_MAX_NV_BUFFER* data,
               AuthorizationDelegate* authorization_delegate) {
  std::string command;
  TPM_RC rc = SerializeCommand_NV_Read(auth_handle, auth_handle_name, nv_index,
                                       nv_index_name, size, offset, &command,
                                       authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string response;
  SendCommandAndWait(command, &response);

  rc = ParseResponse_NV_Read(response, data, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_NV_ChangeAuth(
    const TPMI_RH_NV_INDEX& nv_index,
    const std::string& nv_index_name,
    const TPM2B_AUTH& new_auth,
    std::string* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  UINT32 command_size = 10;  // Header size.
  std::string handle_section_bytes;
  std::string parameter_section_bytes;
  TPM_CC command_code = TPM_CC_NV_ChangeAuth;
  bool is_command_parameter_encryption_possible = true;
  bool is_response_parameter_encryption_possible = false;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string nv_index_bytes;
  rc = Serialize_TPMI_RH_NV_INDEX(nv_index, &nv_index_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string new_auth_bytes;
  rc = Serialize_TPM2B_AUTH(new_auth, &new_auth_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (authorization_delegate) {
    // Encrypt just the parameter data, not the size.
    std::string tmp = new_auth_bytes.substr(2);
    if (!EncryptCommandParameter(authorization_delegate, &tmp)) {
      return TRUNKS_RC_ENCRYPTION_FAILED;
    }
    new_auth_bytes.replace(2, std::string::npos, tmp);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, nv_index_name.data(), nv_index_name.size());
  handle_section_bytes += nv_index_bytes;
  command_size += nv_index_bytes.size();
  pinweaver_eal_sha256_update(&hash, new_auth_bytes.data(), new_auth_bytes.size());
  parameter_section_bytes += new_auth_bytes;
  command_size += new_auth_bytes.size();
  std::string command_hash(32, 0);
  char* hash_ptr = const_cast<char *>(command_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  std::string authorization_section_bytes;
  std::string authorization_size_bytes;
  if (authorization_delegate) {
    if (!GetCommandAuthorization(authorization_delegate, 
            command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!authorization_section_bytes.empty()) {
      tag = TPM_ST_SESSIONS;
      std::string tmp;
      rc = Serialize_UINT32(authorization_section_bytes.size(),
                            &authorization_size_bytes);
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      command_size +=
          authorization_size_bytes.size() + authorization_section_bytes.size();
    }
  }
  std::string tag_bytes;
  rc = Serialize_TPMI_ST_COMMAND_TAG(tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string command_size_bytes;
  rc = Serialize_UINT32(command_size, &command_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  *serialized_command = tag_bytes + command_size_bytes + command_code_bytes +
                        handle_section_bytes + authorization_size_bytes +
                        authorization_section_bytes + parameter_section_bytes;
  if (serialized_command->size() != command_size) {
    return TRUNKS_RC_SERIALIZATION_ERROR;
  }
  return TPM_RC_SUCCESS;
}

static TPM_RC ParseResponse_NV_ChangeAuth(
    const std::string& response,
    AuthorizationDelegate* authorization_delegate) {
  TPM_RC rc = TPM_RC_SUCCESS;
  std::string buffer(response);
  TPM_ST tag;
  std::string tag_bytes;
  rc = Parse_TPM_ST(&buffer, &tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  UINT32 response_size;
  std::string response_size_bytes;
  rc = Parse_UINT32(&buffer, &response_size, &response_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  TPM_RC response_code;
  std::string response_code_bytes;
  rc = Parse_TPM_RC(&buffer, &response_code, &response_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (response_size != response.size()) {
    return TPM_RC_SIZE;
  }
  if (response_code != TPM_RC_SUCCESS) {
    return response_code;
  }
  TPM_CC command_code = TPM_CC_NV_ChangeAuth;
  std::string command_code_bytes;
  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string authorization_section_bytes;
  if (tag == TPM_ST_SESSIONS) {
    UINT32 parameter_section_size = buffer.size();
    rc = Parse_UINT32(&buffer, &parameter_section_size, nullptr);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
    if (parameter_section_size > buffer.size()) {
      return TPM_RC_INSUFFICIENT;
    }
    authorization_section_bytes = buffer.substr(parameter_section_size);
    // Keep the parameter section in |buffer|.
    buffer.erase(parameter_section_size);
  }
  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  pinweaver_eal_sha256_update(&hash, response_code_bytes.data(), response_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, command_code_bytes.data(), command_code_bytes.size());
  pinweaver_eal_sha256_update(&hash, buffer.data(), buffer.size());
  std::string response_hash(32, 0);
  char* hash_ptr = const_cast<char *>(response_hash.data());
  pinweaver_eal_sha256_final(&hash, hash_ptr);
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (!CheckResponseAuthorization(authorization_delegate, 
            response_hash, authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC NV_ChangeAuth(const TPMI_RH_NV_INDEX& nv_index,
                     const std::string& nv_index_name,
                     const TPM2B_AUTH& new_auth,
                     AuthorizationDelegate* authorization_delegate) {
  std::string command;
  TPM_RC rc = SerializeCommand_NV_ChangeAuth(nv_index, nv_index_name, new_auth,
                                             &command, authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string response;
  SendCommandAndWait(command, &response);

  rc = ParseResponse_NV_ChangeAuth(response, authorization_delegate);
  return rc;
}
