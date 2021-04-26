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

// TODO(apronin): remove after de-C++-ification
extern "C" {
#include "pinweaver_tpm.h"
}

const size_t kMaxAuthSectionSize = 3 * sizeof(TPMS_AUTH_COMMAND);
const size_t kSizeOffset = 2;
const size_t kMaxMessageSize = 4096;
uint8_t g_message[kMaxMessageSize];

static TPM_RC dst_data_buf_append(dst_data_buf_t* data_buf, const void* data,
                                  size_t size) {
  if (data_buf->size >= data_buf->max_size)
    return TPM_RC_INSUFFICIENT;
  if (data_buf->size + size > data_buf->max_size
      || size > data_buf->max_size) {
    return TPM_RC_INSUFFICIENT;
  }
  memcpy(data_buf->buffer + data_buf->size, data, size);
  data_buf->size += size;
  return TPM_RC_SUCCESS;
}

static TPM_RC dst_data_buf_skip(dst_data_buf_t* data_buf,
                                size_t size,
                                dst_data_buf_t* reserved) {
  if (data_buf->size + size > data_buf->max_size
      || size > data_buf->max_size) {
    return TPM_RC_INSUFFICIENT;
  }
  if (reserved) {
    reserved->buffer = data_buf->buffer + data_buf->size;
    reserved->max_size = size;
    reserved->size = 0;
  }
  data_buf->size += size;
  return TPM_RC_SUCCESS;
}

static void dst_data_buf_set_to_remainder(dst_data_buf_t* to,
                                          dst_data_buf_t* from) {
  to->max_size = from->max_size - from->size;
  to->buffer = from->buffer + from->size;
  to->size = 0;
}

static TPM_RC src_data_buf_move_start(src_data_buf_t* data_buf,
    dst_data_buf_t* value_bytes, size_t size) {
  if (value_bytes) {
    TPM_RC result = dst_data_buf_append(value_bytes, data_buf->buffer, size);
    if (result)
      return result;
  }
  if (size > data_buf->size)
    return TPM_RC_INSUFFICIENT;
  data_buf->buffer += size;
  data_buf->size -= size;
  return TPM_RC_SUCCESS;
}

static TPM_RC dst_data_buf_set_at_offset(dst_data_buf_t* to,
    dst_data_buf_t* from, size_t offset) {
  if (from->size + offset > from->max_size || offset > from->max_size)
    return TPM_RC_INSUFFICIENT;
  to->buffer = from->buffer;
  to->max_size = from->max_size;
  to->size = from->size + offset;
  return TPM_RC_SUCCESS;
}

static TPM_RC dst_data_buf_insert(dst_data_buf_t* data_buf,
  dst_data_buf_t* new_buf, size_t offset, size_t size) {
  if (data_buf->size + size > data_buf->max_size
      || size > data_buf->max_size
      || offset > data_buf->size) {
    return TPM_RC_INSUFFICIENT;
  }
  memmove(data_buf->buffer + offset + size, data_buf->buffer + offset,
          data_buf->size - offset);
  data_buf->size += size;
  new_buf->buffer = data_buf->buffer + offset;
  new_buf->max_size = size;
  new_buf->size = 0;
  return TPM_RC_SUCCESS;
}

static void SendCommandAndWait(const dst_data_buf_t* command,
                               src_data_buf_t* response) {
  send_command_and_wait((const char *)(command->buffer), (char *)g_message);
  src_data_buf_t buffer = {sizeof(UINT32), g_message + kSizeOffset};
  UINT32 response_size;
  TPM_RC rc = Parse_UINT32(&buffer, &response_size, NULL);
  response->buffer = g_message;
  if (rc != TPM_RC_SUCCESS || response_size > kMaxMessageSize) {
    response->size = 0;
  } else {
    response->size = response_size;
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

TPM_RC Serialize_uint8_t(const uint8_t* value, dst_data_buf_t* buffer) {
  uint8_t value_net = *value;
  switch (sizeof(uint8_t)) {
    case 2:
      value_net = htobe16(*value);
      break;
    case 4:
      value_net = htobe32(*value);
      break;
    case 8:
      value_net = htobe64(*value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  return dst_data_buf_append(buffer, value_bytes, sizeof(uint8_t));
}

TPM_RC Parse_uint8_t(src_data_buf_t* buffer,
                     uint8_t* value,
                     dst_data_buf_t* value_bytes) {
  if (buffer->size < sizeof(uint8_t))
    return TPM_RC_INSUFFICIENT;
  uint8_t value_net = 0;
  memcpy(&value_net, buffer->buffer, sizeof(uint8_t));
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
  return src_data_buf_move_start(buffer, value_bytes, sizeof(uint8_t));
}

TPM_RC Serialize_int8_t(const int8_t* value, dst_data_buf_t* buffer) {
  int8_t value_net = *value;
  switch (sizeof(int8_t)) {
    case 2:
      value_net = htobe16(*value);
      break;
    case 4:
      value_net = htobe32(*value);
      break;
    case 8:
      value_net = htobe64(*value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  return dst_data_buf_append(buffer, value_bytes, sizeof(int8_t));
}

TPM_RC Parse_int8_t(src_data_buf_t* buffer,
                    int8_t* value,
                    dst_data_buf_t* value_bytes) {
  if (buffer->size < sizeof(int8_t))
    return TPM_RC_INSUFFICIENT;
  int8_t value_net = 0;
  memcpy(&value_net, buffer->buffer, sizeof(int8_t));
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
  return src_data_buf_move_start(buffer, value_bytes, sizeof(int8_t));
}

TPM_RC Serialize_int(const int* value, dst_data_buf_t* buffer) {
  int value_net = *value;
  switch (sizeof(int)) {
    case 2:
      value_net = htobe16(*value);
      break;
    case 4:
      value_net = htobe32(*value);
      break;
    case 8:
      value_net = htobe64(*value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  return dst_data_buf_append(buffer, value_bytes, sizeof(int));
}

TPM_RC Parse_int(src_data_buf_t* buffer, int* value, dst_data_buf_t* value_bytes) {
  if (buffer->size < sizeof(int))
    return TPM_RC_INSUFFICIENT;
  int value_net = 0;
  memcpy(&value_net, buffer->buffer, sizeof(int));
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
  return src_data_buf_move_start(buffer, value_bytes, sizeof(int));
}

TPM_RC Serialize_uint16_t(const uint16_t* value, dst_data_buf_t* buffer) {
  uint16_t value_net = *value;
  switch (sizeof(uint16_t)) {
    case 2:
      value_net = htobe16(*value);
      break;
    case 4:
      value_net = htobe32(*value);
      break;
    case 8:
      value_net = htobe64(*value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  return dst_data_buf_append(buffer, value_bytes, sizeof(uint16_t));
}

TPM_RC Parse_uint16_t(src_data_buf_t* buffer,
                      uint16_t* value,
                      dst_data_buf_t* value_bytes) {
  if (buffer->size < sizeof(uint16_t))
    return TPM_RC_INSUFFICIENT;
  uint16_t value_net = 0;
  memcpy(&value_net, buffer->buffer, sizeof(uint16_t));
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
  return src_data_buf_move_start(buffer, value_bytes, sizeof(uint16_t));
}

TPM_RC Serialize_int16_t(const int16_t* value, dst_data_buf_t* buffer) {
  int16_t value_net = *value;
  switch (sizeof(int16_t)) {
    case 2:
      value_net = htobe16(*value);
      break;
    case 4:
      value_net = htobe32(*value);
      break;
    case 8:
      value_net = htobe64(*value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  return dst_data_buf_append(buffer, value_bytes, sizeof(int16_t));
}

TPM_RC Parse_int16_t(src_data_buf_t* buffer,
                     int16_t* value,
                     dst_data_buf_t* value_bytes) {
  if (buffer->size < sizeof(int16_t))
    return TPM_RC_INSUFFICIENT;
  int16_t value_net = 0;
  memcpy(&value_net, buffer->buffer, sizeof(int16_t));
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
  return src_data_buf_move_start(buffer, value_bytes, sizeof(int16_t));
}

TPM_RC Serialize_uint32_t(const uint32_t* value, dst_data_buf_t* buffer) {
  uint32_t value_net = *value;
  switch (sizeof(uint32_t)) {
    case 2:
      value_net = htobe16(*value);
      break;
    case 4:
      value_net = htobe32(*value);
      break;
    case 8:
      value_net = htobe64(*value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  return dst_data_buf_append(buffer, value_bytes, sizeof(uint32_t));
}

TPM_RC Parse_uint32_t(src_data_buf_t* buffer,
                      uint32_t* value,
                      dst_data_buf_t* value_bytes) {
  if (buffer->size < sizeof(uint32_t))
    return TPM_RC_INSUFFICIENT;
  uint32_t value_net = 0;
  memcpy(&value_net, buffer->buffer, sizeof(uint32_t));
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
  return src_data_buf_move_start(buffer, value_bytes, sizeof(uint32_t));
}

TPM_RC Serialize_int32_t(const int32_t* value, dst_data_buf_t* buffer) {
  int32_t value_net = *value;
  switch (sizeof(int32_t)) {
    case 2:
      value_net = htobe16(*value);
      break;
    case 4:
      value_net = htobe32(*value);
      break;
    case 8:
      value_net = htobe64(*value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  return dst_data_buf_append(buffer, value_bytes, sizeof(int32_t));
}

TPM_RC Parse_int32_t(src_data_buf_t* buffer,
                     int32_t* value,
                     dst_data_buf_t* value_bytes) {
  if (buffer->size < sizeof(int32_t))
    return TPM_RC_INSUFFICIENT;
  int32_t value_net = 0;
  memcpy(&value_net, buffer->buffer, sizeof(int32_t));
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
  return src_data_buf_move_start(buffer, value_bytes, sizeof(int32_t));
}

TPM_RC Serialize_uint64_t(const uint64_t* value, dst_data_buf_t* buffer) {
  uint64_t value_net = *value;
  switch (sizeof(uint64_t)) {
    case 2:
      value_net = htobe16(*value);
      break;
    case 4:
      value_net = htobe32(*value);
      break;
    case 8:
      value_net = htobe64(*value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  return dst_data_buf_append(buffer, value_bytes, sizeof(uint64_t));
}

TPM_RC Parse_uint64_t(src_data_buf_t* buffer,
                      uint64_t* value,
                      dst_data_buf_t* value_bytes) {
  if (buffer->size < sizeof(uint64_t))
    return TPM_RC_INSUFFICIENT;
  uint64_t value_net = 0;
  memcpy(&value_net, buffer->buffer, sizeof(uint64_t));
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
  return src_data_buf_move_start(buffer, value_bytes, sizeof(uint64_t));
}

TPM_RC Serialize_int64_t(const int64_t* value, dst_data_buf_t* buffer) {
  int64_t value_net = *value;
  switch (sizeof(int64_t)) {
    case 2:
      value_net = htobe16(*value);
      break;
    case 4:
      value_net = htobe32(*value);
      break;
    case 8:
      value_net = htobe64(*value);
      break;
    default:
      break;
  }
  const char* value_bytes = reinterpret_cast<const char*>(&value_net);
  return dst_data_buf_append(buffer, value_bytes, sizeof(int64_t));
}

TPM_RC Parse_int64_t(src_data_buf_t* buffer,
                     int64_t* value,
                     dst_data_buf_t* value_bytes) {
  if (buffer->size < sizeof(int64_t))
    return TPM_RC_INSUFFICIENT;
  int64_t value_net = 0;
  memcpy(&value_net, buffer->buffer, sizeof(int64_t));
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
  return src_data_buf_move_start(buffer, value_bytes, sizeof(int64_t));
}

TPM_RC Serialize_UINT8(const UINT8* value, dst_data_buf_t* buffer) {
  return Serialize_uint8_t(value, buffer);
}

TPM_RC Parse_UINT8(src_data_buf_t* buffer,
                   UINT8* value,
                   dst_data_buf_t* value_bytes) {
  return Parse_uint8_t(buffer, value, value_bytes);
}

TPM_RC Serialize_BYTE(const BYTE* value, dst_data_buf_t* buffer) {
  return Serialize_uint8_t(value, buffer);
}

TPM_RC Parse_BYTE(src_data_buf_t* buffer, BYTE* value, dst_data_buf_t* value_bytes) {
  return Parse_uint8_t(buffer, value, value_bytes);
}

TPM_RC Serialize_INT8(const INT8* value, dst_data_buf_t* buffer) {
  return Serialize_int8_t(value, buffer);
}

TPM_RC Parse_INT8(src_data_buf_t* buffer, INT8* value, dst_data_buf_t* value_bytes) {
  return Parse_int8_t(buffer, value, value_bytes);
}

TPM_RC Serialize_BOOL(const BOOL* value, dst_data_buf_t* buffer) {
  return Serialize_int(value, buffer);
}

TPM_RC Parse_BOOL(src_data_buf_t* buffer, BOOL* value, dst_data_buf_t* value_bytes) {
  return Parse_int(buffer, value, value_bytes);
}

TPM_RC Serialize_UINT16(const UINT16* value, dst_data_buf_t* buffer) {
  return Serialize_uint16_t(value, buffer);
}

TPM_RC Parse_UINT16(src_data_buf_t* buffer,
                    UINT16* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_uint16_t(buffer, value, value_bytes);
}

TPM_RC Serialize_INT16(const INT16* value, dst_data_buf_t* buffer) {
  return Serialize_int16_t(value, buffer);
}

TPM_RC Parse_INT16(src_data_buf_t* buffer,
                   INT16* value,
                   dst_data_buf_t* value_bytes) {
  return Parse_int16_t(buffer, value, value_bytes);
}

TPM_RC Serialize_UINT32(const UINT32* value, dst_data_buf_t* buffer) {
  return Serialize_uint32_t(value, buffer);
}

TPM_RC Parse_UINT32(src_data_buf_t* buffer,
                    UINT32* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_uint32_t(buffer, value, value_bytes);
}

TPM_RC Serialize_INT32(const INT32* value, dst_data_buf_t* buffer) {
  return Serialize_int32_t(value, buffer);
}

TPM_RC Parse_INT32(src_data_buf_t* buffer,
                   INT32* value,
                   dst_data_buf_t* value_bytes) {
  return Parse_int32_t(buffer, value, value_bytes);
}

TPM_RC Serialize_UINT64(const UINT64* value, dst_data_buf_t* buffer) {
  return Serialize_uint64_t(value, buffer);
}

TPM_RC Parse_UINT64(src_data_buf_t* buffer,
                    UINT64* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_uint64_t(buffer, value, value_bytes);
}

TPM_RC Serialize_INT64(const INT64* value, dst_data_buf_t* buffer) {
  return Serialize_int64_t(value, buffer);
}

TPM_RC Parse_INT64(src_data_buf_t* buffer,
                   INT64* value,
                   dst_data_buf_t* value_bytes) {
  return Parse_int64_t(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_ALGORITHM_ID(const TPM_ALGORITHM_ID* value,
                                  dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_ALGORITHM_ID(src_data_buf_t* buffer,
                              TPM_ALGORITHM_ID* value,
                              dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_MODIFIER_INDICATOR(const TPM_MODIFIER_INDICATOR* value,
                                        dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_MODIFIER_INDICATOR(src_data_buf_t* buffer,
                                    TPM_MODIFIER_INDICATOR* value,
                                    dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_AUTHORIZATION_SIZE(const TPM_AUTHORIZATION_SIZE* value,
                                        dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_AUTHORIZATION_SIZE(src_data_buf_t* buffer,
                                    TPM_AUTHORIZATION_SIZE* value,
                                    dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_PARAMETER_SIZE(const TPM_PARAMETER_SIZE* value,
                                    dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_PARAMETER_SIZE(src_data_buf_t* buffer,
                                TPM_PARAMETER_SIZE* value,
                                dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_KEY_SIZE(const TPM_KEY_SIZE* value, dst_data_buf_t* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_KEY_SIZE(src_data_buf_t* buffer,
                          TPM_KEY_SIZE* value,
                          dst_data_buf_t* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_KEY_BITS(const TPM_KEY_BITS* value, dst_data_buf_t* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_KEY_BITS(src_data_buf_t* buffer,
                          TPM_KEY_BITS* value,
                          dst_data_buf_t* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_HANDLE(const TPM_HANDLE* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_HANDLE(src_data_buf_t* buffer,
                        TPM_HANDLE* value,
                        dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM2B_DIGEST(const TPM2B_DIGEST* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_DIGEST(src_data_buf_t* buffer,
                          TPM2B_DIGEST* value,
                          dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_NONCE(const TPM2B_NONCE* value, dst_data_buf_t* buffer) {
  return Serialize_TPM2B_DIGEST(value, buffer);
}

TPM_RC Parse_TPM2B_NONCE(src_data_buf_t* buffer,
                         TPM2B_NONCE* value,
                         dst_data_buf_t* value_bytes) {
  return Parse_TPM2B_DIGEST(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM2B_AUTH(const TPM2B_AUTH* value, dst_data_buf_t* buffer) {
  return Serialize_TPM2B_DIGEST(value, buffer);
}

TPM_RC Parse_TPM2B_AUTH(src_data_buf_t* buffer,
                        TPM2B_AUTH* value,
                        dst_data_buf_t* value_bytes) {
  return Parse_TPM2B_DIGEST(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM2B_OPERAND(const TPM2B_OPERAND* value,
                               dst_data_buf_t* buffer) {
  return Serialize_TPM2B_DIGEST(value, buffer);
}

TPM_RC Parse_TPM2B_OPERAND(src_data_buf_t* buffer,
                           TPM2B_OPERAND* value,
                           dst_data_buf_t* value_bytes) {
  return Parse_TPM2B_DIGEST(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_ALG_ID(const TPM_ALG_ID* value, dst_data_buf_t* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_ALG_ID(src_data_buf_t* buffer,
                        TPM_ALG_ID* value,
                        dst_data_buf_t* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_HASH(const TPMI_ALG_HASH* value,
                               dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_HASH(src_data_buf_t* buffer,
                           TPMI_ALG_HASH* value,
                           dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_SIGHASH(const TPMS_SCHEME_SIGHASH* value,
                                     dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_SIGHASH(src_data_buf_t* buffer,
                                 TPMS_SCHEME_SIGHASH* value,
                                 dst_data_buf_t* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_HMAC(const TPMS_SCHEME_HMAC* value,
                                  dst_data_buf_t* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_HMAC(src_data_buf_t* buffer,
                              TPMS_SCHEME_HMAC* value,
                              dst_data_buf_t* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_RSASSA(const TPMS_SCHEME_RSASSA* value,
                                    dst_data_buf_t* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_RSASSA(src_data_buf_t* buffer,
                                TPMS_SCHEME_RSASSA* value,
                                dst_data_buf_t* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_RSAPSS(const TPMS_SCHEME_RSAPSS* value,
                                    dst_data_buf_t* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_RSAPSS(src_data_buf_t* buffer,
                                TPMS_SCHEME_RSAPSS* value,
                                dst_data_buf_t* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_ECDSA(const TPMS_SCHEME_ECDSA* value,
                                   dst_data_buf_t* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_ECDSA(src_data_buf_t* buffer,
                               TPMS_SCHEME_ECDSA* value,
                               dst_data_buf_t* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_SM2(const TPMS_SCHEME_SM2* value,
                                 dst_data_buf_t* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_SM2(src_data_buf_t* buffer,
                             TPMS_SCHEME_SM2* value,
                             dst_data_buf_t* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_SCHEME_ECSCHNORR(const TPMS_SCHEME_ECSCHNORR* value,
                                       dst_data_buf_t* buffer) {
  return Serialize_TPMS_SCHEME_SIGHASH(value, buffer);
}

TPM_RC Parse_TPMS_SCHEME_ECSCHNORR(src_data_buf_t* buffer,
                                   TPMS_SCHEME_ECSCHNORR* value,
                                   dst_data_buf_t* value_bytes) {
  return Parse_TPMS_SCHEME_SIGHASH(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_YES_NO(const TPMI_YES_NO* value, dst_data_buf_t* buffer) {
  return Serialize_BYTE(value, buffer);
}

TPM_RC Parse_TPMI_YES_NO(src_data_buf_t* buffer,
                         TPMI_YES_NO* value,
                         dst_data_buf_t* value_bytes) {
  return Parse_BYTE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_DH_OBJECT(const TPMI_DH_OBJECT* value,
                                dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_DH_OBJECT(src_data_buf_t* buffer,
                            TPMI_DH_OBJECT* value,
                            dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_DH_PERSISTENT(const TPMI_DH_PERSISTENT* value,
                                    dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_DH_PERSISTENT(src_data_buf_t* buffer,
                                TPMI_DH_PERSISTENT* value,
                                dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_DH_ENTITY(const TPMI_DH_ENTITY* value,
                                dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_DH_ENTITY(src_data_buf_t* buffer,
                            TPMI_DH_ENTITY* value,
                            dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_DH_PCR(const TPMI_DH_PCR* value, dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_DH_PCR(src_data_buf_t* buffer,
                         TPMI_DH_PCR* value,
                         dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_SH_AUTH_SESSION(const TPMI_SH_AUTH_SESSION* value,
                                      dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_SH_AUTH_SESSION(src_data_buf_t* buffer,
                                  TPMI_SH_AUTH_SESSION* value,
                                  dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_SH_HMAC(const TPMI_SH_HMAC* value, dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_SH_HMAC(src_data_buf_t* buffer,
                          TPMI_SH_HMAC* value,
                          dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_SH_POLICY(const TPMI_SH_POLICY* value,
                                dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_SH_POLICY(src_data_buf_t* buffer,
                            TPMI_SH_POLICY* value,
                            dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_DH_CONTEXT(const TPMI_DH_CONTEXT* value,
                                 dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_DH_CONTEXT(src_data_buf_t* buffer,
                             TPMI_DH_CONTEXT* value,
                             dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_HIERARCHY(const TPMI_RH_HIERARCHY* value,
                                   dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_HIERARCHY(src_data_buf_t* buffer,
                               TPMI_RH_HIERARCHY* value,
                               dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_ENABLES(const TPMI_RH_ENABLES* value,
                                 dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_ENABLES(src_data_buf_t* buffer,
                             TPMI_RH_ENABLES* value,
                             dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_HIERARCHY_AUTH(const TPMI_RH_HIERARCHY_AUTH* value,
                                        dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_HIERARCHY_AUTH(src_data_buf_t* buffer,
                                    TPMI_RH_HIERARCHY_AUTH* value,
                                    dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_PLATFORM(const TPMI_RH_PLATFORM* value,
                                  dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_PLATFORM(src_data_buf_t* buffer,
                              TPMI_RH_PLATFORM* value,
                              dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_OWNER(const TPMI_RH_OWNER* value,
                               dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_OWNER(src_data_buf_t* buffer,
                           TPMI_RH_OWNER* value,
                           dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_ENDORSEMENT(const TPMI_RH_ENDORSEMENT* value,
                                     dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_ENDORSEMENT(src_data_buf_t* buffer,
                                 TPMI_RH_ENDORSEMENT* value,
                                 dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_PROVISION(const TPMI_RH_PROVISION* value,
                                   dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_PROVISION(src_data_buf_t* buffer,
                               TPMI_RH_PROVISION* value,
                               dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_CLEAR(const TPMI_RH_CLEAR* value,
                               dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_CLEAR(src_data_buf_t* buffer,
                           TPMI_RH_CLEAR* value,
                           dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_NV_AUTH(const TPMI_RH_NV_AUTH* value,
                                 dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_NV_AUTH(src_data_buf_t* buffer,
                             TPMI_RH_NV_AUTH* value,
                             dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_LOCKOUT(const TPMI_RH_LOCKOUT* value,
                                 dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_LOCKOUT(src_data_buf_t* buffer,
                             TPMI_RH_LOCKOUT* value,
                             dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RH_NV_INDEX(const TPMI_RH_NV_INDEX* value,
                                  dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPMI_RH_NV_INDEX(src_data_buf_t* buffer,
                              TPMI_RH_NV_INDEX* value,
                              dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_ASYM(const TPMI_ALG_ASYM* value,
                               dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_ASYM(src_data_buf_t* buffer,
                           TPMI_ALG_ASYM* value,
                           dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_SYM(const TPMI_ALG_SYM* value, dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_SYM(src_data_buf_t* buffer,
                          TPMI_ALG_SYM* value,
                          dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_SYM_OBJECT(const TPMI_ALG_SYM_OBJECT* value,
                                     dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_SYM_OBJECT(src_data_buf_t* buffer,
                                 TPMI_ALG_SYM_OBJECT* value,
                                 dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_SYM_MODE(const TPMI_ALG_SYM_MODE* value,
                                   dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_SYM_MODE(src_data_buf_t* buffer,
                               TPMI_ALG_SYM_MODE* value,
                               dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_KDF(const TPMI_ALG_KDF* value, dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_KDF(src_data_buf_t* buffer,
                          TPMI_ALG_KDF* value,
                          dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_SIG_SCHEME(const TPMI_ALG_SIG_SCHEME* value,
                                     dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_SIG_SCHEME(src_data_buf_t* buffer,
                                 TPMI_ALG_SIG_SCHEME* value,
                                 dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ECC_KEY_EXCHANGE(const TPMI_ECC_KEY_EXCHANGE* value,
                                       dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ECC_KEY_EXCHANGE(src_data_buf_t* buffer,
                                   TPMI_ECC_KEY_EXCHANGE* value,
                                   dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_ST(const TPM_ST* value, dst_data_buf_t* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_ST(src_data_buf_t* buffer,
                    TPM_ST* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ST_COMMAND_TAG(const TPMI_ST_COMMAND_TAG* value,
                                     dst_data_buf_t* buffer) {
  return Serialize_TPM_ST(value, buffer);
}

TPM_RC Parse_TPMI_ST_COMMAND_TAG(src_data_buf_t* buffer,
                                 TPMI_ST_COMMAND_TAG* value,
                                 dst_data_buf_t* value_bytes) {
  return Parse_TPM_ST(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ST_ATTEST(const TPMI_ST_ATTEST* value,
                                dst_data_buf_t* buffer) {
  return Serialize_TPM_ST(value, buffer);
}

TPM_RC Parse_TPMI_ST_ATTEST(src_data_buf_t* buffer,
                            TPMI_ST_ATTEST* value,
                            dst_data_buf_t* value_bytes) {
  return Parse_TPM_ST(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_AES_KEY_BITS(const TPMI_AES_KEY_BITS* value,
                                   dst_data_buf_t* buffer) {
  return Serialize_TPM_KEY_BITS(value, buffer);
}

TPM_RC Parse_TPMI_AES_KEY_BITS(src_data_buf_t* buffer,
                               TPMI_AES_KEY_BITS* value,
                               dst_data_buf_t* value_bytes) {
  return Parse_TPM_KEY_BITS(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_SM4_KEY_BITS(const TPMI_SM4_KEY_BITS* value,
                                   dst_data_buf_t* buffer) {
  return Serialize_TPM_KEY_BITS(value, buffer);
}

TPM_RC Parse_TPMI_SM4_KEY_BITS(src_data_buf_t* buffer,
                               TPMI_SM4_KEY_BITS* value,
                               dst_data_buf_t* value_bytes) {
  return Parse_TPM_KEY_BITS(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_KEYEDHASH_SCHEME(
    const TPMI_ALG_KEYEDHASH_SCHEME* value, dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_KEYEDHASH_SCHEME(src_data_buf_t* buffer,
                                       TPMI_ALG_KEYEDHASH_SCHEME* value,
                                       dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_ASYM_SCHEME(const TPMI_ALG_ASYM_SCHEME* value,
                                      dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_ASYM_SCHEME(src_data_buf_t* buffer,
                                  TPMI_ALG_ASYM_SCHEME* value,
                                  dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_RSA_SCHEME(const TPMI_ALG_RSA_SCHEME* value,
                                     dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_RSA_SCHEME(src_data_buf_t* buffer,
                                 TPMI_ALG_RSA_SCHEME* value,
                                 dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_RSA_DECRYPT(const TPMI_ALG_RSA_DECRYPT* value,
                                      dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_RSA_DECRYPT(src_data_buf_t* buffer,
                                  TPMI_ALG_RSA_DECRYPT* value,
                                  dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_RSA_KEY_BITS(const TPMI_RSA_KEY_BITS* value,
                                   dst_data_buf_t* buffer) {
  return Serialize_TPM_KEY_BITS(value, buffer);
}

TPM_RC Parse_TPMI_RSA_KEY_BITS(src_data_buf_t* buffer,
                               TPMI_RSA_KEY_BITS* value,
                               dst_data_buf_t* value_bytes) {
  return Parse_TPM_KEY_BITS(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_ECC_SCHEME(const TPMI_ALG_ECC_SCHEME* value,
                                     dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_ECC_SCHEME(src_data_buf_t* buffer,
                                 TPMI_ALG_ECC_SCHEME* value,
                                 dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_ECC_CURVE(const TPM_ECC_CURVE* value,
                               dst_data_buf_t* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_ECC_CURVE(src_data_buf_t* buffer,
                           TPM_ECC_CURVE* value,
                           dst_data_buf_t* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ECC_CURVE(const TPMI_ECC_CURVE* value,
                                dst_data_buf_t* buffer) {
  return Serialize_TPM_ECC_CURVE(value, buffer);
}

TPM_RC Parse_TPMI_ECC_CURVE(src_data_buf_t* buffer,
                            TPMI_ECC_CURVE* value,
                            dst_data_buf_t* value_bytes) {
  return Parse_TPM_ECC_CURVE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMI_ALG_PUBLIC(const TPMI_ALG_PUBLIC* value,
                                 dst_data_buf_t* buffer) {
  return Serialize_TPM_ALG_ID(value, buffer);
}

TPM_RC Parse_TPMI_ALG_PUBLIC(src_data_buf_t* buffer,
                             TPMI_ALG_PUBLIC* value,
                             dst_data_buf_t* value_bytes) {
  return Parse_TPM_ALG_ID(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_ALGORITHM(const TPMA_ALGORITHM* value,
                                dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_ALGORITHM(src_data_buf_t* buffer,
                            TPMA_ALGORITHM* value,
                            dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_OBJECT(const TPMA_OBJECT* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_OBJECT(src_data_buf_t* buffer,
                         TPMA_OBJECT* value,
                         dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_SESSION(const TPMA_SESSION* value, dst_data_buf_t* buffer) {
  return Serialize_UINT8(value, buffer);
}

TPM_RC Parse_TPMA_SESSION(src_data_buf_t* buffer,
                          TPMA_SESSION* value,
                          dst_data_buf_t* value_bytes) {
  return Parse_UINT8(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_LOCALITY(const TPMA_LOCALITY* value,
                               dst_data_buf_t* buffer) {
  return Serialize_UINT8(value, buffer);
}

TPM_RC Parse_TPMA_LOCALITY(src_data_buf_t* buffer,
                           TPMA_LOCALITY* value,
                           dst_data_buf_t* value_bytes) {
  return Parse_UINT8(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_PERMANENT(const TPMA_PERMANENT* value,
                                dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_PERMANENT(src_data_buf_t* buffer,
                            TPMA_PERMANENT* value,
                            dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_STARTUP_CLEAR(const TPMA_STARTUP_CLEAR* value,
                                    dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_STARTUP_CLEAR(src_data_buf_t* buffer,
                                TPMA_STARTUP_CLEAR* value,
                                dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_MEMORY(const TPMA_MEMORY* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_MEMORY(src_data_buf_t* buffer,
                         TPMA_MEMORY* value,
                         dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_CC(const TPM_CC* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_CC(src_data_buf_t* buffer,
                    TPM_CC* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_CC(const TPMA_CC* value, dst_data_buf_t* buffer) {
  return Serialize_TPM_CC(value, buffer);
}

TPM_RC Parse_TPMA_CC(src_data_buf_t* buffer,
                     TPMA_CC* value,
                     dst_data_buf_t* value_bytes) {
  return Parse_TPM_CC(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_NV_INDEX(const TPM_NV_INDEX* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_NV_INDEX(src_data_buf_t* buffer,
                          TPM_NV_INDEX* value,
                          dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMA_NV(const TPMA_NV* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPMA_NV(src_data_buf_t* buffer,
                     TPMA_NV* value,
                     dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_SPEC(const TPM_SPEC* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_SPEC(src_data_buf_t* buffer,
                      TPM_SPEC* value,
                      dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_GENERATED(const TPM_GENERATED* value,
                               dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_GENERATED(src_data_buf_t* buffer,
                           TPM_GENERATED* value,
                           dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_RC(const TPM_RC* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_RC(src_data_buf_t* buffer,
                    TPM_RC* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_CLOCK_ADJUST(const TPM_CLOCK_ADJUST* value,
                                  dst_data_buf_t* buffer) {
  return Serialize_INT8(value, buffer);
}

TPM_RC Parse_TPM_CLOCK_ADJUST(src_data_buf_t* buffer,
                              TPM_CLOCK_ADJUST* value,
                              dst_data_buf_t* value_bytes) {
  return Parse_INT8(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_EO(const TPM_EO* value, dst_data_buf_t* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_EO(src_data_buf_t* buffer,
                    TPM_EO* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_SU(const TPM_SU* value, dst_data_buf_t* buffer) {
  return Serialize_UINT16(value, buffer);
}

TPM_RC Parse_TPM_SU(src_data_buf_t* buffer,
                    TPM_SU* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_UINT16(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_SE(const TPM_SE* value, dst_data_buf_t* buffer) {
  return Serialize_UINT8(value, buffer);
}

TPM_RC Parse_TPM_SE(src_data_buf_t* buffer,
                    TPM_SE* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_UINT8(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_CAP(const TPM_CAP* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_CAP(src_data_buf_t* buffer,
                     TPM_CAP* value,
                     dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_PT(const TPM_PT* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_PT(src_data_buf_t* buffer,
                    TPM_PT* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_PT_PCR(const TPM_PT_PCR* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_PT_PCR(src_data_buf_t* buffer,
                        TPM_PT_PCR* value,
                        dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_PS(const TPM_PS* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_PS(src_data_buf_t* buffer,
                    TPM_PS* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_HT(const TPM_HT* value, dst_data_buf_t* buffer) {
  return Serialize_UINT8(value, buffer);
}

TPM_RC Parse_TPM_HT(src_data_buf_t* buffer,
                    TPM_HT* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_UINT8(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_RH(const TPM_RH* value, dst_data_buf_t* buffer) {
  return Serialize_UINT32(value, buffer);
}

TPM_RC Parse_TPM_RH(src_data_buf_t* buffer,
                    TPM_RH* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_UINT32(buffer, value, value_bytes);
}

TPM_RC Serialize_TPM_HC(const TPM_HC* value, dst_data_buf_t* buffer) {
  return Serialize_TPM_HANDLE(value, buffer);
}

TPM_RC Parse_TPM_HC(src_data_buf_t* buffer,
                    TPM_HC* value,
                    dst_data_buf_t* value_bytes) {
  return Parse_TPM_HANDLE(buffer, value, value_bytes);
}

TPM_RC Serialize_TPMS_ALGORITHM_DESCRIPTION(
  const TPMS_ALGORITHM_DESCRIPTION* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ALG_ID(&value->alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_ALGORITHM(&value->attributes, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ALGORITHM_DESCRIPTION(src_data_buf_t* buffer,
                                        TPMS_ALGORITHM_DESCRIPTION* value,
                                        dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_HA(const TPMU_HA* value,
                         TPMI_ALG_HASH selector,
                         dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_SHA384) {
    if (sizeof(&value->sha384) < SHA384_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA384_DIGEST_SIZE; ++i) {
      result = Serialize_BYTE(&value->sha384[i], buffer);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_SHA1) {
    if (sizeof(&value->sha1) < SHA1_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA1_DIGEST_SIZE; ++i) {
      result = Serialize_BYTE(&value->sha1[i], buffer);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_SM3_256) {
    if (sizeof(&value->sm3_256) < SM3_256_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SM3_256_DIGEST_SIZE; ++i) {
      result = Serialize_BYTE(&value->sm3_256[i], buffer);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_SHA256) {
    if (sizeof(&value->sha256) < SHA256_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA256_DIGEST_SIZE; ++i) {
      result = Serialize_BYTE(&value->sha256[i], buffer);
      if (result) {
        return result;
      }
    }
  }

  if (selector == TPM_ALG_SHA512) {
    if (sizeof(&value->sha512) < SHA512_DIGEST_SIZE) {
      return TPM_RC_INSUFFICIENT;
    }
    for (uint32_t i = 0; i < SHA512_DIGEST_SIZE; ++i) {
      result = Serialize_BYTE(&value->sha512[i], buffer);
      if (result) {
        return result;
      }
    }
  }
  return result;
}

TPM_RC Parse_TPMU_HA(src_data_buf_t* buffer,
                     TPMI_ALG_HASH selector,
                     TPMU_HA* value,
                     dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_HA(const TPMT_HA* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_HA(&value->digest, value->hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_HA(src_data_buf_t* buffer,
                     TPMT_HA* value,
                     dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_DATA(const TPM2B_DATA* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_DATA(src_data_buf_t* buffer,
                        TPM2B_DATA* value,
                        dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_EVENT(const TPM2B_EVENT* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_EVENT(src_data_buf_t* buffer,
                         TPM2B_EVENT* value,
                         dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_MAX_BUFFER(const TPM2B_MAX_BUFFER* value,
                                  dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_MAX_BUFFER(src_data_buf_t* buffer,
                              TPM2B_MAX_BUFFER* value,
                              dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_MAX_NV_BUFFER(const TPM2B_MAX_NV_BUFFER* value,
                                     dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_MAX_NV_BUFFER(src_data_buf_t* buffer,
                                 TPM2B_MAX_NV_BUFFER* value,
                                 dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_TIMEOUT(const TPM2B_TIMEOUT* value,
                               dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_TIMEOUT(src_data_buf_t* buffer,
                           TPM2B_TIMEOUT* value,
                           dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_IV(const TPM2B_IV* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_IV(src_data_buf_t* buffer,
                      TPM2B_IV* value,
                      dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_NAME(const TPM2B_NAME* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->name) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->name[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_NAME(src_data_buf_t* buffer,
                        TPM2B_NAME* value,
                        dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_PCR_SELECT(const TPMS_PCR_SELECT* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT8(&value->sizeof_select, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->pcr_select) < value->sizeof_select) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->sizeof_select; ++i) {
    result = Serialize_BYTE(&value->pcr_select[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMS_PCR_SELECT(src_data_buf_t* buffer,
                             TPMS_PCR_SELECT* value,
                             dst_data_buf_t* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_UINT8(buffer, &value->sizeof_select, value_bytes);
  if (result) {
    return result;
  }

  if (sizeof(value->pcr_select) < value->sizeof_select) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint8_t i = 0; i < value->sizeof_select; ++i) {
    result = Parse_BYTE(buffer, &value->pcr_select[i], value_bytes);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Serialize_TPMS_PCR_SELECTION(const TPMS_PCR_SELECTION* value,
                                    dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT8(&value->sizeof_select, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->pcr_select) < value->sizeof_select) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->sizeof_select; ++i) {
    result = Serialize_BYTE(&value->pcr_select[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMS_PCR_SELECTION(src_data_buf_t* buffer,
                                TPMS_PCR_SELECTION* value,
                                dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_TK_CREATION(const TPMT_TK_CREATION* value,
                                  dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ST(&value->tag, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RH_HIERARCHY(&value->hierarchy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_TK_CREATION(src_data_buf_t* buffer,
                              TPMT_TK_CREATION* value,
                              dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_TK_VERIFIED(const TPMT_TK_VERIFIED* value,
                                  dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ST(&value->tag, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RH_HIERARCHY(&value->hierarchy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_TK_VERIFIED(src_data_buf_t* buffer,
                              TPMT_TK_VERIFIED* value,
                              dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_TK_AUTH(const TPMT_TK_AUTH* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ST(&value->tag, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RH_HIERARCHY(&value->hierarchy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_TK_AUTH(src_data_buf_t* buffer,
                          TPMT_TK_AUTH* value,
                          dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_TK_HASHCHECK(const TPMT_TK_HASHCHECK* value,
                                   dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ST(&value->tag, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RH_HIERARCHY(&value->hierarchy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_TK_HASHCHECK(src_data_buf_t* buffer,
                               TPMT_TK_HASHCHECK* value,
                               dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_ALG_PROPERTY(const TPMS_ALG_PROPERTY* value,
                                   dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ALG_ID(&value->alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_ALGORITHM(&value->alg_properties, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ALG_PROPERTY(src_data_buf_t* buffer,
                               TPMS_ALG_PROPERTY* value,
                               dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_TAGGED_PROPERTY(const TPMS_TAGGED_PROPERTY* value,
                                      dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_PT(&value->property, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT32(&value->value, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_TAGGED_PROPERTY(src_data_buf_t* buffer,
                                  TPMS_TAGGED_PROPERTY* value,
                                  dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_TAGGED_PCR_SELECT(const TPMS_TAGGED_PCR_SELECT* value,
                                        dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_PT(&value->tag, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT8(&value->sizeof_select, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->pcr_select) < value->sizeof_select) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->sizeof_select; ++i) {
    result = Serialize_BYTE(&value->pcr_select[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMS_TAGGED_PCR_SELECT(src_data_buf_t* buffer,
                                    TPMS_TAGGED_PCR_SELECT* value,
                                    dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPML_CC(const TPML_CC* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(&value->count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->command_codes) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Serialize_TPM_CC(&value->command_codes[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_CC(src_data_buf_t* buffer,
                     TPML_CC* value,
                     dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPML_CCA(const TPML_CCA* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(&value->count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->command_attributes) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Serialize_TPMA_CC(&value->command_attributes[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_CCA(src_data_buf_t* buffer,
                      TPML_CCA* value,
                      dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPML_ALG(const TPML_ALG* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(&value->count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->algorithms) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Serialize_TPM_ALG_ID(&value->algorithms[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_ALG(src_data_buf_t* buffer,
                      TPML_ALG* value,
                      dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPML_HANDLE(const TPML_HANDLE* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(&value->count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->handle) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Serialize_TPM_HANDLE(&value->handle[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_HANDLE(src_data_buf_t* buffer,
                         TPML_HANDLE* value,
                         dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPML_DIGEST(const TPML_DIGEST* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(&value->count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->digests) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Serialize_TPM2B_DIGEST(&value->digests[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_DIGEST(src_data_buf_t* buffer,
                         TPML_DIGEST* value,
                         dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPML_DIGEST_VALUES(const TPML_DIGEST_VALUES* value,
                                    dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(&value->count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->digests) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Serialize_TPMT_HA(&value->digests[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_DIGEST_VALUES(src_data_buf_t* buffer,
                                TPML_DIGEST_VALUES* value,
                                dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_DIGEST_VALUES(const TPM2B_DIGEST_VALUES* value,
                                     dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_DIGEST_VALUES(src_data_buf_t* buffer,
                                 TPM2B_DIGEST_VALUES* value,
                                 dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPML_PCR_SELECTION(const TPML_PCR_SELECTION* value,
                                    dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(&value->count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->pcr_selections) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Serialize_TPMS_PCR_SELECTION(&value->pcr_selections[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_PCR_SELECTION(src_data_buf_t* buffer,
                                TPML_PCR_SELECTION* value,
                                dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPML_ALG_PROPERTY(const TPML_ALG_PROPERTY* value,
                                   dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(&value->count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->alg_properties) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Serialize_TPMS_ALG_PROPERTY(&value->alg_properties[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_ALG_PROPERTY(src_data_buf_t* buffer,
                               TPML_ALG_PROPERTY* value,
                               dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPML_TAGGED_TPM_PROPERTY(const TPML_TAGGED_TPM_PROPERTY* value,
                                          dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(&value->count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->tpm_property) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Serialize_TPMS_TAGGED_PROPERTY(&value->tpm_property[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_TAGGED_TPM_PROPERTY(src_data_buf_t* buffer,
                                      TPML_TAGGED_TPM_PROPERTY* value,
                                      dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPML_TAGGED_PCR_PROPERTY(const TPML_TAGGED_PCR_PROPERTY* value,
                                          dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(&value->count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->pcr_property) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Serialize_TPMS_TAGGED_PCR_SELECT(&value->pcr_property[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_TAGGED_PCR_PROPERTY(src_data_buf_t* buffer,
                                      TPML_TAGGED_PCR_PROPERTY* value,
                                      dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPML_ECC_CURVE(const TPML_ECC_CURVE* value,
                                dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT32(&value->count, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->ecc_curves) < value->count) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->count; ++i) {
    result = Serialize_TPM_ECC_CURVE(&value->ecc_curves[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPML_ECC_CURVE(src_data_buf_t* buffer,
                            TPML_ECC_CURVE* value,
                            dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_CAPABILITIES(const TPMU_CAPABILITIES* value,
                                   TPM_CAP selector,
                                   dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_CAP_PCRS) {
    result = Serialize_TPML_PCR_SELECTION(&value->assigned_pcr, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_TPM_PROPERTIES) {
    result = Serialize_TPML_TAGGED_TPM_PROPERTY(&value->tpm_properties, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_PP_COMMANDS) {
    result = Serialize_TPML_CC(&value->pp_commands, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_AUDIT_COMMANDS) {
    result = Serialize_TPML_CC(&value->audit_commands, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_COMMANDS) {
    result = Serialize_TPML_CCA(&value->command, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_ECC_CURVES) {
    result = Serialize_TPML_ECC_CURVE(&value->ecc_curves, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_PCR_PROPERTIES) {
    result = Serialize_TPML_TAGGED_PCR_PROPERTY(&value->pcr_properties, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_HANDLES) {
    result = Serialize_TPML_HANDLE(&value->handles, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_CAP_ALGS) {
    result = Serialize_TPML_ALG_PROPERTY(&value->algorithms, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_CAPABILITIES(src_data_buf_t* buffer,
                               TPM_CAP selector,
                               TPMU_CAPABILITIES* value,
                               dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_CAPABILITY_DATA(const TPMS_CAPABILITY_DATA* value,
                                      dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_CAP(&value->capability, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_CAPABILITIES(&value->data, value->capability, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CAPABILITY_DATA(src_data_buf_t* buffer,
                                  TPMS_CAPABILITY_DATA* value,
                                  dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_CLOCK_INFO(const TPMS_CLOCK_INFO* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT64(&value->clock, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT32(&value->reset_count, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT32(&value->restart_count, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_YES_NO(&value->safe, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CLOCK_INFO(src_data_buf_t* buffer,
                             TPMS_CLOCK_INFO* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_TIME_INFO(const TPMS_TIME_INFO* value,
                                dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT64(&value->time, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMS_CLOCK_INFO(&value->clock_info, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_TIME_INFO(src_data_buf_t* buffer,
                            TPMS_TIME_INFO* value,
                            dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_TIME_ATTEST_INFO(const TPMS_TIME_ATTEST_INFO* value,
                                       dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMS_TIME_INFO(&value->time, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT64(&value->firmware_version, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_TIME_ATTEST_INFO(src_data_buf_t* buffer,
                                   TPMS_TIME_ATTEST_INFO* value,
                                   dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_CERTIFY_INFO(const TPMS_CERTIFY_INFO* value,
                                   dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_NAME(&value->name, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_NAME(&value->qualified_name, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CERTIFY_INFO(src_data_buf_t* buffer,
                               TPMS_CERTIFY_INFO* value,
                               dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_QUOTE_INFO(const TPMS_QUOTE_INFO* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPML_PCR_SELECTION(&value->pcr_select, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->pcr_digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_QUOTE_INFO(src_data_buf_t* buffer,
                             TPMS_QUOTE_INFO* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_COMMAND_AUDIT_INFO(const TPMS_COMMAND_AUDIT_INFO* value,
                                         dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT64(&value->audit_counter, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM_ALG_ID(&value->digest_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->audit_digest, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->command_digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_COMMAND_AUDIT_INFO(src_data_buf_t* buffer,
                                     TPMS_COMMAND_AUDIT_INFO* value,
                                     dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_SESSION_AUDIT_INFO(const TPMS_SESSION_AUDIT_INFO* value,
                                         dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_YES_NO(&value->exclusive_session, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->session_digest, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SESSION_AUDIT_INFO(src_data_buf_t* buffer,
                                     TPMS_SESSION_AUDIT_INFO* value,
                                     dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_CREATION_INFO(const TPMS_CREATION_INFO* value,
                                    dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_NAME(&value->object_name, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->creation_hash, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CREATION_INFO(src_data_buf_t* buffer,
                                TPMS_CREATION_INFO* value,
                                dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_NV_CERTIFY_INFO(const TPMS_NV_CERTIFY_INFO* value,
                                      dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_NAME(&value->index_name, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT16(&value->offset, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_MAX_NV_BUFFER(&value->nv_contents, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_NV_CERTIFY_INFO(src_data_buf_t* buffer,
                                  TPMS_NV_CERTIFY_INFO* value,
                                  dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_ATTEST(const TPMU_ATTEST* value,
                             TPMI_ST_ATTEST selector,
                             dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ST_ATTEST_SESSION_AUDIT) {
    result = Serialize_TPMS_SESSION_AUDIT_INFO(&value->session_audit, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_QUOTE) {
    result = Serialize_TPMS_QUOTE_INFO(&value->quote, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_COMMAND_AUDIT) {
    result = Serialize_TPMS_COMMAND_AUDIT_INFO(&value->command_audit, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_CERTIFY) {
    result = Serialize_TPMS_CERTIFY_INFO(&value->certify, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_NV) {
    result = Serialize_TPMS_NV_CERTIFY_INFO(&value->nv, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_TIME) {
    result = Serialize_TPMS_TIME_ATTEST_INFO(&value->time, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ST_ATTEST_CREATION) {
    result = Serialize_TPMS_CREATION_INFO(&value->creation, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_ATTEST(src_data_buf_t* buffer,
                         TPMI_ST_ATTEST selector,
                         TPMU_ATTEST* value,
                         dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_ATTEST(const TPMS_ATTEST* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_GENERATED(&value->magic, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_ST_ATTEST(&value->type, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_NAME(&value->qualified_signer, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DATA(&value->extra_data, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMS_CLOCK_INFO(&value->clock_info, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT64(&value->firmware_version, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_ATTEST(&value->attested, value->type, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ATTEST(src_data_buf_t* buffer,
                         TPMS_ATTEST* value,
                         dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_ATTEST(const TPM2B_ATTEST* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->attestation_data) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->attestation_data[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_ATTEST(src_data_buf_t* buffer,
                          TPM2B_ATTEST* value,
                          dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_AUTH_COMMAND(const TPMS_AUTH_COMMAND* value,
                                   dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_SH_AUTH_SESSION(&value->session_handle, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_NONCE(&value->nonce, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_SESSION(&value->session_attributes, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_AUTH(&value->hmac, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_AUTH_COMMAND(src_data_buf_t* buffer,
                               TPMS_AUTH_COMMAND* value,
                               dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_AUTH_RESPONSE(const TPMS_AUTH_RESPONSE* value,
                                    dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_NONCE(&value->nonce, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_SESSION(&value->session_attributes, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_AUTH(&value->hmac, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_AUTH_RESPONSE(src_data_buf_t* buffer,
                                TPMS_AUTH_RESPONSE* value,
                                dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_SYM_KEY_BITS(const TPMU_SYM_KEY_BITS* value,
                                   TPMI_ALG_SYM selector,
                                   dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_SM4) {
    result = Serialize_TPMI_SM4_KEY_BITS(&value->sm4, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_AES) {
    result = Serialize_TPMI_AES_KEY_BITS(&value->aes, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_XOR) {
    result = Serialize_TPMI_ALG_HASH(&value->xor_, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_SYM_KEY_BITS(src_data_buf_t* buffer,
                               TPMI_ALG_SYM selector,
                               TPMU_SYM_KEY_BITS* value,
                               dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_SYM_MODE(const TPMU_SYM_MODE* value,
                               TPMI_ALG_SYM selector,
                               dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_SM4) {
    result = Serialize_TPMI_ALG_SYM_MODE(&value->sm4, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_AES) {
    result = Serialize_TPMI_ALG_SYM_MODE(&value->aes, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_XOR) {
    // Do nothing.
  }
  return result;
}

TPM_RC Parse_TPMU_SYM_MODE(src_data_buf_t* buffer,
                           TPMI_ALG_SYM selector,
                           TPMU_SYM_MODE* value,
                           dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_SYM_DETAILS(const TPMU_SYM_DETAILS* value,
                                  TPMI_ALG_SYM selector,
                                  dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;
    return result;
}

TPM_RC Parse_TPMU_SYM_DETAILS(src_data_buf_t* buffer,
                              TPMI_ALG_SYM selector,
                              TPMU_SYM_DETAILS* value,
                              dst_data_buf_t* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;
    return result;
}

TPM_RC Serialize_TPMT_SYM_DEF(const TPMT_SYM_DEF* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_SYM(&value->algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_KEY_BITS(&value->key_bits, value->algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_MODE(&value->mode, value->algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_DETAILS(&value->details, value->algorithm, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_SYM_DEF(src_data_buf_t* buffer,
                          TPMT_SYM_DEF* value,
                          dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_SYM_DEF_OBJECT(const TPMT_SYM_DEF_OBJECT* value,
                                     dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_SYM_OBJECT(&value->algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_KEY_BITS(&value->key_bits, value->algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_MODE(&value->mode, value->algorithm, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SYM_DETAILS(&value->details, value->algorithm, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_SYM_DEF_OBJECT(src_data_buf_t* buffer,
                                 TPMT_SYM_DEF_OBJECT* value,
                                 dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_SYM_KEY(const TPM2B_SYM_KEY* value,
                               dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_SYM_KEY(src_data_buf_t* buffer,
                           TPM2B_SYM_KEY* value,
                           dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_SYMCIPHER_PARMS(const TPMS_SYMCIPHER_PARMS* value,
                                      dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMT_SYM_DEF_OBJECT(&value->sym, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SYMCIPHER_PARMS(src_data_buf_t* buffer,
                                  TPMS_SYMCIPHER_PARMS* value,
                                  dst_data_buf_t* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMT_SYM_DEF_OBJECT(buffer, &value->sym, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPM2B_SENSITIVE_DATA(const TPM2B_SENSITIVE_DATA* value,
                                      dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_SENSITIVE_DATA(src_data_buf_t* buffer,
                                  TPM2B_SENSITIVE_DATA* value,
                                  dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_SENSITIVE_CREATE(const TPMS_SENSITIVE_CREATE* value,
                                       dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_AUTH(&value->user_auth, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_SENSITIVE_DATA(&value->data, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SENSITIVE_CREATE(src_data_buf_t* buffer,
                                   TPMS_SENSITIVE_CREATE* value,
                                   dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_SENSITIVE_CREATE(const TPM2B_SENSITIVE_CREATE* value,
                                        dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  dst_data_buf_t field_bytes;
  result = dst_data_buf_set_at_offset(&field_bytes, buffer, sizeof(UINT16));
  if (result) {
    return result;
  }
  if (value->size) {
    if (value->size != sizeof(TPMS_SENSITIVE_CREATE)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMS_SENSITIVE_CREATE(&value->sensitive, &field_bytes);
    if (result) {
      return result;
    }
  }
  UINT16 field_size = field_bytes.size - buffer->size - sizeof(UINT16);
  result = Serialize_UINT16(&field_size, buffer);
  if (result) {
    return result;
  }
  return dst_data_buf_set_at_offset(buffer, &field_bytes, 0);
}

TPM_RC Parse_TPM2B_SENSITIVE_CREATE(src_data_buf_t* buffer,
                                    TPM2B_SENSITIVE_CREATE* value,
                                    dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_SCHEME_XOR(const TPMS_SCHEME_XOR* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_ALG_KDF(&value->kdf, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_XOR(src_data_buf_t* buffer,
                             TPMS_SCHEME_XOR* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_SCHEME_KEYEDHASH(const TPMU_SCHEME_KEYEDHASH* value,
                                       TPMI_ALG_KEYEDHASH_SCHEME selector,
                                       dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_HMAC) {
    result = Serialize_TPMS_SCHEME_HMAC(&value->hmac, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_XOR) {
    result = Serialize_TPMS_SCHEME_XOR(&value->xor_, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_SCHEME_KEYEDHASH(src_data_buf_t* buffer,
                                   TPMI_ALG_KEYEDHASH_SCHEME selector,
                                   TPMU_SCHEME_KEYEDHASH* value,
                                   dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_KEYEDHASH_SCHEME(const TPMT_KEYEDHASH_SCHEME* value,
                                       dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_KEYEDHASH_SCHEME(&value->scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SCHEME_KEYEDHASH(&value->details, value->scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_KEYEDHASH_SCHEME(src_data_buf_t* buffer,
                                   TPMT_KEYEDHASH_SCHEME* value,
                                   dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_SCHEME_ECDAA(const TPMS_SCHEME_ECDAA* value,
                                   dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT16(&value->count, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_ECDAA(src_data_buf_t* buffer,
                               TPMS_SCHEME_ECDAA* value,
                               dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_SIG_SCHEME(const TPMU_SIG_SCHEME* value,
                                 TPMI_ALG_SIG_SCHEME selector,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_HMAC) {
    result = Serialize_TPMS_SCHEME_HMAC(&value->hmac, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECSCHNORR) {
    result = Serialize_TPMS_SCHEME_ECSCHNORR(&value->ec_schnorr, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSAPSS) {
    result = Serialize_TPMS_SCHEME_RSAPSS(&value->rsapss, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDAA) {
    result = Serialize_TPMS_SCHEME_ECDAA(&value->ecdaa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSASSA) {
    result = Serialize_TPMS_SCHEME_RSASSA(&value->rsassa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SM2) {
    result = Serialize_TPMS_SCHEME_SM2(&value->sm2, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDSA) {
    result = Serialize_TPMS_SCHEME_ECDSA(&value->ecdsa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }
  return result;
}

TPM_RC Parse_TPMU_SIG_SCHEME(src_data_buf_t* buffer,
                             TPMI_ALG_SIG_SCHEME selector,
                             TPMU_SIG_SCHEME* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_SIG_SCHEME(const TPMT_SIG_SCHEME* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_SIG_SCHEME(&value->scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SIG_SCHEME(&value->details, value->scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_SIG_SCHEME(src_data_buf_t* buffer,
                             TPMT_SIG_SCHEME* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_SCHEME_OAEP(const TPMS_SCHEME_OAEP* value,
                                  dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_OAEP(src_data_buf_t* buffer,
                              TPMS_SCHEME_OAEP* value,
                              dst_data_buf_t* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_ECDH(const TPMS_SCHEME_ECDH* value,
                                  dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_ECDH(src_data_buf_t* buffer,
                              TPMS_SCHEME_ECDH* value,
                              dst_data_buf_t* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_MGF1(const TPMS_SCHEME_MGF1* value,
                                  dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_MGF1(src_data_buf_t* buffer,
                              TPMS_SCHEME_MGF1* value,
                              dst_data_buf_t* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_KDF1_SP800_56a(
    const TPMS_SCHEME_KDF1_SP800_56a* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_KDF1_SP800_56a(src_data_buf_t* buffer,
                                        TPMS_SCHEME_KDF1_SP800_56a* value,
                                        dst_data_buf_t* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_KDF2(const TPMS_SCHEME_KDF2* value,
                                  dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_KDF2(src_data_buf_t* buffer,
                              TPMS_SCHEME_KDF2* value,
                              dst_data_buf_t* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_SCHEME_KDF1_SP800_108(
    const TPMS_SCHEME_KDF1_SP800_108* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SCHEME_KDF1_SP800_108(src_data_buf_t* buffer,
                                        TPMS_SCHEME_KDF1_SP800_108* value,
                                        dst_data_buf_t* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMI_ALG_HASH(buffer, &value->hash_alg, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMU_KDF_SCHEME(const TPMU_KDF_SCHEME* value,
                                 TPMI_ALG_KDF selector,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KDF1_SP800_56a) {
    result = Serialize_TPMS_SCHEME_KDF1_SP800_56a(&value->kdf1_sp800_56a, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_MGF1) {
    result = Serialize_TPMS_SCHEME_MGF1(&value->mgf1, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_KDF1_SP800_108) {
    result = Serialize_TPMS_SCHEME_KDF1_SP800_108(&value->kdf1_sp800_108, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_KDF2) {
    result = Serialize_TPMS_SCHEME_KDF2(&value->kdf2, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }
  return result;
}

TPM_RC Parse_TPMU_KDF_SCHEME(src_data_buf_t* buffer,
                             TPMI_ALG_KDF selector,
                             TPMU_KDF_SCHEME* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_KDF_SCHEME(const TPMT_KDF_SCHEME* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_KDF(&value->scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_KDF_SCHEME(&value->details, value->scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_KDF_SCHEME(src_data_buf_t* buffer,
                             TPMT_KDF_SCHEME* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_ASYM_SCHEME(const TPMU_ASYM_SCHEME* value,
                                  TPMI_ALG_ASYM_SCHEME selector,
                                  dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_RSAES) {
    // Do nothing.
  }

  if (selector == TPM_ALG_ECSCHNORR) {
    result = Serialize_TPMS_SCHEME_ECSCHNORR(&value->ec_schnorr, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }

  if (selector == TPM_ALG_ECDH) {
    result = Serialize_TPMS_SCHEME_ECDH(&value->ecdh, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_OAEP) {
    result = Serialize_TPMS_SCHEME_OAEP(&value->oaep, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSAPSS) {
    result = Serialize_TPMS_SCHEME_RSAPSS(&value->rsapss, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDAA) {
    result = Serialize_TPMS_SCHEME_ECDAA(&value->ecdaa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSASSA) {
    result = Serialize_TPMS_SCHEME_RSASSA(&value->rsassa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SM2) {
    result = Serialize_TPMS_SCHEME_SM2(&value->sm2, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDSA) {
    result = Serialize_TPMS_SCHEME_ECDSA(&value->ecdsa, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_ASYM_SCHEME(src_data_buf_t* buffer,
                              TPMI_ALG_ASYM_SCHEME selector,
                              TPMU_ASYM_SCHEME* value,
                              dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_ASYM_SCHEME(const TPMT_ASYM_SCHEME* value,
                                  dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_ASYM_SCHEME(&value->scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_ASYM_SCHEME(&value->details, value->scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_ASYM_SCHEME(src_data_buf_t* buffer,
                              TPMT_ASYM_SCHEME* value,
                              dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_RSA_SCHEME(const TPMT_RSA_SCHEME* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_RSA_SCHEME(&value->scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_ASYM_SCHEME(&value->details, value->scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_RSA_SCHEME(src_data_buf_t* buffer,
                             TPMT_RSA_SCHEME* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_RSA_DECRYPT(const TPMT_RSA_DECRYPT* value,
                                  dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_RSA_DECRYPT(&value->scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_ASYM_SCHEME(&value->details, value->scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_RSA_DECRYPT(src_data_buf_t* buffer,
                              TPMT_RSA_DECRYPT* value,
                              dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_PUBLIC_KEY_RSA(const TPM2B_PUBLIC_KEY_RSA* value,
                                      dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_PUBLIC_KEY_RSA(src_data_buf_t* buffer,
                                  TPM2B_PUBLIC_KEY_RSA* value,
                                  dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_PRIVATE_KEY_RSA(const TPM2B_PRIVATE_KEY_RSA* value,
                                       dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_PRIVATE_KEY_RSA(src_data_buf_t* buffer,
                                   TPM2B_PRIVATE_KEY_RSA* value,
                                   dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_ECC_PARAMETER(const TPM2B_ECC_PARAMETER* value,
                                     dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_ECC_PARAMETER(src_data_buf_t* buffer,
                                 TPM2B_ECC_PARAMETER* value,
                                 dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_ECC_POINT(const TPMS_ECC_POINT* value,
                                dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_ECC_PARAMETER(&value->x, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(&value->y, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ECC_POINT(src_data_buf_t* buffer,
                            TPMS_ECC_POINT* value,
                            dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_ECC_POINT(const TPM2B_ECC_POINT* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  dst_data_buf_t field_bytes;
  result = dst_data_buf_set_at_offset(&field_bytes, buffer, sizeof(UINT16));
  if (result) {
    return result;
  }
  if (value->size) {
    if (value->size != sizeof(TPMS_ECC_POINT)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMS_ECC_POINT(&value->point, &field_bytes);
    if (result) {
      return result;
    }
  }
  UINT16 field_size = field_bytes.size - buffer->size - sizeof(UINT16);
  result = Serialize_UINT16(&field_size, buffer);
  if (result) {
    return result;
  }
  return dst_data_buf_set_at_offset(buffer, &field_bytes, 0);
}

TPM_RC Parse_TPM2B_ECC_POINT(src_data_buf_t* buffer,
                             TPM2B_ECC_POINT* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_ECC_SCHEME(const TPMT_ECC_SCHEME* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_ECC_SCHEME(&value->scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SIG_SCHEME(&value->details, value->scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_ECC_SCHEME(src_data_buf_t* buffer,
                             TPMT_ECC_SCHEME* value,
                             dst_data_buf_t* value_bytes) {
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
    const TPMS_ALGORITHM_DETAIL_ECC* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM_ECC_CURVE(&value->curve_id, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT16(&value->key_size, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_KDF_SCHEME(&value->kdf, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_ECC_SCHEME(&value->sign, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(&value->p, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(&value->a, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(&value->b, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(&value->g_x, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(&value->g_y, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(&value->n, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(&value->h, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ALGORITHM_DETAIL_ECC(src_data_buf_t* buffer,
                                       TPMS_ALGORITHM_DETAIL_ECC* value,
                                       dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_SIGNATURE_RSASSA(const TPMS_SIGNATURE_RSASSA* value,
                                       dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_PUBLIC_KEY_RSA(&value->sig, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SIGNATURE_RSASSA(src_data_buf_t* buffer,
                                   TPMS_SIGNATURE_RSASSA* value,
                                   dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_SIGNATURE_RSAPSS(const TPMS_SIGNATURE_RSAPSS* value,
                                       dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_PUBLIC_KEY_RSA(&value->sig, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SIGNATURE_RSAPSS(src_data_buf_t* buffer,
                                   TPMS_SIGNATURE_RSAPSS* value,
                                   dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_SIGNATURE_ECDSA(const TPMS_SIGNATURE_ECDSA* value,
                                      dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_HASH(&value->hash, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(&value->signature_r, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_ECC_PARAMETER(&value->signature_s, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_SIGNATURE_ECDSA(src_data_buf_t* buffer,
                                  TPMS_SIGNATURE_ECDSA* value,
                                  dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_SIGNATURE(const TPMU_SIGNATURE* value,
                                TPMI_ALG_SIG_SCHEME selector,
                                dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_HMAC) {
    result = Serialize_TPMT_HA(&value->hmac, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECSCHNORR) {
    result = Serialize_TPMS_SIGNATURE_ECDSA(&value->ecschnorr, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSAPSS) {
    result = Serialize_TPMS_SIGNATURE_RSAPSS(&value->rsapss, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDAA) {
    result = Serialize_TPMS_SIGNATURE_ECDSA(&value->ecdaa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSASSA) {
    result = Serialize_TPMS_SIGNATURE_RSASSA(&value->rsassa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SM2) {
    result = Serialize_TPMS_SIGNATURE_ECDSA(&value->sm2, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECDSA) {
    result = Serialize_TPMS_SIGNATURE_ECDSA(&value->ecdsa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_NULL) {
    // Do nothing.
  }
  return result;
}

TPM_RC Parse_TPMU_SIGNATURE(src_data_buf_t* buffer,
                            TPMI_ALG_SIG_SCHEME selector,
                            TPMU_SIGNATURE* value,
                            dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_SIGNATURE(const TPMT_SIGNATURE* value,
                                dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_SIG_SCHEME(&value->sig_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SIGNATURE(&value->signature, value->sig_alg, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_SIGNATURE(src_data_buf_t* buffer,
                            TPMT_SIGNATURE* value,
                            dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_ENCRYPTED_SECRET(const TPM2B_ENCRYPTED_SECRET* value,
                                        dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->secret) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->secret[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_ENCRYPTED_SECRET(src_data_buf_t* buffer,
                                    TPM2B_ENCRYPTED_SECRET* value,
                                    dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_KEYEDHASH_PARMS(const TPMS_KEYEDHASH_PARMS* value,
                                      dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMT_KEYEDHASH_SCHEME(&value->scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_KEYEDHASH_PARMS(src_data_buf_t* buffer,
                                  TPMS_KEYEDHASH_PARMS* value,
                                  dst_data_buf_t* value_bytes) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Parse_TPMT_KEYEDHASH_SCHEME(buffer, &value->scheme, value_bytes);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Serialize_TPMS_ASYM_PARMS(const TPMS_ASYM_PARMS* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMT_SYM_DEF_OBJECT(&value->symmetric, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_ASYM_SCHEME(&value->scheme, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ASYM_PARMS(src_data_buf_t* buffer,
                             TPMS_ASYM_PARMS* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_RSA_PARMS(const TPMS_RSA_PARMS* value,
                                dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMT_SYM_DEF_OBJECT(&value->symmetric, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_RSA_SCHEME(&value->scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RSA_KEY_BITS(&value->key_bits, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT32(&value->exponent, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_RSA_PARMS(src_data_buf_t* buffer,
                            TPMS_RSA_PARMS* value,
                            dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_ECC_PARMS(const TPMS_ECC_PARMS* value,
                                dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMT_SYM_DEF_OBJECT(&value->symmetric, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_ECC_SCHEME(&value->scheme, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_ECC_CURVE(&value->curve_id, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_KDF_SCHEME(&value->kdf, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_ECC_PARMS(src_data_buf_t* buffer,
                            TPMS_ECC_PARMS* value,
                            dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_PUBLIC_PARMS(const TPMU_PUBLIC_PARMS* value,
                                   TPMI_ALG_PUBLIC selector,
                                   dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KEYEDHASH) {
    result = Serialize_TPMS_KEYEDHASH_PARMS(&value->keyed_hash_detail, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSA) {
    result = Serialize_TPMS_RSA_PARMS(&value->rsa_detail, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SYMCIPHER) {
    result = Serialize_TPMS_SYMCIPHER_PARMS(&value->sym_detail, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECC) {
    result = Serialize_TPMS_ECC_PARMS(&value->ecc_detail, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_PUBLIC_PARMS(src_data_buf_t* buffer,
                               TPMI_ALG_PUBLIC selector,
                               TPMU_PUBLIC_PARMS* value,
                               dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_PUBLIC_PARMS(const TPMT_PUBLIC_PARMS* value,
                                   dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_PUBLIC(&value->type, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_PUBLIC_PARMS(&value->parameters, value->type, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_PUBLIC_PARMS(src_data_buf_t* buffer,
                               TPMT_PUBLIC_PARMS* value,
                               dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_PUBLIC_ID(const TPMU_PUBLIC_ID* value,
                                TPMI_ALG_PUBLIC selector,
                                dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KEYEDHASH) {
    result = Serialize_TPM2B_DIGEST(&value->keyed_hash, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSA) {
    result = Serialize_TPM2B_PUBLIC_KEY_RSA(&value->rsa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SYMCIPHER) {
    result = Serialize_TPM2B_DIGEST(&value->sym, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECC) {
    result = Serialize_TPMS_ECC_POINT(&value->ecc, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_PUBLIC_ID(src_data_buf_t* buffer,
                            TPMI_ALG_PUBLIC selector,
                            TPMU_PUBLIC_ID* value,
                            dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_PUBLIC(const TPMT_PUBLIC* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_PUBLIC(&value->type, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_ALG_HASH(&value->name_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_OBJECT(&value->object_attributes, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->auth_policy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_PUBLIC_PARMS(&value->parameters, value->type, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_PUBLIC_ID(&value->unique, value->type, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_PUBLIC(src_data_buf_t* buffer,
                         TPMT_PUBLIC* value,
                         dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_PUBLIC(const TPM2B_PUBLIC* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  dst_data_buf_t field_bytes;
  result = dst_data_buf_set_at_offset(&field_bytes, buffer, sizeof(UINT16));
  if (result) {
    return result;
  }
  if (value->size) {
    if (value->size != sizeof(TPMT_PUBLIC)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMT_PUBLIC(&value->public_area, &field_bytes);
    if (result) {
      return result;
    }
  }
  UINT16 field_size = field_bytes.size - buffer->size - sizeof(UINT16);
  result = Serialize_UINT16(&field_size, buffer);
  if (result) {
    return result;
  }
  return dst_data_buf_set_at_offset(buffer, &field_bytes, 0);
}

TPM_RC Parse_TPM2B_PUBLIC(src_data_buf_t* buffer,
                          TPM2B_PUBLIC* value,
                          dst_data_buf_t* value_bytes) {
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
    const TPM2B_PRIVATE_VENDOR_SPECIFIC* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_PRIVATE_VENDOR_SPECIFIC(src_data_buf_t* buffer,
                                           TPM2B_PRIVATE_VENDOR_SPECIFIC* value,
                                           dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMU_SENSITIVE_COMPOSITE(const TPMU_SENSITIVE_COMPOSITE* value,
                                          TPMI_ALG_PUBLIC selector,
                                          dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  if (selector == TPM_ALG_KEYEDHASH) {
    result = Serialize_TPM2B_SENSITIVE_DATA(&value->bits, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_RSA) {
    result = Serialize_TPM2B_PRIVATE_KEY_RSA(&value->rsa, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_SYMCIPHER) {
    result = Serialize_TPM2B_SYM_KEY(&value->sym, buffer);
    if (result) {
      return result;
    }
  }

  if (selector == TPM_ALG_ECC) {
    result = Serialize_TPM2B_ECC_PARAMETER(&value->ecc, buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPMU_SENSITIVE_COMPOSITE(src_data_buf_t* buffer,
                                      TPMI_ALG_PUBLIC selector,
                                      TPMU_SENSITIVE_COMPOSITE* value,
                                      dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMT_SENSITIVE(const TPMT_SENSITIVE* value,
                                dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_ALG_PUBLIC(&value->sensitive_type, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_AUTH(&value->auth_value, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->seed_value, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMU_SENSITIVE_COMPOSITE(&value->sensitive,
                                              value->sensitive_type, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMT_SENSITIVE(src_data_buf_t* buffer,
                            TPMT_SENSITIVE* value,
                            dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_SENSITIVE(const TPM2B_SENSITIVE* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  dst_data_buf_t field_bytes;
  result = dst_data_buf_set_at_offset(&field_bytes, buffer, sizeof(UINT16));
  if (result) {
    return result;
  }
  if (value->size) {
    if (value->size != sizeof(TPMT_SENSITIVE)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMT_SENSITIVE(&value->sensitive_area, &field_bytes);
    if (result) {
      return result;
    }
  }
  UINT16 field_size = field_bytes.size - buffer->size - sizeof(UINT16);
  result = Serialize_UINT16(&field_size, buffer);
  if (result) {
    return result;
  }
  return dst_data_buf_set_at_offset(buffer, &field_bytes, 0);
}

TPM_RC Parse_TPM2B_SENSITIVE(src_data_buf_t* buffer,
                             TPM2B_SENSITIVE* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize__PRIVATE(const _PRIVATE* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_DIGEST(&value->integrity_outer, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->integrity_inner, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMT_SENSITIVE(&value->sensitive, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse__PRIVATE(src_data_buf_t* buffer,
                      _PRIVATE* value,
                      dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_PRIVATE(const TPM2B_PRIVATE* value,
                               dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_PRIVATE(src_data_buf_t* buffer,
                           TPM2B_PRIVATE* value,
                           dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize__ID_OBJECT(const _ID_OBJECT* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_DIGEST(&value->integrity_hmac, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->enc_identity, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse__ID_OBJECT(src_data_buf_t* buffer,
                        _ID_OBJECT* value,
                        dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_ID_OBJECT(const TPM2B_ID_OBJECT* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->credential) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->credential[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_ID_OBJECT(src_data_buf_t* buffer,
                             TPM2B_ID_OBJECT* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_NV_PUBLIC(const TPMS_NV_PUBLIC* value,
                                dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPMI_RH_NV_INDEX(&value->nv_index, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_ALG_HASH(&value->name_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_NV(&value->attributes, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->auth_policy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_UINT16(&value->data_size, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_NV_PUBLIC(src_data_buf_t* buffer,
                            TPMS_NV_PUBLIC* value,
                            dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_NV_PUBLIC(const TPM2B_NV_PUBLIC* value,
                                 dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  dst_data_buf_t field_bytes;
  result = dst_data_buf_set_at_offset(&field_bytes, buffer, sizeof(UINT16));
  if (result) {
    return result;
  }
  if (value->size) {
    if (value->size != sizeof(TPMS_NV_PUBLIC)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMS_NV_PUBLIC(&value->nv_public, &field_bytes);
    if (result) {
      return result;
    }
  }
  UINT16 field_size = field_bytes.size - buffer->size - sizeof(UINT16);
  result = Serialize_UINT16(&field_size, buffer);
  if (result) {
    return result;
  }
  return dst_data_buf_set_at_offset(buffer, &field_bytes, 0);
}

TPM_RC Parse_TPM2B_NV_PUBLIC(src_data_buf_t* buffer,
                             TPM2B_NV_PUBLIC* value,
                             dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_CONTEXT_SENSITIVE(const TPM2B_CONTEXT_SENSITIVE* value,
                                         dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_CONTEXT_SENSITIVE(src_data_buf_t* buffer,
                                     TPM2B_CONTEXT_SENSITIVE* value,
                                     dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_CONTEXT_DATA(const TPMS_CONTEXT_DATA* value,
                                   dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPM2B_DIGEST(&value->integrity, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_CONTEXT_SENSITIVE(&value->encrypted, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CONTEXT_DATA(src_data_buf_t* buffer,
                               TPMS_CONTEXT_DATA* value,
                               dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_CONTEXT_DATA(const TPM2B_CONTEXT_DATA* value,
                                    dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT16(&value->size, buffer);
  if (result) {
    return result;
  }

  if (sizeof(&value->buffer) < value->size) {
    return TPM_RC_INSUFFICIENT;
  }
  for (uint32_t i = 0; i < value->size; ++i) {
    result = Serialize_BYTE(&value->buffer[i], buffer);
    if (result) {
      return result;
    }
  }
  return result;
}

TPM_RC Parse_TPM2B_CONTEXT_DATA(src_data_buf_t* buffer,
                                TPM2B_CONTEXT_DATA* value,
                                dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_CONTEXT(const TPMS_CONTEXT* value, dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_UINT64(&value->sequence, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_DH_CONTEXT(&value->saved_handle, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMI_RH_HIERARCHY(&value->hierarchy, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_CONTEXT_DATA(&value->context_blob, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CONTEXT(src_data_buf_t* buffer,
                          TPMS_CONTEXT* value,
                          dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPMS_CREATION_DATA(const TPMS_CREATION_DATA* value,
                                    dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  result = Serialize_TPML_PCR_SELECTION(&value->pcr_select, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DIGEST(&value->pcr_digest, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPMA_LOCALITY(&value->locality, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM_ALG_ID(&value->parent_name_alg, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_NAME(&value->parent_name, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_NAME(&value->parent_qualified_name, buffer);
  if (result) {
    return result;
  }

  result = Serialize_TPM2B_DATA(&value->outside_info, buffer);
  if (result) {
    return result;
  }
  return result;
}

TPM_RC Parse_TPMS_CREATION_DATA(src_data_buf_t* buffer,
                                TPMS_CREATION_DATA* value,
                                dst_data_buf_t* value_bytes) {
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

TPM_RC Serialize_TPM2B_CREATION_DATA(const TPM2B_CREATION_DATA* value,
                                     dst_data_buf_t* buffer) {
  TPM_RC result = TPM_RC_SUCCESS;

  dst_data_buf_t field_bytes;
  result = dst_data_buf_set_at_offset(&field_bytes, buffer, sizeof(UINT16));
  if (result) {
    return result;
  }
  if (value->size) {
    if (value->size != sizeof(TPMS_CREATION_DATA)) {
      return TPM_RC_SIZE;
    }
    result = Serialize_TPMS_CREATION_DATA(&value->creation_data, &field_bytes);
    if (result) {
      return result;
    }
  }
  UINT16 field_size = field_bytes.size - buffer->size - sizeof(UINT16);
  result = Serialize_UINT16(&field_size, buffer);
  if (result) {
    return result;
  }
  return dst_data_buf_set_at_offset(buffer, &field_bytes, 0);
}

TPM_RC Parse_TPM2B_CREATION_DATA(src_data_buf_t* buffer,
                                 TPM2B_CREATION_DATA* value,
                                 dst_data_buf_t* value_bytes) {
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

static TPM_RC EncryptField(dst_data_buf_t* field,
    AuthorizationDelegate* authorization_delegate
) {
  if (authorization_delegate) {
    // Encrypt just the field data, not the size.
    if (field->size < sizeof(UINT16))
      return TPM_RC_FAILURE;
    src_data_buf_t field_data = {field->size - sizeof(UINT16),
                                 field->buffer + sizeof(UINT16)};
    if (!EncryptCommandParameter(authorization_delegate, &field_data)) {
      return TRUNKS_RC_ENCRYPTION_FAILED;
    }
  }
  return TPM_RC_SUCCESS;
}

// Insert authorization section and set tag and command size fields
static TPM_RC FinalizeCommand(
    dst_data_buf_t* serialized_command,
    size_t authorization_section_offset,
    uint8_t* command_hash_buffer /* SHA256_DIGEST_SIZE */,
    bool is_command_parameter_encryption_possible,
    bool is_response_parameter_encryption_possible,
    AuthorizationDelegate* authorization_delegate) {
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  TPM_RC rc;

  if (authorization_delegate && command_hash_buffer) {
    src_data_buf_t command_hash = {SHA256_DIGEST_SIZE, command_hash_buffer};
    uint8_t authorization_section_buf[kMaxAuthSectionSize];
    dst_data_buf_t authorization_section_bytes = {kMaxAuthSectionSize, 0,
                                                  authorization_section_buf};
    if (!GetCommandAuthorization(authorization_delegate,
            &command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes)) {
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    }
    if (authorization_section_bytes.size != 0) {
      dst_data_buf_t authorization_section;
      rc = dst_data_buf_insert(serialized_command, &authorization_section,
          authorization_section_offset,
          authorization_section_bytes.size + sizeof(UINT32));
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      tag = TPM_ST_SESSIONS;
      UINT32 size = authorization_section_bytes.size;
      rc = Serialize_UINT32(&size, &authorization_section);
      if (rc != TPM_RC_SUCCESS) {
        return rc;
      }
      rc = dst_data_buf_append(&authorization_section,
                               authorization_section_bytes.buffer,
                               authorization_section_bytes.size);
    }
  }
  UINT32 command_size = serialized_command->size;
  if (command_size < 10) {
    return TPM_RC_FAILURE;
  }
  dst_data_buf_t tag_size_bytes = {
      sizeof(TPMI_ST_COMMAND_TAG) + sizeof(UINT32),
      0,
      serialized_command->buffer};
  rc = Serialize_TPMI_ST_COMMAND_TAG(&tag, &tag_size_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  return Serialize_UINT32(&command_size, &tag_size_bytes);
}

typedef struct cmd_processor_t {
  TPM_CC command_code;
  bool is_command_parameter_encryption_possible;
  bool is_response_parameter_encryption_possible;
  size_t authorization_section_offset;
  dst_data_buf_t* serialized_command;
  dst_data_buf_t field_bytes;
  AuthorizationDelegate* authorization_delegate;
  pinweaver_eal_sha256_ctx_t hash;
  bool next_encrypt;
} cmd_processor_t;

static dst_data_buf_t* cmd_process_start_field(cmd_processor_t* p) {
  dst_data_buf_set_to_remainder(&p->field_bytes, p->serialized_command);
  return &p->field_bytes;
}

static TPM_RC cmd_process_field(cmd_processor_t* p,
                                const TPM2B_DIGEST* optional_name) {
  p->field_bytes.max_size = p->field_bytes.size;
  dst_data_buf_skip(p->serialized_command, p->field_bytes.size, NULL);
  if (p->next_encrypt) {
    TPM_RC rc = EncryptField(&p->field_bytes,
                             p->authorization_delegate);
    if (rc != TPM_RC_SUCCESS)
      return rc;
  }
  p->next_encrypt = false;

  const void* data;
  size_t size;
  if (optional_name) {
    data = optional_name->buffer;
    size = optional_name->size;
  } else {
    data = p->field_bytes.buffer;
    size = p->field_bytes.size;
  }
  if (pinweaver_eal_sha256_update(&p->hash, data, size))
    return TRUNKS_RC_HASH_ERROR;
  return TPM_RC_SUCCESS;
}

static TPM_RC cmd_process_start(
    cmd_processor_t* p,
    TPM_CC command_code,
    bool is_command_parameter_encryption_possible,
    bool is_response_parameter_encryption_possible,
    dst_data_buf_t* serialized_command,
    AuthorizationDelegate* authorization_delegate
) {
  memset(p, 0, sizeof(cmd_processor_t));

  p->command_code = command_code;
  p->is_command_parameter_encryption_possible =
      is_command_parameter_encryption_possible;
  p->is_response_parameter_encryption_possible =
      is_response_parameter_encryption_possible;
  p->serialized_command = serialized_command;
  p->authorization_delegate = authorization_delegate;

  if (pinweaver_eal_sha256_init(&p->hash))
    return TRUNKS_RC_HASH_ERROR;

  TPM_RC rc = dst_data_buf_skip(p->serialized_command,
      sizeof(TPMI_ST_COMMAND_TAG) + sizeof(UINT32), NULL);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  dst_data_buf_t* field_bytes = cmd_process_start_field(p);
  rc = Serialize_TPM_CC(&p->command_code, field_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  return cmd_process_field(p, NULL);
}

static void cmd_process_param_section(cmd_processor_t* p) {
  p->authorization_section_offset = p->serialized_command->size;
  p->next_encrypt = p->is_command_parameter_encryption_possible;
}

static TPM_RC cmd_process_finish(cmd_processor_t* p) {
  uint8_t command_hash_buffer[SHA256_DIGEST_SIZE];
  if (pinweaver_eal_sha256_final(&p->hash, command_hash_buffer))
    return TRUNKS_RC_HASH_ERROR;
  if (p->authorization_section_offset == 0) {
    p->authorization_section_offset = p->serialized_command->size;
  }
  return FinalizeCommand(p->serialized_command,
      p->authorization_section_offset,
      command_hash_buffer,
      p->is_command_parameter_encryption_possible,
      p->is_response_parameter_encryption_possible,
      p->authorization_delegate);
}

#define CMD_PROCESS(data, type, name) \
  do { \
    dst_data_buf_t* field_bytes = cmd_process_start_field(&p); \
    TPM_RC rc = Serialize_##type((data), field_bytes); \
    if (rc != TPM_RC_SUCCESS) \
      return rc; \
    rc = cmd_process_field(&p, (name)); \
    if (rc != TPM_RC_SUCCESS) \
      return rc; \
  } while(0)

#define CMD_PROCESS_VAL(field, type) \
  CMD_PROCESS(&(field), type, NULL)

#define CMD_PROCESS_HANDLE(field) \
  CMD_PROCESS(&(field), TPM_HANDLE, field##_name)

#define CMD_PROCESS_PTR(field, type) \
  CMD_PROCESS(field, type, NULL)

#define CMD_PROCESS_START(cc, cmd_enc, rsp_enc) \
  cmd_processor_t p; \
  do { \
    TPM_RC rc = cmd_process_start(&p, (cc), (cmd_enc), (rsp_enc), \
        serialized_command, authorization_delegate); \
    if (rc != TPM_RC_SUCCESS) \
      return rc; \
  } while(0)

#define CMD_PROCESS_FINISH() \
  return cmd_process_finish(&p)

#define CMD_PROCESS_PARAM_SECTION() \
  cmd_process_param_section(&p)

typedef struct rsp_processor_t {
  src_data_buf_t buffer;
  AuthorizationDelegate* authorization_delegate;
  uint8_t* response_code_ptr;
  TPM_CC command_code;
  TPM_ST tag;
  bool decrypt_first;
} rsp_processor_t;

static TPM_RC rsp_process_start(
    rsp_processor_t* p,
    const src_data_buf_t* response,
    TPM_CC command_code,
    bool decrypt_first,
    AuthorizationDelegate* authorization_delegate
) {
  memset(p, 0, sizeof(rsp_processor_t));

  p->buffer.size = response->size;
  p->buffer.buffer = response->buffer;
  p->command_code = command_code;
  p->decrypt_first = decrypt_first;
  p->authorization_delegate = authorization_delegate;

  TPM_RC rc = Parse_TPM_ST(&p->buffer, &p->tag, NULL);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }

  UINT32 response_size;
  rc = Parse_UINT32(&p->buffer, &response_size, NULL);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }

  TPM_RC response_code;
  p->response_code_ptr = p->buffer.buffer;
  rc = Parse_TPM_RC(&p->buffer, &response_code, NULL);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }

  if (response_size != response->size) {
    return TPM_RC_SIZE;
  }
  return response_code;
}

static TPM_RC rsp_process_auth_block(rsp_processor_t* p) {
  if (p->tag != TPM_ST_SESSIONS)
    return TPM_RC_SUCCESS;

  TPM_CC command_code_buffer;
  dst_data_buf_t command_code_bytes = {sizeof(TPM_CC), 0,
                                       (uint8_t *)&command_code_buffer};
  TPM_RC rc = Serialize_TPM_CC(&p->command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }

  UINT32 auth_section_size;
  rc = Parse_UINT32(&p->buffer, &auth_section_size, nullptr);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (auth_section_size > p->buffer.size) {
    return TPM_RC_INSUFFICIENT;
  }
  src_data_buf_t authorization_section_bytes = {auth_section_size,
                                                p->buffer.buffer};
  p->buffer.buffer += auth_section_size;
  p->buffer.size -= auth_section_size;

  pinweaver_eal_sha256_ctx_t hash;
  if (pinweaver_eal_sha256_init(&hash))
    return TRUNKS_RC_HASH_ERROR;
  if (pinweaver_eal_sha256_update(&hash, p->response_code_ptr,
                                  sizeof(TPM_RC))) {
    return TRUNKS_RC_HASH_ERROR;
  }
  if (pinweaver_eal_sha256_update(&hash, command_code_bytes.buffer,
                                  command_code_bytes.size)) {
    return TRUNKS_RC_HASH_ERROR;
  }
  if (pinweaver_eal_sha256_update(&hash, p->buffer.buffer, p->buffer.size))
    return TRUNKS_RC_HASH_ERROR;

  uint8_t response_hash_buffer[SHA256_DIGEST_SIZE];
  src_data_buf_t response_hash = {SHA256_DIGEST_SIZE, response_hash_buffer};
  if (pinweaver_eal_sha256_final(&hash, response_hash_buffer))
    return TRUNKS_RC_HASH_ERROR;

  if (!p->authorization_delegate) {
    return TRUNKS_RC_AUTHORIZATION_FAILED;
  }
  if (!CheckResponseAuthorization(p->authorization_delegate,
      &response_hash, &authorization_section_bytes)) {
    return TRUNKS_RC_AUTHORIZATION_FAILED;
  }

  if (p->decrypt_first) {
    UINT16 first_param_size;
    rc = Parse_UINT16(&p->buffer, &first_param_size, NULL);
    if (rc != TPM_RC_SUCCESS) {
      return rc;
    }
    if (first_param_size > p->buffer.size) {
      return TPM_RC_INSUFFICIENT;
    }
    src_data_buf_t first_param = {first_param_size, p->buffer.buffer};
    if (!DecryptResponseParameter(p->authorization_delegate, &first_param)) {
      return TRUNKS_RC_ENCRYPTION_FAILED;
    }
  }
  return TPM_RC_SUCCESS;
}

#define RSP_PROCESS_START(cc, decrypt_first) \
  rsp_processor_t p; \
  do { \
    TPM_RC rc = rsp_process_start(&p, response, cc, decrypt_first, \
                                  authorization_delegate); \
    if (rc != TPM_RC_SUCCESS) \
      return rc; \
  } while(0)

#define RSP_PROCESS_AUTH_BLOCK() \
  do { \
    TPM_RC rc = rsp_process_auth_block(&p); \
    if (rc != TPM_RC_SUCCESS) \
      return rc; \
  } while(0)

#define RSP_PROCESS_FIELD(field, type) \
  do { \
    TPM_RC rc = Parse_##type(&p.buffer, field, NULL); \
    if (rc != TPM_RC_SUCCESS) \
      return rc; \
  } while(0)

#define RSP_PROCESS_FINISH() \
  return TPM_RC_SUCCESS

static TPM_RC SerializeCommand_StartAuthSession(
    const TPMI_DH_OBJECT tpm_key,
    const TPM2B_DIGEST* tpm_key_name,
    const TPMI_DH_ENTITY bind,
    const TPM2B_DIGEST* bind_name,
    const TPM2B_NONCE* nonce_caller,
    const TPM2B_ENCRYPTED_SECRET* encrypted_salt,
    const TPM_SE session_type,
    const TPMT_SYM_DEF* symmetric,
    const TPMI_ALG_HASH auth_hash,
    dst_data_buf_t* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  CMD_PROCESS_START(TPM_CC_StartAuthSession, true, true);
  CMD_PROCESS_HANDLE(tpm_key);
  CMD_PROCESS_HANDLE(bind);
  CMD_PROCESS_PARAM_SECTION();
  CMD_PROCESS_PTR(nonce_caller, TPM2B_NONCE);
  CMD_PROCESS_PTR(encrypted_salt, TPM2B_ENCRYPTED_SECRET);
  CMD_PROCESS_VAL(session_type, TPM_SE);
  CMD_PROCESS_PTR(symmetric, TPMT_SYM_DEF);
  CMD_PROCESS_VAL(auth_hash, TPMI_ALG_HASH);
  CMD_PROCESS_FINISH();
}

static TPM_RC ParseResponse_StartAuthSession(
    const src_data_buf_t* response,
    TPMI_SH_AUTH_SESSION* session_handle,
    TPM2B_NONCE* nonce_tpm,
    AuthorizationDelegate* authorization_delegate) {
  RSP_PROCESS_START(TPM_CC_StartAuthSession, true);
  RSP_PROCESS_FIELD(session_handle, TPMI_SH_AUTH_SESSION);
  RSP_PROCESS_AUTH_BLOCK();
  RSP_PROCESS_FIELD(nonce_tpm, TPM2B_NONCE);
  RSP_PROCESS_FINISH();
}

TPM_RC StartAuthSession(
    const TPMI_DH_OBJECT tpm_key,
    const TPM2B_DIGEST* tpm_key_name,
    const TPMI_DH_ENTITY bind,
    const TPM2B_DIGEST* bind_name,
    const TPM2B_NONCE* nonce_caller,
    const TPM2B_ENCRYPTED_SECRET* encrypted_salt,
    const TPM_SE session_type,
    const TPMT_SYM_DEF* symmetric,
    const TPMI_ALG_HASH auth_hash,
    TPMI_SH_AUTH_SESSION* session_handle,
    TPM2B_NONCE* nonce_tpm,
    AuthorizationDelegate* authorization_delegate) {
  dst_data_buf_t command = {kMaxMessageSize, 0, g_message};
  TPM_RC rc = SerializeCommand_StartAuthSession(
      tpm_key, tpm_key_name, bind, bind_name, nonce_caller, encrypted_salt,
      session_type, symmetric, auth_hash, &command, authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  src_data_buf_t response;
  SendCommandAndWait(&command, &response);
  rc = ParseResponse_StartAuthSession(&response, session_handle, nonce_tpm,
                                      authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_ReadPublic(
    const TPMI_DH_OBJECT object_handle,
    const TPM2B_DIGEST* object_handle_name,
    dst_data_buf_t* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  CMD_PROCESS_START(TPM_CC_ReadPublic, false, true);
  CMD_PROCESS_HANDLE(object_handle);
  CMD_PROCESS_FINISH();
}

static TPM_RC ParseResponse_ReadPublic(
    const src_data_buf_t* response,
    TPM2B_PUBLIC* out_public,
    TPM2B_NAME* name,
    TPM2B_NAME* qualified_name,
    AuthorizationDelegate* authorization_delegate) {
  RSP_PROCESS_START(TPM_CC_ReadPublic, true);
  RSP_PROCESS_AUTH_BLOCK();
  RSP_PROCESS_FIELD(out_public, TPM2B_PUBLIC);
  RSP_PROCESS_FIELD(name, TPM2B_NAME);
  RSP_PROCESS_FIELD(qualified_name, TPM2B_NAME);
  RSP_PROCESS_FINISH();
}

TPM_RC ReadPublic(const TPMI_DH_OBJECT object_handle,
                  const TPM2B_DIGEST* object_handle_name,
                  TPM2B_PUBLIC* out_public,
                  TPM2B_NAME* name,
                  TPM2B_NAME* qualified_name,
                  AuthorizationDelegate* authorization_delegate) {
  dst_data_buf_t command = {kMaxMessageSize, 0, g_message};
  TPM_RC rc = SerializeCommand_ReadPublic(object_handle, object_handle_name,
                                          &command, authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  src_data_buf_t response;
  SendCommandAndWait(&command, &response);

  rc = ParseResponse_ReadPublic(&response, out_public, name, qualified_name,
                                authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_PolicyCommandCode(
    const TPMI_SH_POLICY policy_session,
    const TPM2B_DIGEST* policy_session_name,
    const TPM_CC code,
    dst_data_buf_t* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  CMD_PROCESS_START(TPM_CC_PolicyCommandCode, false, false);
  CMD_PROCESS_HANDLE(policy_session);
  CMD_PROCESS_PARAM_SECTION();
  CMD_PROCESS_VAL(code, TPM_CC);
  CMD_PROCESS_FINISH();
}

static TPM_RC ParseResponse_PolicyCommandCode(
    const src_data_buf_t* response,
    AuthorizationDelegate* authorization_delegate) {
  RSP_PROCESS_START(TPM_CC_PolicyCommandCode, false);
  RSP_PROCESS_AUTH_BLOCK();
  RSP_PROCESS_FINISH();
}

TPM_RC PolicyCommandCode(
    const TPMI_SH_POLICY policy_session,
    const TPM2B_DIGEST* policy_session_name,
    const TPM_CC code,
    AuthorizationDelegate* authorization_delegate) {
  dst_data_buf_t command = {kMaxMessageSize, 0, g_message};
  TPM_RC rc = SerializeCommand_PolicyCommandCode(
      policy_session, policy_session_name, code, &command,
      authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  src_data_buf_t response;
  SendCommandAndWait(&command, &response);

  rc = ParseResponse_PolicyCommandCode(&response, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_PolicyAuthValue(
    const TPMI_SH_POLICY policy_session,
    const TPM2B_DIGEST* policy_session_name,
    dst_data_buf_t* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  CMD_PROCESS_START(TPM_CC_PolicyAuthValue, false, false);
  CMD_PROCESS_HANDLE(policy_session);
  CMD_PROCESS_FINISH();
}

static TPM_RC ParseResponse_PolicyAuthValue(
    const src_data_buf_t* response,
    AuthorizationDelegate* authorization_delegate) {
  RSP_PROCESS_START(TPM_CC_PolicyAuthValue, false);
  RSP_PROCESS_AUTH_BLOCK();
  RSP_PROCESS_FINISH();
}

TPM_RC PolicyAuthValue(const TPMI_SH_POLICY policy_session,
                       const TPM2B_DIGEST* policy_session_name,
                       AuthorizationDelegate* authorization_delegate) {
  dst_data_buf_t command = {kMaxMessageSize, 0, g_message};
  TPM_RC rc = SerializeCommand_PolicyAuthValue(
      policy_session, policy_session_name, &command, authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  src_data_buf_t response;
  SendCommandAndWait(&command, &response);

  rc = ParseResponse_PolicyAuthValue(&response, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_FlushContext(
    const TPMI_DH_CONTEXT flush_handle,
    dst_data_buf_t* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  CMD_PROCESS_START(TPM_CC_FlushContext, false, false);
  CMD_PROCESS_PARAM_SECTION();
  CMD_PROCESS_VAL(flush_handle, TPMI_DH_CONTEXT);
  CMD_PROCESS_FINISH();
}

static TPM_RC ParseResponse_FlushContext(
    const src_data_buf_t* response,
    AuthorizationDelegate* authorization_delegate) {
  RSP_PROCESS_START(TPM_CC_FlushContext, false);
  RSP_PROCESS_AUTH_BLOCK();
  RSP_PROCESS_FINISH();
}

TPM_RC FlushContext(const TPMI_DH_CONTEXT flush_handle,
                    AuthorizationDelegate* authorization_delegate) {
  dst_data_buf_t command = {kMaxMessageSize, 0, g_message};
  TPM_RC rc = SerializeCommand_FlushContext(flush_handle, &command,
                                            authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  src_data_buf_t response;
  SendCommandAndWait(&command, &response);

  rc = ParseResponse_FlushContext(&response, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_NV_DefineSpace(
    const TPMI_RH_PROVISION auth_handle,
    const TPM2B_DIGEST* auth_handle_name,
    const TPM2B_AUTH* auth,
    const TPM2B_NV_PUBLIC* public_info,
    dst_data_buf_t* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  CMD_PROCESS_START(TPM_CC_NV_DefineSpace, true, false);
  CMD_PROCESS_HANDLE(auth_handle);
  CMD_PROCESS_PARAM_SECTION();
  CMD_PROCESS_PTR(auth, TPM2B_AUTH);
  CMD_PROCESS_PTR(public_info, TPM2B_NV_PUBLIC);
  CMD_PROCESS_FINISH();
}

static TPM_RC ParseResponse_NV_DefineSpace(
    const src_data_buf_t* response,
    AuthorizationDelegate* authorization_delegate) {
  RSP_PROCESS_START(TPM_CC_NV_DefineSpace, false);
  RSP_PROCESS_AUTH_BLOCK();
  RSP_PROCESS_FINISH();
}

TPM_RC NV_DefineSpace(const TPMI_RH_PROVISION auth_handle,
                      const TPM2B_DIGEST* auth_handle_name,
                      const TPM2B_AUTH* auth,
                      const TPM2B_NV_PUBLIC* public_info,
                      AuthorizationDelegate* authorization_delegate) {
  dst_data_buf_t command = {kMaxMessageSize, 0, g_message};
  TPM_RC rc = SerializeCommand_NV_DefineSpace(auth_handle, auth_handle_name,
                                              auth, public_info, &command,
                                              authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  src_data_buf_t response;
  SendCommandAndWait(&command, &response);

  rc = ParseResponse_NV_DefineSpace(&response, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_NV_ReadPublic(
    const TPMI_RH_NV_INDEX nv_index,
    const TPM2B_DIGEST* nv_index_name,
    dst_data_buf_t* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  CMD_PROCESS_START(TPM_CC_NV_ReadPublic, false, true);
  CMD_PROCESS_HANDLE(nv_index);
  CMD_PROCESS_FINISH();
}

static TPM_RC ParseResponse_NV_ReadPublic(
    const src_data_buf_t* response,
    TPM2B_NV_PUBLIC* nv_public,
    TPM2B_NAME* nv_name,
    AuthorizationDelegate* authorization_delegate) {
  RSP_PROCESS_START(TPM_CC_NV_ReadPublic, true);
  RSP_PROCESS_AUTH_BLOCK();
  RSP_PROCESS_FIELD(nv_public, TPM2B_NV_PUBLIC);
  RSP_PROCESS_FIELD(nv_name, TPM2B_NAME);
  RSP_PROCESS_FINISH();
}

TPM_RC NV_ReadPublic(const TPMI_RH_NV_INDEX nv_index,
                     const TPM2B_DIGEST* nv_index_name,
                     TPM2B_NV_PUBLIC* nv_public,
                     TPM2B_NAME* nv_name,
                     AuthorizationDelegate* authorization_delegate) {
  dst_data_buf_t command = {kMaxMessageSize, 0, g_message};
  TPM_RC rc = SerializeCommand_NV_ReadPublic(nv_index, nv_index_name, &command,
                                             authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  src_data_buf_t response;
  SendCommandAndWait(&command, &response);

  rc = ParseResponse_NV_ReadPublic(&response, nv_public, nv_name,
                                   authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_NV_Write(
    const TPMI_RH_NV_AUTH auth_handle,
    const TPM2B_DIGEST* auth_handle_name,
    const TPMI_RH_NV_INDEX nv_index,
    const TPM2B_DIGEST* nv_index_name,
    const TPM2B_MAX_NV_BUFFER* data,
    const UINT16 offset,
    dst_data_buf_t* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  CMD_PROCESS_START(TPM_CC_NV_Write, true, false);
  CMD_PROCESS_HANDLE(auth_handle);
  CMD_PROCESS_HANDLE(nv_index);
  CMD_PROCESS_PARAM_SECTION();
  CMD_PROCESS_PTR(data, TPM2B_MAX_NV_BUFFER);
  CMD_PROCESS_VAL(offset, UINT16);
  CMD_PROCESS_FINISH();
}

static TPM_RC ParseResponse_NV_Write(
    const src_data_buf_t* response,
    AuthorizationDelegate* authorization_delegate) {
  RSP_PROCESS_START(TPM_CC_NV_Write, false);
  RSP_PROCESS_AUTH_BLOCK();
  RSP_PROCESS_FINISH();
}

TPM_RC NV_Write(const TPMI_RH_NV_AUTH auth_handle,
                const TPM2B_DIGEST* auth_handle_name,
                const TPMI_RH_NV_INDEX nv_index,
                const TPM2B_DIGEST* nv_index_name,
                const TPM2B_MAX_NV_BUFFER* data,
                const UINT16 offset,
                AuthorizationDelegate* authorization_delegate) {
  dst_data_buf_t command = {kMaxMessageSize, 0, g_message};
  TPM_RC rc = SerializeCommand_NV_Write(auth_handle, auth_handle_name, nv_index,
                                        nv_index_name, data, offset, &command,
                                        authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  src_data_buf_t response;
  SendCommandAndWait(&command, &response);

  rc = ParseResponse_NV_Write(&response, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_NV_Read(
    const TPMI_RH_NV_AUTH auth_handle,
    const TPM2B_DIGEST* auth_handle_name,
    const TPMI_RH_NV_INDEX nv_index,
    const TPM2B_DIGEST* nv_index_name,
    const UINT16 size,
    const UINT16 offset,
    dst_data_buf_t* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  CMD_PROCESS_START(TPM_CC_NV_Read, false, true);
  CMD_PROCESS_HANDLE(auth_handle);
  CMD_PROCESS_HANDLE(nv_index);
  CMD_PROCESS_PARAM_SECTION();
  CMD_PROCESS_VAL(size, UINT16);
  CMD_PROCESS_VAL(offset, UINT16);
  CMD_PROCESS_FINISH();
}

static TPM_RC ParseResponse_NV_Read(
    const src_data_buf_t* response,
    TPM2B_MAX_NV_BUFFER* data,
    AuthorizationDelegate* authorization_delegate) {
  RSP_PROCESS_START(TPM_CC_NV_Read, true);
  RSP_PROCESS_AUTH_BLOCK();
  RSP_PROCESS_FIELD(data, TPM2B_MAX_NV_BUFFER);
  RSP_PROCESS_FINISH();
}

TPM_RC NV_Read(const TPMI_RH_NV_AUTH auth_handle,
               const TPM2B_DIGEST* auth_handle_name,
               const TPMI_RH_NV_INDEX nv_index,
               const TPM2B_DIGEST* nv_index_name,
               const UINT16 size,
               const UINT16 offset,
               TPM2B_MAX_NV_BUFFER* data,
               AuthorizationDelegate* authorization_delegate) {
  dst_data_buf_t command = {kMaxMessageSize, 0, g_message};
  TPM_RC rc = SerializeCommand_NV_Read(auth_handle, auth_handle_name, nv_index,
                                       nv_index_name, size, offset, &command,
                                       authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  src_data_buf_t response;
  SendCommandAndWait(&command, &response);

  rc = ParseResponse_NV_Read(&response, data, authorization_delegate);
  return rc;
}

static TPM_RC SerializeCommand_NV_ChangeAuth(
    const TPMI_RH_NV_INDEX nv_index,
    const TPM2B_DIGEST* nv_index_name,
    const TPM2B_AUTH* new_auth,
    dst_data_buf_t* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  CMD_PROCESS_START(TPM_CC_NV_ChangeAuth, true, false);
  CMD_PROCESS_HANDLE(nv_index);
  CMD_PROCESS_PARAM_SECTION();
  CMD_PROCESS_PTR(new_auth, TPM2B_AUTH);
  CMD_PROCESS_FINISH();
}

static TPM_RC ParseResponse_NV_ChangeAuth(
    const src_data_buf_t* response,
    AuthorizationDelegate* authorization_delegate) {
  RSP_PROCESS_START(TPM_CC_NV_ChangeAuth, false);
  RSP_PROCESS_AUTH_BLOCK();
  RSP_PROCESS_FINISH();
}

TPM_RC NV_ChangeAuth(const TPMI_RH_NV_INDEX nv_index,
                     const TPM2B_DIGEST* nv_index_name,
                     const TPM2B_AUTH* new_auth,
                     AuthorizationDelegate* authorization_delegate) {
  dst_data_buf_t command = {kMaxMessageSize, 0, g_message};
  TPM_RC rc = SerializeCommand_NV_ChangeAuth(nv_index, nv_index_name, new_auth,
                                             &command, authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  src_data_buf_t response;
  SendCommandAndWait(&command, &response);

  rc = ParseResponse_NV_ChangeAuth(&response, authorization_delegate);
  return rc;
}
