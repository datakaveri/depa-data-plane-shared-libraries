/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "private_key_client_utils.h"

#include <string>

#include <google/protobuf/util/time_util.h>

#include "src/core/utils/base64.h"
#include "src/public/core/interface/execution_result.h"
#include "src/public/cpio/proto/private_key_service/v1/private_key_service.pb.h"

#include "error_codes.h"

using google::cmrt::sdk::private_key_service::v1::PrivateKey;
using google::protobuf::util::TimeUtil;
using google::scp::core::ExecutionResultOr;
using google::scp::core::SuccessExecutionResult;

namespace google::scp::cpio::client_providers {

ExecutionResultOr<PrivateKey> PrivateKeyClientUtils::ConstructPrivateKey(
    const EncryptionKey& encryption_key,
    const std::string& plaintext) noexcept {
  PrivateKey private_key;
  private_key.set_key_id(*encryption_key.key_id);
  private_key.set_public_key(*encryption_key.public_key_material);
  *private_key.mutable_expiration_time() =
      TimeUtil::MillisecondsToTimestamp(encryption_key.expiration_time_in_ms);
  *private_key.mutable_creation_time() =
      TimeUtil::MillisecondsToTimestamp(encryption_key.creation_time_in_ms);

  std::string encoded_key;
  RETURN_IF_FAILURE(core::utils::Base64Encode(plaintext, encoded_key));
  private_key.set_private_key(std::move(encoded_key));

  return private_key;
}

}  // namespace google::scp::cpio::client_providers
