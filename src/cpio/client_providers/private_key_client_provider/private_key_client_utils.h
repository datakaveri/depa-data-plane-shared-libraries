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

#ifndef CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_CLIENT_PROVIDER_PRIVATE_KEY_CLIENT_UTILS_H_
#define CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_CLIENT_PROVIDER_PRIVATE_KEY_CLIENT_UTILS_H_

#include <string>

#include "src/cpio/client_providers/interface/private_key_fetcher_provider_interface.h"
#include "src/public/core/interface/execution_result.h"
#include "src/public/cpio/proto/private_key_service/v1/private_key_service.pb.h"

#include "error_codes.h"

namespace google::scp::cpio::client_providers {

class PrivateKeyClientUtils {
 public:
  // Builds a PrivateKey proto from the EncryptionKey metadata and the
  // already-decrypted plaintext key material. The plaintext is base64-encoded
  // before being stored in the proto.
  static core::ExecutionResultOr<cmrt::sdk::private_key_service::v1::PrivateKey>
  ConstructPrivateKey(const EncryptionKey& encryption_key,
                      const std::string& plaintext) noexcept;
};

}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_CLIENT_PROVIDER_PRIVATE_KEY_CLIENT_UTILS_H_
