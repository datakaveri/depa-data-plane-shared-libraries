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

#ifndef CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_CLIENT_PROVIDER_PRIVATE_KEY_CLIENT_PROVIDER_H_
#define CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_CLIENT_PROVIDER_PRIVATE_KEY_CLIENT_PROVIDER_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/status/status.h"
#include "src/core/interface/async_context.h"
#include "src/cpio/client_providers/interface/kms_client_provider_interface.h"
#include "src/cpio/client_providers/interface/private_key_client_provider_interface.h"
#include "src/cpio/client_providers/interface/private_key_fetcher_provider_interface.h"
#include "src/public/core/interface/execution_result.h"
#include "src/public/cpio/proto/kms_service/v1/kms_service.pb.h"

#include "error_codes.h"
#include "private_key_client_utils.h"

namespace google::scp::cpio::client_providers {

class PrivateKeyClientProvider : public PrivateKeyClientProviderInterface {
 public:
  virtual ~PrivateKeyClientProvider() = default;

  explicit PrivateKeyClientProvider(
      PrivateKeyClientOptions private_key_client_options,
      absl::Nonnull<std::unique_ptr<PrivateKeyFetcherProviderInterface>>
          private_key_fetcher,
      absl::Nonnull<std::unique_ptr<KmsClientProviderInterface>> kms_client)
      : private_key_fetcher_(std::move(private_key_fetcher)),
        kms_client_(std::move(kms_client)),
        private_key_client_options_(std::move(private_key_client_options)) {}

  absl::Status ListPrivateKeys(
      core::AsyncContext<
          cmrt::sdk::private_key_service::v1::ListPrivateKeysRequest,
          cmrt::sdk::private_key_service::v1::ListPrivateKeysResponse>&
          context) noexcept override;

 private:
  // Called when FetchPrivateKey completes. The iSPIRT KMS returns a single
  // EncryptionKey envelope whose keyMaterial is released only via /app/unwrapKey
  // (RSA-wrapped). We dispatch the envelope's key material to the KMS client
  // (GcpUnwrapKmsClientProvider) for decryption rather than decrypting locally.
  void OnFetchPrivateKeyCallback(
      core::AsyncContext<
          cmrt::sdk::private_key_service::v1::ListPrivateKeysRequest,
          cmrt::sdk::private_key_service::v1::ListPrivateKeysResponse>&
          list_private_keys_context,
      core::AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
          fetch_private_key_context) noexcept;

  // Called when the KMS client finishes decrypting (unwrapping) the key
  // material. Builds the PrivateKey proto and finishes the list context.
  void OnKmsDecryptCallback(
      core::AsyncContext<
          cmrt::sdk::private_key_service::v1::ListPrivateKeysRequest,
          cmrt::sdk::private_key_service::v1::ListPrivateKeysResponse>&
          list_private_keys_context,
      std::shared_ptr<EncryptionKey> encryption_key,
      core::AsyncContext<cmrt::sdk::kms_service::v1::DecryptRequest,
                         cmrt::sdk::kms_service::v1::DecryptResponse>&
          decrypt_context) noexcept;

  std::unique_ptr<PrivateKeyFetcherProviderInterface> private_key_fetcher_;
  std::unique_ptr<KmsClientProviderInterface> kms_client_;
  PrivateKeyClientOptions private_key_client_options_;
};

}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_CLIENT_PROVIDER_PRIVATE_KEY_CLIENT_PROVIDER_H_
