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
#include "src/cpio/client_providers/interface/private_key_client_provider_interface.h"
#include "src/cpio/client_providers/interface/private_key_fetcher_provider_interface.h"
#include "src/public/core/interface/execution_result.h"

#include "error_codes.h"
#include "private_key_client_utils.h"

namespace google::scp::cpio::client_providers {

class PrivateKeyClientProvider : public PrivateKeyClientProviderInterface {
 public:
  virtual ~PrivateKeyClientProvider() = default;

  explicit PrivateKeyClientProvider(
      PrivateKeyClientOptions private_key_client_options,
      absl::Nonnull<std::unique_ptr<PrivateKeyFetcherProviderInterface>>
          private_key_fetcher)
      : private_key_fetcher_(std::move(private_key_fetcher)),
        private_key_client_options_(std::move(private_key_client_options)) {}

  absl::Status ListPrivateKeys(
      core::AsyncContext<
          cmrt::sdk::private_key_service::v1::ListPrivateKeysRequest,
          cmrt::sdk::private_key_service::v1::ListPrivateKeysResponse>&
          context) noexcept override;

 private:
  // Called when FetchPrivateKey completes. Decrypts each returned key using
  // the ephemeral X25519 private key stored in the fetch request (GCP TEE
  // path: the vending service encrypted the key material with the TEE public
  // key that was sent as the OIDC nonce).
  void OnFetchPrivateKeyCallback(
      core::AsyncContext<
          cmrt::sdk::private_key_service::v1::ListPrivateKeysRequest,
          cmrt::sdk::private_key_service::v1::ListPrivateKeysResponse>&
          list_private_keys_context,
      core::AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
          fetch_private_key_context) noexcept;

  std::unique_ptr<PrivateKeyFetcherProviderInterface> private_key_fetcher_;
  PrivateKeyClientOptions private_key_client_options_;
};

}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_CLIENT_PROVIDER_PRIVATE_KEY_CLIENT_PROVIDER_H_
