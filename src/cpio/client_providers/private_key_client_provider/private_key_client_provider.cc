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

#include "private_key_client_provider.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/nullability.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "src/core/interface/async_context.h"
#include "src/core/interface/http_client_interface.h"
#include "src/cpio/client_providers/interface/auth_token_provider_interface.h"
#include "src/cpio/client_providers/interface/kms_client_provider_interface.h"
#include "src/cpio/client_providers/interface/role_credentials_provider_interface.h"
#include "src/public/core/interface/execution_result.h"
#include "src/public/cpio/interface/private_key_client/type_def.h"
#include "src/public/cpio/proto/kms_service/v1/kms_service.pb.h"
#include "src/public/cpio/proto/private_key_service/v1/private_key_service.pb.h"

#include "error_codes.h"
#include "private_key_client_utils.h"

using google::cmrt::sdk::kms_service::v1::DecryptRequest;
using google::cmrt::sdk::kms_service::v1::DecryptResponse;
using google::cmrt::sdk::private_key_service::v1::ListPrivateKeysRequest;
using google::cmrt::sdk::private_key_service::v1::ListPrivateKeysResponse;
using google::cmrt::sdk::private_key_service::v1::PrivateKey;
using google::scp::core::AsyncContext;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::HttpClientInterface;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::common::kZeroUuid;

namespace {
constexpr std::string_view kPrivateKeyClientProvider =
    "PrivateKeyClientProvider";

// keyEncryptionKeyUri prefix used by the iSPIRT KMS envelope
// (KeyWrapper.ts: "azu-kms://" + kid). Stripped to recover the bare kid the
// KMS /app/unwrapKey expects as `wrappedKid`.
constexpr absl::string_view kKekUriPrefix = "azu-kms://";
}  // namespace

namespace google::scp::cpio::client_providers {

absl::Status PrivateKeyClientProvider::ListPrivateKeys(
    AsyncContext<ListPrivateKeysRequest, ListPrivateKeysResponse>&
        list_private_keys_context) noexcept {
  PS_VLOG(5, private_key_client_options_.log_context)
      << "Listing private keys...";

  auto request = std::make_shared<PrivateKeyFetchingRequest>();
  request->key_vending_endpoint = std::make_shared<PrivateKeyVendingEndpoint>(
      private_key_client_options_.primary_private_key_vending_endpoint);

  if (list_private_keys_context.request->key_ids().empty()) {
    request->max_age_seconds =
        list_private_keys_context.request->max_age_seconds();
    PS_VLOG(5, private_key_client_options_.log_context)
        << "Fetching private keys by max_age_seconds: "
        << request->max_age_seconds;
  } else {
    // Fetch the first requested key ID (single-key model).
    request->key_id = std::make_shared<std::string>(
        list_private_keys_context.request->key_ids(0));
    PS_VLOG(5, private_key_client_options_.log_context)
        << "Fetching private key by key_id: " << *request->key_id;
  }

  AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>
      fetch_context(
          std::move(request),
          std::bind(&PrivateKeyClientProvider::OnFetchPrivateKeyCallback, this,
                    list_private_keys_context, std::placeholders::_1),
          list_private_keys_context);

  if (auto result = private_key_fetcher_->FetchPrivateKey(fetch_context);
      !result.Successful()) {
    auto error_message =
        google::scp::core::errors::GetErrorMessage(result.status_code);
    PS_LOG(ERROR, private_key_client_options_.log_context)
        << "FetchPrivateKey failed: " << error_message;
    list_private_keys_context.Finish(result);
    return absl::UnknownError(error_message);
  }

  return absl::OkStatus();
}

void PrivateKeyClientProvider::OnFetchPrivateKeyCallback(
    AsyncContext<ListPrivateKeysRequest, ListPrivateKeysResponse>&
        list_private_keys_context,
    AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
        fetch_private_key_context) noexcept {
  if (!fetch_private_key_context.result.Successful()) {
    SCP_ERROR_CONTEXT(kPrivateKeyClientProvider, list_private_keys_context,
                      fetch_private_key_context.result,
                      "FetchPrivateKey failed.");
    list_private_keys_context.Finish(fetch_private_key_context.result);
    return;
  }

  list_private_keys_context.response =
      std::make_shared<ListPrivateKeysResponse>();

  const auto& encryption_keys =
      fetch_private_key_context.response->encryption_keys;
  if (encryption_keys.empty()) {
    // Nothing to decrypt.
    list_private_keys_context.Finish(SuccessExecutionResult());
    return;
  }

  // The iSPIRT KMS returns a single-party key envelope (one EncryptionKey, one
  // keyData). Dispatch its key material to the KMS client (/app/unwrapKey).
  auto encryption_key = encryption_keys[0];
  if (encryption_key->key_data.empty() ||
      !encryption_key->key_data[0]->key_material ||
      encryption_key->key_data[0]->key_material->empty()) {
    PS_LOG(ERROR, private_key_client_options_.log_context)
        << "Missing key_material for key_id: " << *encryption_key->key_id;
    list_private_keys_context.Finish(FailureExecutionResult(
        SC_PRIVATE_KEY_CLIENT_PROVIDER_KEY_DATA_NOT_FOUND));
    return;
  }

  const auto& key_data = encryption_key->key_data[0];
  const std::string kek_uri =
      key_data->key_encryption_key_uri ? *key_data->key_encryption_key_uri : "";
  const std::string kid = absl::StartsWith(kek_uri, kKekUriPrefix)
                              ? std::string(kek_uri.substr(kKekUriPrefix.size()))
                              : kek_uri;

  auto decrypt_request = std::make_shared<DecryptRequest>();
  decrypt_request->set_key_resource_name(kid);
  decrypt_request->set_ciphertext(*key_data->key_material);

  AsyncContext<DecryptRequest, DecryptResponse> decrypt_context(
      std::move(decrypt_request),
      std::bind(&PrivateKeyClientProvider::OnKmsDecryptCallback, this,
                list_private_keys_context, encryption_key,
                std::placeholders::_1),
      list_private_keys_context);

  if (auto status = kms_client_->Decrypt(decrypt_context); !status.ok()) {
    PS_LOG(ERROR, private_key_client_options_.log_context)
        << "KMS Decrypt dispatch failed: " << status;
    list_private_keys_context.Finish(FailureExecutionResult(
        SC_PRIVATE_KEY_CLIENT_PROVIDER_KEY_DATA_NOT_FOUND));
    return;
  }
}

void PrivateKeyClientProvider::OnKmsDecryptCallback(
    AsyncContext<ListPrivateKeysRequest, ListPrivateKeysResponse>&
        list_private_keys_context,
    std::shared_ptr<EncryptionKey> encryption_key,
    AsyncContext<DecryptRequest, DecryptResponse>& decrypt_context) noexcept {
  if (!decrypt_context.result.Successful()) {
    SCP_ERROR_CONTEXT(kPrivateKeyClientProvider, list_private_keys_context,
                      decrypt_context.result,
                      "KMS Decrypt (unwrap) failed for key_id %s.",
                      encryption_key->key_id->c_str());
    list_private_keys_context.Finish(decrypt_context.result);
    return;
  }

  const std::string& plaintext = decrypt_context.response->plaintext();
  auto private_key_or =
      PrivateKeyClientUtils::ConstructPrivateKey(*encryption_key, plaintext);
  if (!private_key_or.Successful()) {
    auto error_message = google::scp::core::errors::GetErrorMessage(
        private_key_or.result().status_code);
    PS_LOG(ERROR, private_key_client_options_.log_context)
        << "ConstructPrivateKey failed: " << error_message;
    list_private_keys_context.Finish(private_key_or.result());
    return;
  }

  *list_private_keys_context.response->add_private_keys() =
      std::move(*private_key_or);
  list_private_keys_context.Finish(SuccessExecutionResult());
}

absl::Nonnull<std::unique_ptr<PrivateKeyClientProviderInterface>>
PrivateKeyClientProviderFactory::Create(
    PrivateKeyClientOptions options,
    absl::Nonnull<core::HttpClientInterface*> http_client,
    absl::Nonnull<RoleCredentialsProviderInterface*> role_credentials_provider,
    absl::Nonnull<AuthTokenProviderInterface*> auth_token_provider,
    absl::Nonnull<core::AsyncExecutorInterface*> io_async_executor) {
  auto kms_client = KmsClientProviderFactory::Create(role_credentials_provider,
                                                     io_async_executor);
  return std::make_unique<PrivateKeyClientProvider>(
      std::move(options),
      PrivateKeyFetcherProviderFactory::Create(
          http_client, role_credentials_provider, auth_token_provider,
          options.log_context),
      std::move(kms_client));
}

}  // namespace google::scp::cpio::client_providers
