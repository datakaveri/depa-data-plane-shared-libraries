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
#include "absl/strings/str_cat.h"
#include "openssl/hpke.h"
#include "src/core/interface/async_context.h"
#include "src/core/interface/http_client_interface.h"
#include "src/cpio/client_providers/interface/auth_token_provider_interface.h"
#include "src/cpio/client_providers/interface/role_credentials_provider_interface.h"
#include "src/public/core/interface/execution_result.h"
#include "src/public/cpio/interface/private_key_client/type_def.h"
#include "src/public/cpio/proto/private_key_service/v1/private_key_service.pb.h"

#include "error_codes.h"
#include "private_key_client_utils.h"

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

// Decrypts |ciphertext| using HPKE with the X25519 private key bytes in
// |priv_key_bytes|.
//
// Expected ciphertext layout (produced by the vending service):
//   enc (X25519_PUBLIC_VALUE_LEN bytes)  ||  AES-256-GCM ciphertext+tag
//
// This mirrors the same HPKE suite used for OHTTP in this codebase:
//   DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM
absl::StatusOr<std::string> HpkeDecrypt(
    const std::string& ciphertext, const std::string& priv_key_bytes) {
  const size_t enc_len =
      EVP_HPKE_KEM_enc_len(EVP_hpke_x25519_hkdf_sha256());  // 32 bytes

  if (ciphertext.size() <= enc_len) {
    return absl::InvalidArgumentError(
        "HPKE ciphertext too short to contain encapsulated key");
  }

  // Reconstruct the recipient HPKE key from the raw X25519 private key bytes.
  bssl::ScopedEVP_HPKE_KEY hpke_key;
  if (!EVP_HPKE_KEY_init(
          hpke_key.get(), EVP_hpke_x25519_hkdf_sha256(),
          reinterpret_cast<const uint8_t*>(priv_key_bytes.data()),
          priv_key_bytes.size())) {
    return absl::InternalError("Failed to initialize HPKE recipient key");
  }

  // Set up the recipient context using the encapsulated key (first enc_len
  // bytes of the ciphertext).
  bssl::ScopedEVP_HPKE_CTX hpke_ctx;
  const auto* enc = reinterpret_cast<const uint8_t*>(ciphertext.data());
  if (!EVP_HPKE_CTX_setup_recipient(hpke_ctx.get(), hpke_key.get(),
                                    EVP_hpke_hkdf_sha256(),
                                    EVP_hpke_aes_256_gcm(), enc, enc_len,
                                    /*info=*/nullptr, /*info_len=*/0)) {
    return absl::InternalError("Failed to set up HPKE recipient context");
  }

  // Decrypt the remainder.
  const auto* ct =
      reinterpret_cast<const uint8_t*>(ciphertext.data()) + enc_len;
  const size_t ct_len = ciphertext.size() - enc_len;
  std::vector<uint8_t> plaintext(ct_len);
  size_t plaintext_len = 0;
  if (!EVP_HPKE_CTX_open(hpke_ctx.get(), plaintext.data(), &plaintext_len,
                          plaintext.size(), ct, ct_len,
                          /*aad=*/nullptr, /*aad_len=*/0)) {
    return absl::InternalError("HPKE decryption failed");
  }

  return std::string(reinterpret_cast<const char*>(plaintext.data()),
                     plaintext_len);
}
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

  const std::string& ephemeral_priv_key =
      fetch_private_key_context.request->ephemeral_private_key_bytes;

  list_private_keys_context.response =
      std::make_shared<ListPrivateKeysResponse>();

  for (const auto& encryption_key :
       fetch_private_key_context.response->encryption_keys) {
    if (encryption_key->key_data.empty() ||
        !encryption_key->key_data[0]->key_material ||
        encryption_key->key_data[0]->key_material->empty()) {
      PS_LOG(ERROR, private_key_client_options_.log_context)
          << "Missing key_material for key_id: " << *encryption_key->key_id;
      list_private_keys_context.Finish(
          FailureExecutionResult(SC_PRIVATE_KEY_CLIENT_PROVIDER_KEY_DATA_NOT_FOUND));
      return;
    }

    const std::string& ciphertext =
        *encryption_key->key_data[0]->key_material;

    auto plaintext_or = HpkeDecrypt(ciphertext, ephemeral_priv_key);
    if (!plaintext_or.ok()) {
      PS_LOG(ERROR, private_key_client_options_.log_context)
          << "HPKE decryption failed for key_id " << *encryption_key->key_id
          << ": " << plaintext_or.status();
      list_private_keys_context.Finish(
          FailureExecutionResult(SC_PRIVATE_KEY_CLIENT_PROVIDER_KEY_DATA_NOT_FOUND));
      return;
    }

    auto private_key_or =
        PrivateKeyClientUtils::ConstructPrivateKey(*encryption_key, *plaintext_or);
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
  }

  list_private_keys_context.Finish(SuccessExecutionResult());
}

absl::Nonnull<std::unique_ptr<PrivateKeyClientProviderInterface>>
PrivateKeyClientProviderFactory::Create(
    PrivateKeyClientOptions options,
    absl::Nonnull<core::HttpClientInterface*> http_client,
    absl::Nonnull<RoleCredentialsProviderInterface*> role_credentials_provider,
    absl::Nonnull<AuthTokenProviderInterface*> auth_token_provider,
    absl::Nonnull<core::AsyncExecutorInterface*> /*io_async_executor*/) {
  return std::make_unique<PrivateKeyClientProvider>(
      std::move(options),
      PrivateKeyFetcherProviderFactory::Create(
          http_client, role_credentials_provider, auth_token_provider,
          options.log_context));
}

}  // namespace google::scp::cpio::client_providers
