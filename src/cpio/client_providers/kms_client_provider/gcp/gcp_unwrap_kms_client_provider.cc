// Copyright (c) iSPIRT / DEPA.
// Licensed under the Apache License, Version 2.0.

#include "gcp_unwrap_kms_client_provider.h"

#include <cstdlib>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "absl/base/nullability.h"
#include "absl/functional/bind_front.h"
#include "absl/strings/str_cat.h"
#include "src/core/utils/base64.h"
#include "src/cpio/client_providers/confidential_space/confidential_space_token_fetcher.h"
#include "src/cpio/client_providers/global_cpio/global_cpio.h"
#include "src/cpio/client_providers/interface/kms_client_provider_interface.h"
#include "src/cpio/client_providers/interface/role_credentials_provider_interface.h"
#include "src/cpio/client_providers/kms_client_provider/azure/azure_kms_client_provider_utils.h"
#include "src/public/cpio/interface/kms_client/type_def.h"

#include "error_codes.h"

using google::cmrt::sdk::kms_service::v1::DecryptRequest;
using google::cmrt::sdk::kms_service::v1::DecryptResponse;
using google::scp::core::AsyncContext;
using google::scp::core::AsyncExecutorInterface;
using google::scp::core::BytesBuffer;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::HttpClientInterface;
using google::scp::core::HttpHeaders;
using google::scp::core::HttpMethod;
using google::scp::core::HttpRequest;
using google::scp::core::HttpResponse;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::Uri;
using google::scp::core::errors::SC_GCP_KMS_CLIENT_PROVIDER_BASE64_DECODING_FAILED;
using google::scp::core::errors::SC_GCP_KMS_CLIENT_PROVIDER_CIPHERTEXT_NOT_FOUND;
using google::scp::core::errors::SC_GCP_KMS_CLIENT_PROVIDER_DECRYPTION_FAILED;
using google::scp::core::errors::SC_GCP_KMS_CLIENT_PROVIDER_KEY_ARN_NOT_FOUND;
using google::scp::core::utils::Base64Decode;
using std::bind;
using std::placeholders::_1;

namespace {
constexpr char kGcpUnwrapKmsClientProvider[] = "GcpUnwrapKmsClientProvider";

constexpr char kAuthorizationHeaderKey[] = "Authorization";
constexpr char kBearerTokenPrefix[] = "Bearer ";

// Endpoint of the iSPIRT KMS /app/unwrapKey?fmt=tink. Provided via env var so
// it can be set per-deployment (the KMS client does not see the B&A runtime
// flags). terraform must inject KMS_UNWRAP_URL into the container env, e.g.
// "http://20.219.6.35/app/unwrapKey?fmt=tink".
constexpr char kKmsUnwrapUrlEnvVar[] = "KMS_UNWRAP_URL";

// Request/response field names of the iSPIRT KMS unwrap API.
constexpr char kWrapped[] = "wrapped";
constexpr char kWrappedKid[] = "wrappedKid";
constexpr char kWrappingKey[] = "wrappingKey";
constexpr char kAttestationType[] = "attestationType";
constexpr char kGcp[] = "gcp";
}  // namespace

namespace google::scp::cpio::client_providers {

absl::Status GcpUnwrapKmsClientProvider::Decrypt(
    AsyncContext<DecryptRequest, DecryptResponse>& decrypt_context) noexcept {
  const auto& ciphertext = decrypt_context.request->ciphertext();
  if (ciphertext.empty()) {
    auto execution_result =
        FailureExecutionResult(SC_GCP_KMS_CLIENT_PROVIDER_CIPHERTEXT_NOT_FOUND);
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      execution_result, "Missing ciphertext in decrypt request.");
    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return absl::UnknownError("Missing ciphertext");
  }

  const auto& key_id = decrypt_context.request->key_resource_name();
  if (key_id.empty()) {
    auto execution_result =
        FailureExecutionResult(SC_GCP_KMS_CLIENT_PROVIDER_KEY_ARN_NOT_FOUND);
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      execution_result, "Missing key id in decrypt request.");
    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return absl::UnknownError("Missing key id");
  }

  if (unwrap_url_.empty()) {
    const char* value_from_env = std::getenv(kKmsUnwrapUrlEnvVar);
    if (value_from_env != nullptr && *value_from_env != '\0') {
      unwrap_url_ = value_from_env;
    } else {
      auto execution_result =
          FailureExecutionResult(SC_GCP_KMS_CLIENT_PROVIDER_DECRYPTION_FAILED);
      SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                        execution_result,
                        "KMS_UNWRAP_URL env var is not set.");
      decrypt_context.result = execution_result;
      decrypt_context.Finish();
      return absl::UnknownError("KMS_UNWRAP_URL not set");
    }
  }

  // 1. Generate ephemeral RSA wrapping key pair (.first=private, .second=public).
  const auto wrapping_key_pair_or =
      AzureKmsClientProviderUtils::GenerateWrappingKey();
  if (!wrapping_key_pair_or.ok()) {
    auto execution_result =
        FailureExecutionResult(SC_GCP_KMS_CLIENT_PROVIDER_DECRYPTION_FAILED);
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      execution_result, "Failed to generate wrapping key: %s",
                      wrapping_key_pair_or.status().ToString().c_str());
    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return absl::UnknownError("wrapping key generation failed");
  }
  std::shared_ptr<EvpPkeyWrapper> wrapping_private_key =
      wrapping_key_pair_or.value().first;
  std::shared_ptr<EvpPkeyWrapper> wrapping_public_key =
      wrapping_key_pair_or.value().second;

  // 2. hex(SHA-256(wrapping public key PEM)) — used as the JWT eat_nonce.
  const auto hex_hash_or =
      AzureKmsClientProviderUtils::CreateHexHashOnKey(wrapping_public_key);
  if (!hex_hash_or.ok()) {
    auto execution_result =
        FailureExecutionResult(SC_GCP_KMS_CLIENT_PROVIDER_DECRYPTION_FAILED);
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      execution_result, "Failed to hash wrapping key: %s",
                      hex_hash_or.status().ToString().c_str());
    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return absl::UnknownError("wrapping key hash failed");
  }

  // 3. Fetch a Confidential Space token whose eat_nonce is the wrapping-key
  //    hash. The wrapping key must exist BEFORE the token is minted (unlike the
  //    Azure SNP flow, where the report is fetched after token acquisition).
  auto token_or =
      FetchConfidentialSpaceToken(unwrap_url_, {hex_hash_or.value()});
  if (!token_or.ok()) {
    auto execution_result =
        FailureExecutionResult(SC_GCP_KMS_CLIENT_PROVIDER_DECRYPTION_FAILED);
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      execution_result,
                      "Failed to fetch Confidential Space token: %s",
                      token_or.status().ToString().c_str());
    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return absl::UnknownError("Confidential Space token fetch failed");
  }

  const auto wrapping_key_pem_or =
      AzureKmsClientProviderUtils::EvpPkeyToPem(wrapping_public_key);
  if (!wrapping_key_pem_or.ok()) {
    auto execution_result =
        FailureExecutionResult(SC_GCP_KMS_CLIENT_PROVIDER_DECRYPTION_FAILED);
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      execution_result,
                      "Failed to convert wrapping key to PEM: %s",
                      wrapping_key_pem_or.status().ToString().c_str());
    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return absl::UnknownError("wrapping key PEM conversion failed");
  }

  // 4. POST to /app/unwrapKey.
  nlohmann::json payload;
  payload[kWrapped] = ciphertext;
  payload[kWrappedKid] = key_id;
  payload[kWrappingKey] = wrapping_key_pem_or.value();
  payload[kAttestationType] = kGcp;

  AsyncContext<HttpRequest, HttpResponse> http_context;
  http_context.request = std::make_shared<HttpRequest>();
  http_context.request->path = std::make_shared<Uri>(unwrap_url_);
  http_context.request->method = HttpMethod::POST;
  http_context.request->body = BytesBuffer(payload.dump());
  http_context.request->headers = std::make_shared<HttpHeaders>();
  http_context.request->headers->insert(
      {std::string(kAuthorizationHeaderKey),
       absl::StrCat(kBearerTokenPrefix, token_or.value())});
  http_context.callback =
      bind(&GcpUnwrapKmsClientProvider::OnDecryptCallback, this,
           decrypt_context, wrapping_private_key, _1);

  auto execution_result = http_client_->PerformRequest(http_context);
  if (!execution_result.Successful()) {
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      execution_result,
                      "Failed to perform http request to /app/unwrapKey.");
    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return absl::UnknownError("unwrapKey request failed");
  }
  return absl::OkStatus();
}

void GcpUnwrapKmsClientProvider::OnDecryptCallback(
    AsyncContext<DecryptRequest, DecryptResponse>& decrypt_context,
    std::shared_ptr<EvpPkeyWrapper> ephemeral_private_key,
    AsyncContext<HttpRequest, HttpResponse>& http_client_context) noexcept {
  if (!http_client_context.result.Successful()) {
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      http_client_context.result,
                      "Failed to unwrap key via iSPIRT KMS /app/unwrapKey.");
    decrypt_context.result = http_client_context.result;
    decrypt_context.Finish();
    return;
  }

  std::string resp(http_client_context.response->body.bytes->begin(),
                   http_client_context.response->body.bytes->end());
  nlohmann::json unwrap_resp;
  try {
    unwrap_resp = nlohmann::json::parse(resp);
  } catch (const nlohmann::json::parse_error& e) {
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      http_client_context.result,
                      "Failed to parse /app/unwrapKey response as JSON.");
    decrypt_context.result = http_client_context.result;
    decrypt_context.Finish();
    return;
  }
  if (!unwrap_resp.contains(kWrapped)) {
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      http_client_context.result,
                      "/app/unwrapKey response missing 'wrapped' field.");
    decrypt_context.result = http_client_context.result;
    decrypt_context.Finish();
    return;
  }

  std::string base64_encoded = unwrap_resp[kWrapped].get<std::string>();
  std::string decoded_wrapped;
  if (auto execution_result = Base64Decode(std::string_view(base64_encoded),
                                           decoded_wrapped);
      !execution_result.Successful()) {
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      execution_result,
                      "Failed to base64-decode /app/unwrapKey response.");
    decrypt_context.result = FailureExecutionResult(
        SC_GCP_KMS_CLIENT_PROVIDER_BASE64_DECODING_FAILED);
    decrypt_context.Finish();
    return;
  }

  std::vector<unsigned char> encrypted(decoded_wrapped.begin(),
                                       decoded_wrapped.end());
  const auto decrypted_or =
      AzureKmsClientProviderUtils::KeyUnwrap(ephemeral_private_key, encrypted);
  if (!decrypted_or.ok()) {
    auto execution_result =
        FailureExecutionResult(SC_GCP_KMS_CLIENT_PROVIDER_DECRYPTION_FAILED);
    SCP_ERROR_CONTEXT(kGcpUnwrapKmsClientProvider, decrypt_context,
                      execution_result, "Failed to RSA-unwrap key: %s",
                      decrypted_or.status().ToString().c_str());
    decrypt_context.result = execution_result;
    decrypt_context.Finish();
    return;
  }

  decrypt_context.response = std::make_shared<DecryptResponse>();
  decrypt_context.response->set_plaintext(decrypted_or.value());
  decrypt_context.result = SuccessExecutionResult();
  decrypt_context.Finish();
}

std::unique_ptr<KmsClientProviderInterface> KmsClientProviderFactory::Create(
    absl::Nonnull<
        RoleCredentialsProviderInterface*> /*role_credentials_provider*/,
    AsyncExecutorInterface* /*io_async_executor*/) noexcept {
  // Reuse the global HTTP client (matches the Azure provider; avoids changing
  // the KmsClientProviderFactory::Create signature shared with AWS/GCP).
  auto cpio_ = &GlobalCpio::GetGlobalCpio();
  auto http_client = &cpio_->GetHttpClient();
  return std::make_unique<GcpUnwrapKmsClientProvider>(http_client);
}
}  // namespace google::scp::cpio::client_providers
