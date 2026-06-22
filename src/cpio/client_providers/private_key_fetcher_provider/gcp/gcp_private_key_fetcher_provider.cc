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

#include "gcp_private_key_fetcher_provider.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "absl/strings/str_cat.h"
#include "src/core/interface/http_client_interface.h"
#include "src/cpio/client_providers/confidential_space/confidential_space_token_fetcher.h"
#include "src/cpio/client_providers/interface/auth_token_provider_interface.h"
#include "src/cpio/client_providers/interface/role_credentials_provider_interface.h"
#include "src/cpio/client_providers/private_key_fetcher_provider/private_key_fetcher_provider_utils.h"
#include "src/public/core/interface/execution_result.h"

#include "error_codes.h"

using google::scp::core::AsyncContext;
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
using google::scp::core::common::kZeroUuid;
using google::scp::core::errors::
    SC_GCP_PRIVATE_KEY_FETCHER_PROVIDER_CREDENTIALS_PROVIDER_NOT_FOUND;
using std::bind;
using std::placeholders::_1;

namespace {
constexpr std::string_view kGcpPrivateKeyFetcherProvider =
    "GcpPrivateKeyFetcherProvider";
constexpr char kAuthorizationHeaderKey[] = "Authorization";
constexpr char kBearerTokenPrefix[] = "Bearer ";
constexpr char kAttestationType[] = "attestationType";
constexpr char kGcp[] = "gcp";

// iSPIRT KMS /key (and /unwrapKey) response field names.
constexpr char kWrappedKid[] = "wrappedKid";
constexpr char kWrapped[] = "wrapped";
}  // namespace

namespace google::scp::cpio::client_providers {

ExecutionResult GcpPrivateKeyFetcherProvider::Init() noexcept {
  RETURN_IF_FAILURE(PrivateKeyFetcherProvider::Init());

  if (!auth_token_provider_) {
    auto execution_result = FailureExecutionResult(
        SC_GCP_PRIVATE_KEY_FETCHER_PROVIDER_CREDENTIALS_PROVIDER_NOT_FOUND);
    SCP_ERROR(kGcpPrivateKeyFetcherProvider, kZeroUuid, execution_result,
              "Failed to get credentials provider.");
    return execution_result;
  }

  return SuccessExecutionResult();
}

ExecutionResult GcpPrivateKeyFetcherProvider::SignHttpRequest(
    AsyncContext<PrivateKeyFetchingRequest, core::HttpRequest>&
        sign_request_context) noexcept {
  const auto& endpoint = sign_request_context.request->key_vending_endpoint
                             ->private_key_vending_service_endpoint;

  // Fetch a Confidential Space attestation token from the launcher. No nonce is
  // needed for /app/key — the wrapping-key binding only applies to /unwrapKey.
  // The audience is the KMS endpoint (the KMS validation policy does not pin
  // `aud`).
  auto token_or = FetchConfidentialSpaceToken(endpoint, /*nonces=*/{});
  if (!token_or.ok()) {
    auto execution_result = FailureExecutionResult(
        SC_GCP_PRIVATE_KEY_FETCHER_PROVIDER_CREDENTIALS_PROVIDER_NOT_FOUND);
    SCP_ERROR_CONTEXT(kGcpPrivateKeyFetcherProvider, sign_request_context,
                      execution_result,
                      "Failed to fetch Confidential Space token: %s",
                      token_or.status().ToString().c_str());
    sign_request_context.result = execution_result;
    sign_request_context.Finish();
    return execution_result;
  }

  // POST {attestationType:"gcp"} to the iSPIRT KMS /app/key endpoint. The real
  // key material is released by /app/unwrapKey (see the GCP KMS client); /key
  // returns the EncryptionKey envelope (kid + keyEncryptionKeyUri).
  auto http_request = std::make_shared<HttpRequest>();
  http_request->method = HttpMethod::POST;
  http_request->path = std::make_shared<Uri>(endpoint);
  nlohmann::json body;
  body[kAttestationType] = kGcp;
  http_request->body = BytesBuffer(body.dump());
  http_request->headers = std::make_shared<HttpHeaders>();
  http_request->headers->insert(
      {std::string(kAuthorizationHeaderKey),
       absl::StrCat(kBearerTokenPrefix, *token_or)});

  sign_request_context.response = std::move(http_request);
  sign_request_context.result = SuccessExecutionResult();
  sign_request_context.Finish();
  return SuccessExecutionResult();
}

ExecutionResult GcpPrivateKeyFetcherProvider::FetchPrivateKey(
    AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
        private_key_fetching_context) noexcept {
  AsyncContext<PrivateKeyFetchingRequest, HttpRequest>
      sign_http_request_context(
          private_key_fetching_context.request,
          bind(&GcpPrivateKeyFetcherProvider::SignHttpRequestCallback, this,
               private_key_fetching_context, _1),
          private_key_fetching_context);

  return SignHttpRequest(sign_http_request_context);
}

void GcpPrivateKeyFetcherProvider::SignHttpRequestCallback(
    AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
        private_key_fetching_context,
    AsyncContext<PrivateKeyFetchingRequest, HttpRequest>&
        sign_http_request_context) noexcept {
  auto execution_result = sign_http_request_context.result;
  if (!execution_result.Successful()) {
    SCP_ERROR_CONTEXT(kGcpPrivateKeyFetcherProvider,
                      private_key_fetching_context, execution_result,
                      "Failed to sign http request.");
    private_key_fetching_context.result = execution_result;
    private_key_fetching_context.Finish();
    return;
  }

  AsyncContext<HttpRequest, HttpResponse> http_client_context(
      std::move(sign_http_request_context.response),
      bind(&GcpPrivateKeyFetcherProvider::PrivateKeyFetchingCallback, this,
           private_key_fetching_context, _1),
      private_key_fetching_context);
  execution_result = http_client_->PerformRequest(http_client_context);
  if (!execution_result.Successful()) {
    SCP_ERROR_CONTEXT(
        kGcpPrivateKeyFetcherProvider, private_key_fetching_context,
        execution_result,
        "Failed to perform http request to reach endpoint %s.",
        private_key_fetching_context.request->key_vending_endpoint
            ->private_key_vending_service_endpoint.c_str());
    private_key_fetching_context.result = execution_result;
    private_key_fetching_context.Finish();
  }
}

void GcpPrivateKeyFetcherProvider::PrivateKeyFetchingCallback(
    AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
        private_key_fetching_context,
    AsyncContext<HttpRequest, HttpResponse>& http_client_context) noexcept {
  private_key_fetching_context.result = http_client_context.result;
  if (!http_client_context.result.Successful()) {
    SCP_ERROR_CONTEXT(
        kGcpPrivateKeyFetcherProvider, private_key_fetching_context,
        private_key_fetching_context.result, "Failed to fetch private key.");
    private_key_fetching_context.Finish();
    return;
  }

  std::string resp(http_client_context.response->body.bytes->begin(),
                   http_client_context.response->body.bytes->end());

  nlohmann::json private_key_resp;
  try {
    private_key_resp = nlohmann::json::parse(resp);
  } catch (const nlohmann::json::parse_error& e) {
    std::string error_message =
        "Received http response could not be parsed into a JSON: ";
    error_message += e.what();
    SCP_ERROR_CONTEXT(kGcpPrivateKeyFetcherProvider,
                      private_key_fetching_context, http_client_context.result,
                      error_message);
    private_key_fetching_context.result = http_client_context.result;
    private_key_fetching_context.Finish();
    return;
  }
  if (!private_key_resp.contains(kWrappedKid)) {
    SCP_ERROR_CONTEXT(kGcpPrivateKeyFetcherProvider,
                      private_key_fetching_context, http_client_context.result,
                      "/key did not provide the wrappedKid property");
    private_key_fetching_context.result = http_client_context.result;
    private_key_fetching_context.Finish();
    return;
  }
  if (!private_key_resp.contains(kWrapped)) {
    SCP_ERROR_CONTEXT(kGcpPrivateKeyFetcherProvider,
                      private_key_fetching_context, http_client_context.result,
                      "/key did not provide the wrapped property");
    private_key_fetching_context.result = http_client_context.result;
    private_key_fetching_context.Finish();
    return;
  }

  std::string wrapped = private_key_resp[kWrapped];
  BytesBuffer buffer(wrapped);
  PrivateKeyFetchingResponse response;
  auto result =
      PrivateKeyFetchingClientUtils::ParsePrivateKey(buffer, response);
  if (!result.Successful()) {
    SCP_ERROR_CONTEXT(
        kGcpPrivateKeyFetcherProvider, private_key_fetching_context,
        private_key_fetching_context.result, "Failed to parse private key.");
    private_key_fetching_context.result = result;
    private_key_fetching_context.Finish();
    return;
  }

  private_key_fetching_context.response =
      std::make_shared<PrivateKeyFetchingResponse>(response);
  private_key_fetching_context.Finish();
}

std::unique_ptr<PrivateKeyFetcherProviderInterface>
PrivateKeyFetcherProviderFactory::Create(
    HttpClientInterface* http_client,
    RoleCredentialsProviderInterface* role_credentials_provider,
    AuthTokenProviderInterface* auth_token_provider,
    privacy_sandbox::server_common::log::PSLogContext& log_context) {
  return std::make_unique<GcpPrivateKeyFetcherProvider>(
      http_client, auth_token_provider, log_context);
}
}  // namespace google::scp::cpio::client_providers
