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

#ifndef CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_GCP_GCP_PRIVATE_KEY_FETCHER_PROVIDER_H_
#define CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_GCP_GCP_PRIVATE_KEY_FETCHER_PROVIDER_H_

#include <memory>
#include <string>

#include "src/core/interface/async_context.h"
#include "src/cpio/client_providers/interface/auth_token_provider_interface.h"
#include "src/cpio/client_providers/private_key_fetcher_provider/private_key_fetcher_provider.h"
#include "src/public/core/interface/execution_result.h"

#include "error_codes.h"

namespace google::scp::cpio::client_providers {
/*! @copydoc PrivateKeyFetcherProviderInterface
 *
 * GCP Confidential Space variant that talks to the iSPIRT/DEPA KMS
 * (`POST /app/key?fmt=tink`) instead of Google's Privacy Sandbox coordinator.
 * Authorization is a Confidential Space OIDC attestation token
 * (issuer confidentialcomputing.googleapis.com) carried as a Bearer header;
 * the response is the iSPIRT `{wrappedKid, wrapped}` envelope, parsed the same
 * way as the Azure provider.
 */
class GcpPrivateKeyFetcherProvider : public PrivateKeyFetcherProvider {
 public:
  /**
   * @brief Constructs a new GCP Private Key Fetching Client Provider object.
   *
   * @param http_client http client to issue http requests.
   * @param auth_token_provider auth token provider (retained for interface
   *        compatibility; the Confidential Space token is fetched directly from
   *        the launcher socket).
   */
  GcpPrivateKeyFetcherProvider(
      core::HttpClientInterface* http_client,
      AuthTokenProviderInterface* auth_token_provider,
      privacy_sandbox::server_common::log::PSLogContext& log_context =
          const_cast<privacy_sandbox::server_common::log::NoOpContext&>(
              privacy_sandbox::server_common::log::kNoOpContext))
      : PrivateKeyFetcherProvider(http_client, log_context),
        auth_token_provider_(auth_token_provider) {}

  core::ExecutionResult Init() noexcept override;

  core::ExecutionResult FetchPrivateKey(
      core::AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
          private_key_fetching_context) noexcept override;

  core::ExecutionResult SignHttpRequest(
      core::AsyncContext<PrivateKeyFetchingRequest, core::HttpRequest>&
          sign_http_request_context) noexcept override;

 protected:
  /**
   * @brief Triggered to fetch private key when http request is signed.
   */
  void SignHttpRequestCallback(
      core::AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
          private_key_fetching_context,
      core::AsyncContext<PrivateKeyFetchingRequest, core::HttpRequest>&
          sign_http_request_context) noexcept;

  /**
   * @brief Triggered to parse private key when private key payload is fetched.
   */
  void PrivateKeyFetchingCallback(
      core::AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
          private_key_fetching_context,
      core::AsyncContext<core::HttpRequest, core::HttpResponse>&
          http_client_context) noexcept;

 private:
  // Auth token provider (retained for factory/interface compatibility; the
  // Confidential Space attestation token is fetched from the launcher socket).
  AuthTokenProviderInterface* auth_token_provider_;
};
}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_GCP_GCP_PRIVATE_KEY_FETCHER_PROVIDER_H_
