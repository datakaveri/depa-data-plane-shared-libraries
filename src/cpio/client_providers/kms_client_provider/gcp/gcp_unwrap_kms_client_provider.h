// Copyright (c) iSPIRT / DEPA.
// Licensed under the Apache License, Version 2.0.

#ifndef CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_GCP_GCP_UNWRAP_KMS_CLIENT_PROVIDER_H_
#define CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_GCP_GCP_UNWRAP_KMS_CLIENT_PROVIDER_H_

#include <memory>
#include <string>
#include <utility>

#include "src/core/interface/async_context.h"
#include "src/cpio/client_providers/interface/kms_client_provider_interface.h"
#include "src/cpio/client_providers/kms_client_provider/azure/azure_kms_client_provider_utils.h"
#include "src/public/core/interface/execution_result.h"

namespace google::scp::cpio::client_providers {

/*! @copydoc KmsClientProviderInterface
 *
 * GCP Confidential Space variant that decrypts (unwraps) HPKE private key
 * material against the iSPIRT/DEPA KMS `POST /app/unwrapKey?fmt=tink`, instead
 * of Google Cloud KMS.
 *
 * Flow (synchronous, mirrors the Azure provider but with a Confidential Space
 * OIDC token instead of an SNP report):
 *   1. Generate an ephemeral RSA wrapping key pair.
 *   2. Compute hex(SHA-256(wrappingPubKey PEM)).
 *   3. Fetch a Confidential Space attestation token with nonce = that hash,
 *      so the KMS can bind the wrapping key to this TEE via the JWT eat_nonce.
 *   4. POST {wrapped, wrappedKid, wrappingKey(PEM), attestationType:"gcp"} with
 *      Authorization: Bearer <token>.
 *   5. RSA-OAEP-unwrap the response with the ephemeral private key.
 *
 * The reused RSA / PEM / hash / unwrap crypto lives in
 * AzureKmsClientProviderUtils (platform-neutral).
 */
class GcpUnwrapKmsClientProvider : public KmsClientProviderInterface {
 public:
  explicit GcpUnwrapKmsClientProvider(core::HttpClientInterface* http_client)
      : http_client_(http_client), unwrap_url_() {}

  absl::Status Decrypt(
      core::AsyncContext<cmrt::sdk::kms_service::v1::DecryptRequest,
                         cmrt::sdk::kms_service::v1::DecryptResponse>&
          decrypt_context) noexcept override;

 private:
  /**
   * @brief Called when the /app/unwrapKey HTTP response arrives; RSA-unwraps
   * the returned key material with the ephemeral private key.
   */
  void OnDecryptCallback(
      core::AsyncContext<cmrt::sdk::kms_service::v1::DecryptRequest,
                         cmrt::sdk::kms_service::v1::DecryptResponse>&
          decrypt_context,
      std::shared_ptr<EvpPkeyWrapper> ephemeral_private_key,
      core::AsyncContext<core::HttpRequest, core::HttpResponse>&
          http_client_context) noexcept;

  core::HttpClientInterface* http_client_;
  std::string unwrap_url_;
};
}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_KMS_CLIENT_PROVIDER_GCP_GCP_UNWRAP_KMS_CLIENT_PROVIDER_H_
