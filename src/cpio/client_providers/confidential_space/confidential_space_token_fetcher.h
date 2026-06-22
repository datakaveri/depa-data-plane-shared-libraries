// Copyright (c) iSPIRT / DEPA.
// Licensed under the Apache License, Version 2.0.

#ifndef CPIO_CLIENT_PROVIDERS_CONFIDENTIAL_SPACE_TOKEN_FETCHER_H_
#define CPIO_CLIENT_PROVIDERS_CONFIDENTIAL_SPACE_TOKEN_FETCHER_H_

#include <string>
#include <vector>

#include "absl/status/statusor.h"

namespace google::scp::cpio::client_providers {

// Fetches a GCP Confidential Space OIDC attestation token from the local
// launcher's token endpoint.
//
// The token is issued by `https://confidentialcomputing.googleapis.com` and
// carries the Confidential Space attestation claims (swname, hwmodel,
// submods.container.image_digest, etc.) plus any supplied `nonces` echoed back
// in the `eat_nonce` claim. This is NOT the GCE metadata instance-identity
// token (issuer accounts.google.com) — that token lacks the attestation
// claims, so the iSPIRT KMS cannot authorize on it.
//
// Transport: HTTP POST to `http://localhost/v1/token` over the launcher Unix
// domain socket `/run/container_launcher/teeserver.sock` with JSON body
//   { "audience": <audience>, "token_type": "OIDC", "nonces": [<nonces>] }
// CPIO's HTTP/2 client is TCP-only, so this uses libcurl with
// CURLOPT_UNIX_SOCKET_PATH.
//
// @param audience  Token audience (e.g. the KMS endpoint URL). Required by the
//                  launcher for OIDC tokens; the KMS validation policy does not
//                  pin `aud`.
// @param nonces    Values echoed into `eat_nonce`. For /app/unwrapKey this is
//                  the lowercase hex SHA-256 of the RSA wrapping public key PEM;
//                  for /app/key it is empty.
// @return the raw OIDC token (JWT) string, or an error.
absl::StatusOr<std::string> FetchConfidentialSpaceToken(
    const std::string& audience, const std::vector<std::string>& nonces);

}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_CONFIDENTIAL_SPACE_TOKEN_FETCHER_H_
