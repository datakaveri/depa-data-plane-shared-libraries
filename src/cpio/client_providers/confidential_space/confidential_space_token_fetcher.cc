// Copyright (c) iSPIRT / DEPA.
// Licensed under the Apache License, Version 2.0.

#include "confidential_space_token_fetcher.h"

#include <curl/curl.h>

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"

namespace google::scp::cpio::client_providers {
namespace {

// Confidential Space launcher token endpoint, reached over the launcher's
// Unix domain socket. See
// https://cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources
constexpr char kTeeSocketPath[] = "/run/container_launcher/teeserver.sock";
constexpr char kTokenUrl[] = "http://localhost/v1/token";
constexpr long kRequestTimeoutSeconds = 10L;

size_t WriteResponseCallback(char* ptr, size_t size, size_t nmemb,
                             void* userdata) {
  auto* out = static_cast<std::string*>(userdata);
  const size_t total = size * nmemb;
  out->append(ptr, total);
  return total;
}

}  // namespace

absl::StatusOr<std::string> FetchConfidentialSpaceToken(
    const std::string& audience, const std::vector<std::string>& nonces) {
  nlohmann::json body;
  body["audience"] = audience;
  body["token_type"] = "OIDC";
  if (!nonces.empty()) {
    body["nonces"] = nonces;
  }
  const std::string body_str = body.dump();

  CURL* curl = curl_easy_init();
  if (curl == nullptr) {
    return absl::InternalError("curl_easy_init() failed");
  }

  std::string response;
  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");

  curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, kTeeSocketPath);
  curl_easy_setopt(curl, CURLOPT_URL, kTokenUrl);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                   static_cast<long>(body_str.size()));
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteResponseCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, kRequestTimeoutSeconds);

  const CURLcode res = curl_easy_perform(curl);
  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) {
    return absl::InternalError(
        absl::StrCat("Confidential Space token request failed: ",
                     curl_easy_strerror(res)));
  }
  if (http_code != 200) {
    return absl::InternalError(
        absl::StrCat("Confidential Space token endpoint returned HTTP ",
                     http_code, ": ", response));
  }
  if (response.empty()) {
    return absl::InternalError(
        "Confidential Space token endpoint returned an empty body");
  }
  // The launcher returns the raw OIDC token (JWT) as the response body.
  return response;
}

}  // namespace google::scp::cpio::client_providers
