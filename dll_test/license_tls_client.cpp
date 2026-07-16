#include "license_tls_client.h"
#include "license_tls_resources.h"

#include <windows.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace LicenseTlsClient
{
namespace
{
constexpr size_t kMaximumResponseBytes = 32768;
constexpr uint32_t kReadTimeoutMs = 7000;
int g_resourceAnchor = 0;

class TlsContext
{
public:
    TlsContext()
    {
        mbedtls_net_init(&socket);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&config);
        mbedtls_x509_crt_init(&caChain);
        mbedtls_ctr_drbg_init(&ctrDrbg);
        mbedtls_entropy_init(&entropy);
    }

    ~TlsContext()
    {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&config);
        mbedtls_x509_crt_free(&caChain);
        mbedtls_ctr_drbg_free(&ctrDrbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_net_free(&socket);
    }

    mbedtls_net_context socket{};
    mbedtls_ssl_context ssl{};
    mbedtls_ssl_config config{};
    mbedtls_x509_crt caChain{};
    mbedtls_ctr_drbg_context ctrDrbg{};
    mbedtls_entropy_context entropy{};
};

bool LoadCaBundle(std::vector<unsigned char>& bundle)
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&g_resourceAnchor),
            &module)) {
        return false;
    }

    HRSRC resource = FindResourceW(
        module,
        MAKEINTRESOURCEW(IDR_LICENSE_CA_BUNDLE),
        MAKEINTRESOURCEW(10)); // RT_RCDATA
    if (!resource) {
        return false;
    }
    HGLOBAL loaded = LoadResource(module, resource);
    const DWORD size = SizeofResource(module, resource);
    const void* data = loaded ? LockResource(loaded) : nullptr;
    if (!data || size == 0) {
        return false;
    }

    const unsigned char* begin = static_cast<const unsigned char*>(data);
    bundle.assign(begin, begin + size);
    bundle.push_back(0); // PEM parser requires a terminating NUL included in the length.
    return true;
}

bool WriteAll(mbedtls_ssl_context& ssl, const std::string& request, int& detail)
{
    size_t sent = 0;
    while (sent < request.size()) {
        const int result = mbedtls_ssl_write(
            &ssl,
            reinterpret_cast<const unsigned char*>(request.data() + sent),
            request.size() - sent);
        if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (result <= 0) {
            detail = result;
            return false;
        }
        sent += static_cast<size_t>(result);
    }
    return true;
}

bool ReadAll(mbedtls_ssl_context& ssl, std::string& response, Error& error, int& detail)
{
    response.clear();
    unsigned char buffer[2048]{};
    for (;;) {
        const int result = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer));
        if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (result == 0 || result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            return true;
        }
        if (result < 0) {
            detail = result;
            error = Error::IoError;
            return false;
        }
        if (response.size() + static_cast<size_t>(result) > kMaximumResponseBytes) {
            error = Error::ResponseTooLarge;
            return false;
        }
        response.append(reinterpret_cast<const char*>(buffer), static_cast<size_t>(result));
    }
}

bool ContainsChunkedEncoding(const std::string& headers)
{
    std::string lowered = headers;
    for (char& ch : lowered) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    const size_t transfer = lowered.find("\r\ntransfer-encoding:");
    return transfer != std::string::npos && lowered.find("chunked", transfer) != std::string::npos;
}

bool DecodeChunked(const std::string& input, std::string& output)
{
    output.clear();
    size_t cursor = 0;
    while (cursor < input.size()) {
        const size_t lineEnd = input.find("\r\n", cursor);
        if (lineEnd == std::string::npos) {
            return false;
        }
        const std::string sizeText = input.substr(cursor, lineEnd - cursor);
        char* parseEnd = nullptr;
        const unsigned long chunkSize = std::strtoul(sizeText.c_str(), &parseEnd, 16);
        if (parseEnd == sizeText.c_str() || (*parseEnd != '\0' && *parseEnd != ';')) {
            return false;
        }
        cursor = lineEnd + 2;
        if (chunkSize == 0) {
            return true;
        }
        if (chunkSize > input.size() - cursor || output.size() + chunkSize > kMaximumResponseBytes) {
            return false;
        }
        output.append(input, cursor, chunkSize);
        cursor += chunkSize;
        if (cursor + 2 > input.size() || input.compare(cursor, 2, "\r\n") != 0) {
            return false;
        }
        cursor += 2;
    }
    return false;
}

bool ParseHttpResponse(
    const std::string& response,
    unsigned& statusCode,
    std::string& body)
{
    const size_t statusSpace = response.find(' ');
    const size_t statusLineEnd = response.find("\r\n");
    if (response.compare(0, 5, "HTTP/") != 0 || statusSpace == std::string::npos ||
        statusLineEnd == std::string::npos || statusSpace >= statusLineEnd) {
        return false;
    }

    char* statusEnd = nullptr;
    const unsigned long parsedStatus = std::strtoul(response.c_str() + statusSpace + 1, &statusEnd, 10);
    if (!statusEnd || parsedStatus < 100 || parsedStatus > 999) {
        return false;
    }

    const size_t headerEnd = response.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        return false;
    }
    statusCode = static_cast<unsigned>(parsedStatus);

    const std::string encodedBody = response.substr(headerEnd + 4);
    const std::string headers = response.substr(0, headerEnd + 2);
    if (ContainsChunkedEncoding(headers)) {
        return DecodeChunked(encodedBody, body);
    }
    body = encodedBody;
    return true;
}
}

Response PostJson(
    const char* host,
    const char* path,
    const char* apiKey,
    const std::string& body)
{
    Response response{};
    if (!host || !*host || !path || !*path || !apiKey || !*apiKey) {
        response.error = Error::InvalidArgument;
        return response;
    }

    TlsContext tls;
    std::vector<unsigned char> caBundle;
    if (!LoadCaBundle(caBundle)) {
        response.error = Error::ResourceError;
        response.detail = static_cast<int>(GetLastError());
        return response;
    }

    int result = mbedtls_x509_crt_parse(&tls.caChain, caBundle.data(), caBundle.size());
    if (result < 0) {
        response.error = Error::CertificateError;
        response.detail = result;
        return response;
    }

    constexpr char personalization[] = "MyPatch-License-TLS";
    result = mbedtls_ctr_drbg_seed(
        &tls.ctrDrbg,
        mbedtls_entropy_func,
        &tls.entropy,
        reinterpret_cast<const unsigned char*>(personalization),
        sizeof(personalization) - 1);
    if (result != 0) {
        response.error = Error::EntropyError;
        response.detail = result;
        return response;
    }

    result = mbedtls_net_connect(&tls.socket, host, "443", MBEDTLS_NET_PROTO_TCP);
    if (result != 0) {
        response.error = Error::ConnectError;
        response.detail = result;
        return response;
    }

    result = mbedtls_ssl_config_defaults(
        &tls.config,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    if (result != 0) {
        response.error = Error::TlsSetupError;
        response.detail = result;
        return response;
    }

    mbedtls_ssl_conf_authmode(&tls.config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&tls.config, &tls.caChain, nullptr);
    mbedtls_ssl_conf_rng(&tls.config, mbedtls_ctr_drbg_random, &tls.ctrDrbg);
    mbedtls_ssl_conf_read_timeout(&tls.config, kReadTimeoutMs);
    mbedtls_ssl_conf_min_tls_version(&tls.config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&tls.config, MBEDTLS_SSL_VERSION_TLS1_2);

    result = mbedtls_ssl_setup(&tls.ssl, &tls.config);
    if (result == 0) {
        result = mbedtls_ssl_set_hostname(&tls.ssl, host);
    }
    if (result != 0) {
        response.error = Error::TlsSetupError;
        response.detail = result;
        return response;
    }

    mbedtls_ssl_set_bio(
        &tls.ssl,
        &tls.socket,
        mbedtls_net_send,
        mbedtls_net_recv,
        mbedtls_net_recv_timeout);

    do {
        result = mbedtls_ssl_handshake(&tls.ssl);
    } while (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (result != 0) {
        response.error = Error::TlsHandshakeError;
        response.detail = result;
        return response;
    }

    std::string request;
    request.reserve(body.size() + std::strlen(apiKey) + 256);
    request += "POST ";
    request += path;
    request += " HTTP/1.1\r\nHost: ";
    request += host;
    request += "\r\nUser-Agent: MyPatch-License/2.0\r\nContent-Type: application/json\r\nx-api-key: ";
    request += apiKey;
    request += "\r\nContent-Length: ";
    request += std::to_string(body.size());
    request += "\r\nConnection: close\r\n\r\n";
    request += body;

    if (!WriteAll(tls.ssl, request, response.detail)) {
        response.error = Error::IoError;
        return response;
    }

    std::string rawResponse;
    if (!ReadAll(tls.ssl, rawResponse, response.error, response.detail)) {
        return response;
    }
    mbedtls_ssl_close_notify(&tls.ssl);

    if (!ParseHttpResponse(rawResponse, response.statusCode, response.body)) {
        response.error = Error::ProtocolError;
        return response;
    }
    response.error = Error::None;
    return response;
}
}
