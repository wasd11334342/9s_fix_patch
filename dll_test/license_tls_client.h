#pragma once

#include <string>

namespace LicenseTlsClient
{
enum class Error
{
    None,
    InvalidArgument,
    ResourceError,
    EntropyError,
    CertificateError,
    ConnectError,
    TlsSetupError,
    TlsHandshakeError,
    IoError,
    ProtocolError,
    ResponseTooLarge
};

struct Response
{
    Error error = Error::ProtocolError;
    unsigned statusCode = 0;
    std::string body;
    int detail = 0;

    bool Ok() const
    {
        return error == Error::None;
    }
};

Response PostJson(
    const char* host,
    const char* path,
    const char* apiKey,
    const std::string& body);
}
