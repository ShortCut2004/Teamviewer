#pragma once
#include <string>
#include <vector>
#include <iostream>
#include "json.hpp"
#include "map"
#include "MessageData.h"
#include "sqlite3.h"
#include <winsock2.h>
#include <ws2tcpip.h>

using namespace nlohmann;

typedef std::vector<unsigned char> buffer;

#define ERROR_CODE 41
#define LENGTH_OF_BYTE_SIZE 4 
#define SIZE_OF_BYTE 256

typedef struct verificationFirstPhaseResponse
{
    unsigned int verificationResponseStatus;
    std::string encryptionKey;
}verificationFirstPhaseResponse;

typedef struct loginResponse
{
    unsigned int loginResponseStatus;
    std::string srpGroup;
    std::string salt;
}loginResponse;

typedef struct signUpResponse
{
    unsigned int signUpResponseStatus;
}signUpResponse;

typedef struct errorResponse
{
    std::string error;
}errorResponse;

typedef struct LogoutResponse
{
    unsigned int LogoutResponseStatus;
}LogoutResponse;

typedef struct SignoutResponse
{
    unsigned int SignoutResponseStatus;
}SignoutResponse;

typedef struct keyResponse
{
    std::string key;
}keyResponse;

typedef struct registrationResponse
{
    unsigned int registrationResult;
}registrationResponse;

class JsonResponsePacketSerializer
{
public:

    static buffer serialize(json j, int size, char code, const char* jStrByte);
    static buffer serializeRegistrationResponse(registrationResponse RegistrationResponse);
    static buffer serializeLoginResponse(loginResponse LoginResponse);
    static buffer serializeSaltAndSrpGroupReqestResponse(loginResponse LoginResponse);
    static buffer serializeErrorResponse(errorResponse ErrorResponse);
    static buffer serializeKeyResponse(keyResponse KeyResponse);
    static buffer serializeFirstPhaseOfVerificationMessageResponse(verificationFirstPhaseResponse VerificationFirstPhaseResponse);
    static buffer serializeSecondPhaseOfVerificationMessageResponse(std::string code);
    static buffer serializeLogoutResponse(LogoutResponse logoutResponse);
    static buffer serializeSignoutResponse(SignoutResponse signoutResponse);
    static buffer serializeIpRequestResponse(std::string userIp);
    static buffer serializeIpRequestFromPeer(std::string& peerUserName);
    static buffer serializeSocketForIpRequestFromPeer(SOCKET& socket, std::string& username, std::string& peerUsername);
    static buffer serializeInitiateListeningResponse(int code);
    static buffer serializeRequestSentSuccessfully();
    static buffer serializeCancelRequestResponse(std::string code);
};