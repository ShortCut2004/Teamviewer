#pragma once
#include <string>
#include <vector>
#include <iostream>
#include "IRequestHandler.h"
#include "json.hpp"
#include <cctype>

using namespace nlohmann;

typedef std::vector<unsigned char> buffer;

typedef struct logInRequest
{
	std::string username;
	std::string srpGroup;
	std::string salt;
}logInRequest;

typedef struct userData
{
	int user_id = 0;
	std::string username;
	std::string peerUsername;
	std::string verifier;
	std::string srpGroup;
	std::string email;
	std::string salt;
	std::string encryptionKey;
	std::string decryptionKey;
	std::string ip;
	std::string peerIp;
	int socket;
}userData;


typedef struct logOutRequest
{
	std::string username;
}logOutRequest;

typedef struct signOutRequest
{
	std::string username;
}signOutRequest;


class IRequestHandler;
class loginRequestHandler;

class JsonRequestPacketDeserializer
{
public:

	static userData deserializeLoginRequest(buffer& buffer);
	static userData deserializeSignupRequest(buffer& buffer);
	static logOutRequest deserializelogOutRequestRequest(buffer& buffer);
	static signOutRequest deserializeSignOutRequestRequest(buffer& buffer);
	static userData deserializeSaltAndSrpGroupRequest(buffer& buffer);
	static userData deserializeSecondPhaseMessageVerificationResponse(buffer& buffer);
	static std::string deserializeKeyResponse(buffer& buffer);
	static int deserializeMessageCode(buffer buffer);
	static json getMessageFromVector(buffer& vectorToGetFrom);
	static userData deserializeSocketForIpRequest(buffer& buffer);
	static userData deserializeIpResponseMessage(buffer& buffer);
	static userData deserializeIpRequestMessage(buffer& buffer);
	static userData deserializeInitiateListening(buffer& buffer);
	static userData deserializeCheckRequest(buffer& buffer);

private:
	static json parseString(std::string& data);
};
