#include "JsonResponsePacketSerializer.h"

/*
Serializes the given json object, size, code and jStrByte into a buffer and returns it.

input:
j: The json object to serialize.
size: The size of the serialized object.
code: The message type code to attach to the serialized object.
jStrByte: A character pointer to the serialized json object.

output:
A buffer containing the serialized json object.

throws:
N/A
*/
buffer JsonResponsePacketSerializer::serialize(json j, int size, char code, const char* jStrByte)
{
	char sizeIntArr[LENGTH_OF_BYTE_SIZE];
	buffer vec;
	std::string sizeBytesStr;
	std::string msg;


	for (int i = LENGTH_OF_BYTE_SIZE - 1; i >= 0; i--)
	{
		sizeIntArr[i] = size % SIZE_OF_BYTE;
		size = size / SIZE_OF_BYTE;
	}
	for (int i = 0; i < LENGTH_OF_BYTE_SIZE; i++)
	{
		sizeBytesStr += sizeIntArr[i];
	}
	msg = code + sizeBytesStr + jStrByte;
	for (int i = 0; i < (int)msg.length(); i++)
	{
		vec.push_back(msg[i]);
	}
	return vec;
}

/*
Serialize the registration response as a buffer

input:

RegistrationResponse: registrationResponse struct that holds the response information
output:

buffer: serialized buffer containing the registration response
*/
buffer JsonResponsePacketSerializer::serializeRegistrationResponse(registrationResponse RegistrationResponse)
{
	if (RegistrationResponse.registrationResult)
	{
		json j;
		std::string jStr;
		const char* jStrByte;
		int size;
		j["code"] = std::to_string(SUCCESSFUL_REGISTRATION);
		jStr = j.dump();
		jStrByte = jStr.c_str();
		size = strlen(jStrByte);

		return serialize(j, size, (char)SUCCESSFUL_REGISTRATION, jStrByte);
	}
	errorResponse err = errorResponse();
	err.error = "problem with registration";
	return serializeErrorResponse(err);
}

/*
Serializes a login response object into a buffer that can be sent over the network.

input:
LoginResponse: a loginResponse object containing the status of the login operation and a salt value.

output:
buffer: a vector of bytes representing the serialized login response.
*/
buffer JsonResponsePacketSerializer::serializeLoginResponse(loginResponse LoginResponse)
{
	json j;
	std::string jStr;
	const char* jStrByte;
	int size;

	j["code"] = std::to_string(LoginResponse.loginResponseStatus);
	j["salt"] = LoginResponse.salt;
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)LoginResponse.loginResponseStatus, jStrByte);
}

/*
The function serializeSaltAndSrpGroupReqestResponse takes a loginResponse object and returns a serialized JSON message as a buffer. The message contains the response code, salt, and SRP group of the login response.

Input:
loginResponse LoginResponse: A loginResponse object that contains the response code, salt, and SRP group of the login response.

Output:
buffer: A serialized JSON message as a buffer. The message contains the response code, salt, and SRP group of the login response.
*/
buffer JsonResponsePacketSerializer::serializeSaltAndSrpGroupReqestResponse(loginResponse LoginResponse)
{
	json j;
	std::string jStr;
	const char* jStrByte;
	int size;

	j["code"] = std::to_string(LoginResponse.loginResponseStatus);
	j["salt"] = LoginResponse.salt;
	j["srp_group"] = LoginResponse.srpGroup;
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)LoginResponse.loginResponseStatus, jStrByte);
}

/*
Serialize an error response as a buffer

input:
errorResponse ErrorResponse - errorResponse struct that holds the error message

output:
buffer - serialized buffer containing the error message response
*/
buffer JsonResponsePacketSerializer::serializeErrorResponse(errorResponse ErrorResponse)
{
	json j;
	std::string jStr;
	const char* jStrByte;
	int size;

	j["code"] = std::to_string(ERROR_CODE);
	j["message"] = ErrorResponse.error;
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, ERROR_CODE, jStrByte);
}

/*
Serialize the key response as a buffer

input:
keyResponse KeyResponse - keyResponse struct that holds the response information

output:
buffer: - serialized buffer containing the key response
*/
buffer JsonResponsePacketSerializer::serializeKeyResponse(keyResponse KeyResponse)
{
	json j;
	std::string jStr;
	const char* jStrByte;
	int size;

	j["code"] = std::to_string(INITIAL_KEYS);
	j["encryption_key"] = KeyResponse.key;
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)INITIAL_KEYS, jStrByte);
}

/*
Serialize the first phase of verification message response as a buffer

input:

verificationFirstPhaseResponse VerificationFirstPhaseResponse - verificationFirstPhaseResponse struct that holds the response information

output:

buffer: - serialized buffer containing the first phase of verification response
*/
buffer JsonResponsePacketSerializer::serializeFirstPhaseOfVerificationMessageResponse(verificationFirstPhaseResponse VerificationFirstPhaseResponse)
{
	json j;
	std::string jStr;
	const char* jStrByte;
	int size;

	j["code"] = std::to_string(VerificationFirstPhaseResponse.verificationResponseStatus);
	j["encryption_key"] = VerificationFirstPhaseResponse.encryptionKey;
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)VerificationFirstPhaseResponse.verificationResponseStatus, jStrByte);
}

/*
Serialize the second phase of the verification message response as a buffer

input:
std::string code - the code of the response

output:
buffer: - serialized buffer containing the second phase of the verification message response
*/
buffer JsonResponsePacketSerializer::serializeSecondPhaseOfVerificationMessageResponse(std::string code)
{
	json j;
	std::string jStr;
	const char* jStrByte;
	int size;

	j["code"] = code;
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)code.c_str(), jStrByte);
}

/*
Serialize the cancel request response as a buffer

input:
std::string code - the code of the response

output:
buffer: - serialized buffer containing the cancel request response
*/
buffer JsonResponsePacketSerializer::serializeCancelRequestResponse(std::string code)
{
	json j;
	std::string jStr;
	const char* jStrByte;
	int size;

	j["code"] = code;
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)code.c_str(), jStrByte);
}

/*
Serialize the IP request response as a buffer

input:

std::string userIp: the IP address of the user
output:

buffer: serialized buffer containing the IP request response
*/
buffer JsonResponsePacketSerializer::serializeIpRequestResponse(std::string userIp)
{
	json j;
	std::string jStr;
	const char* jStrByte;
	int size;

	j["code"] = std::to_string(IP_RESPONSE);
	j["ip"] = userIp;
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)IP_RESPONSE, jStrByte);
}

/*
Serialize a response indicating that a request has been sent successfully

input: none

output:
buffer: serialized buffer containing the response indicating that a request has been sent successfully
*/
buffer JsonResponsePacketSerializer::serializeRequestSentSuccessfully()
{
	json j;
	std::string jStr;
	const char* jStrByte;
	int size;

	j["code"] = std::to_string(REQUEST_SENT_SUCCESSFULLY);
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)REQUEST_SENT_SUCCESSFULLY, jStrByte);
}

/*
Serialize an IP request from peer as a buffer

input:
std::string& peerUserName - the username of the requesting peer

output:
buffer - serialized buffer containing the IP request from peer
*/
buffer JsonResponsePacketSerializer::serializeIpRequestFromPeer(std::string& peerUserName)
{
	json j;
	std::string jStr;
	const char* jStrByte;
	int size;

	j["code"] = std::to_string(IP_REQUEST_FROM_PEER);
	j["peer_user_name"] = peerUserName;
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)IP_REQUEST_FROM_PEER, jStrByte);
}

/*
Serialize the socket for IP request from peer as a buffer

input:
SOCKET& socket - socket number to be sent
std::string& username - the username of the client that initiated the request
std::string& peerUsername - the username of the peer client that the request was sent to

output:
buffer: - serialized buffer containing the socket for IP request from peer
*/
buffer JsonResponsePacketSerializer::serializeSocketForIpRequestFromPeer(SOCKET& socket, std::string& username, std::string& peerUsername)
{
	json j;
	std::string jStr;
	const char* jStrByte;
	int size, socketNumber = 0;

	j["peer_user_name"] = username;
	j["user_name"] = peerUsername;
	j["socket"] = std::to_string((int)socket);
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)IP_REQUEST_FROM_PEER, jStrByte);
}

/*
Serialize the logout response as a buffer

input:
LogoutResponse logoutResponse - struct containing the response information

output:
buffer - serialized buffer containing the logout response
*/
buffer JsonResponsePacketSerializer::serializeLogoutResponse(LogoutResponse logoutResponse)
{
	json j;
	std::string msg;
	std::string jStr;
	const char* jStrByte;
	int size;
	std::vector<unsigned char> vec;
	char sizeIntArr[LENGTH_OF_BYTE_SIZE];
	std::string sizeBytesStr;

	j["code"] = std::to_string(logoutResponse.LogoutResponseStatus);
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)logoutResponse.LogoutResponseStatus, jStrByte);
}

/*
Serialize the signout response as a buffer

input:
SignoutResponse signoutResponse - SignoutResponse struct containing the response information

output:
buffer - serialized buffer containing the signout response
*/
buffer JsonResponsePacketSerializer::serializeSignoutResponse(SignoutResponse signoutResponse)
{
	json j;
	std::string msg;
	std::string jStr;
	const char* jStrByte;
	int size;
	std::string sizeBytesStr;

	j["code"] = std::to_string(signoutResponse.SignoutResponseStatus);
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)signoutResponse.SignoutResponseStatus, jStrByte);
}

/*
Serialize the initiate listening response as a buffer

input:
int code - the code that represents the response status

output:
buffer: - serialized buffer containing the initiate listening response
*/
buffer JsonResponsePacketSerializer::serializeInitiateListeningResponse(int code)
{
	json j;
	std::string msg;
	std::string jStr;
	const char* jStrByte;
	int size;
	std::string sizeBytesStr;

	j["code"] = std::to_string(code);
	jStr = j.dump();
	jStrByte = jStr.c_str();
	size = strlen(jStrByte);

	return serialize(j, size, (char)code, jStrByte);
}