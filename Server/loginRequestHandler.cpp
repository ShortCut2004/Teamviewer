#include "loginRequestHandler.h"

/*
Construct a new login request handler

input:
Database* database - pointer to the database instance
LoginManager* loginManager - pointer to the login manager instance
RequestHandlerFactory* handleFactory - pointer to the request handler factory instance

output:
none
*/
loginRequestHandler::loginRequestHandler(Database* database, LoginManager* loginManager, RequestHandlerFactory* handleFactory)
	: _db(database), m_loginManager(loginManager), m_handleFactory(handleFactory)
{}

/*
Checks whether the request is relevant to the login request handler

input:
requestInfo reqInfo - struct containing the id of the request

output:
bool - true if the request is relevant to the login request handler, false otherwise
*/
bool loginRequestHandler::isRequestRelevant(requestInfo reqInfo)
{
	if (reqInfo.id == CHECK_FOR_REQUEST || reqInfo.id == CANCEL_REQUEST || reqInfo.id == STOP_LISTENING || reqInfo.id == LISTEN_REQUEST || reqInfo.id == SALT_REQUEST || reqInfo.id == VERIFICATION_MESSAGE || reqInfo.id == EXCHANGE_NEW_KEYS || reqInfo.id == INITIAL_KEYS || reqInfo.id == REGISTRATION || reqInfo.id == LOG_IN || reqInfo.id == SIGN_OUT || reqInfo.id == LOG_OUT || reqInfo.id == IP_REQUEST || reqInfo.id == IP_RESPONSE_FROM_PEER)
	{
		return true;
	}
	return false;
}

/*
Handles the incoming request

input:
requestInfo reqInfo - struct containing the request information, such as the request ID, buffer

output:
requestResult - struct containing the data of the response and the handler responsible for it
*/
requestResult loginRequestHandler::handleRequest(requestInfo reqInfo, std::map<std::string, std::string>& m_clientsIp, std::map <std::string, SOCKET>& m_clientsSocket, SOCKET& socket, std::list<std::string>& listeningList, std::map<std::string, std::string>& m_clientsInitiatingRequestForIp)
{
	std::vector<unsigned char> dataBeforeEncryption;

	switch (reqInfo.id)
	{
	case INITIAL_KEYS:
		return createExchangeKeys(reqInfo);
		break;
	case LOG_IN:
		return login(reqInfo);
		break;
	case LOG_OUT:
		return logout(reqInfo);
		break;
	case REGISTRATION:
		return signUp(reqInfo);
		break;
	case SIGN_OUT:
		return signOut(reqInfo);
		break;
	case SALT_REQUEST:
		return handleSaltAndSrpGroupRequest(reqInfo);
		break;
	case EXCHANGE_NEW_KEYS:
		return handleFirstPhaseVerification(reqInfo);
		break;
	case VERIFICATION_MESSAGE:
		return handleSecondPhaseVerification(reqInfo, m_clientsIp, m_clientsSocket, socket);
		break;
	case IP_REQUEST:
		return sendRequestIpToPeer(reqInfo, m_clientsSocket, listeningList);
		break;
	case IP_RESPONSE_FROM_PEER:
		return ipRequestAnswer(reqInfo, m_clientsIp, m_clientsInitiatingRequestForIp, m_clientsSocket, listeningList);
		break;
	case LISTEN_REQUEST:
		return initiateListening(reqInfo, listeningList);
		break;
	case STOP_LISTENING:
		return removeFromListeningList(reqInfo, listeningList);
		break;
	case CHECK_FOR_REQUEST:
		return checkForRequest(reqInfo, m_clientsInitiatingRequestForIp, m_clientsIp);
		break;
	case CANCEL_REQUEST:
		return cancelRequest(reqInfo, m_clientsInitiatingRequestForIp);
		break;
	default:
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR!" });
		return requestResult{ dataBeforeEncryption, nullptr };
		break;
	}
}

/*
Create a new encryption key pair and send the public key to the client.

Input:
requestInfo reqInfo - struct containing the request information, including the client's public key
stored in the buffer field

Output:
requestResult - a struct containing the serialized buffer with the public key response and a nullptr
for the next handler in the chain
*/
requestResult loginRequestHandler::createExchangeKeys(requestInfo reqInfo)
{
	keyResponse response = keyResponse();
	std::vector<unsigned char> dataBeforeEncryption, tempKey;

	tempKey = Encryption::base64_decode(JsonRequestPacketDeserializer::deserializeKeyResponse(reqInfo.buffer));
	std::string key(tempKey.begin(), tempKey.end());
	this->m_encryption_key = key;
	Encryption::generate_keypair(response.key, this->m_decryption_key);
	dataBeforeEncryption = JsonResponsePacketSerializer::serializeKeyResponse(response);

	return requestResult{ dataBeforeEncryption, nullptr };
}

/*
Handles the request of a client to log in.

Input:

reqInfo: the request info object containing the request's data
m_loginManager: a pointer to the LoginManager instance that handles the login process
_db: a pointer to the database that stores the users' information
Output:

A requestResult object containing the response to the request.
If the login was successful, the response will contain the user's salt, which is used in the SRP protocol.
If the login failed, an error response is returned.
*/
requestResult loginRequestHandler::login(requestInfo reqInfo)
{
	loginResponse response = loginResponse();
	std::vector<unsigned char> dataBeforeEncryption, output;
	userData data;

	data = JsonRequestPacketDeserializer::deserializeLoginRequest(reqInfo.buffer);
	response.loginResponseStatus = this->m_loginManager->login(data);
	if (response.loginResponseStatus == ERROR)
	{
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR while logging in." });

		return requestResult{ dataBeforeEncryption, nullptr };
	}

	userData dataToSend = _db->getSaltByEmail(data);
	response.salt = dataToSend.salt;
	dataBeforeEncryption = JsonResponsePacketSerializer::serializeLoginResponse(response);

	return requestResult{ dataBeforeEncryption, nullptr };
}

/*
Sign out a user from the system

input:
requestInfo reqInfo - struct containing the request information, including the username of the user to sign out

output:
requestResult - struct containing the result of the request, including a response packet to send back to the client
*/
requestResult loginRequestHandler::signOut(requestInfo reqInfo)
{
	SignoutResponse signOutResponse;
	std::vector<unsigned char> dataBeforeEncryption;

	signOutResponse.SignoutResponseStatus = m_loginManager->signOut(JsonRequestPacketDeserializer::deserializeSignOutRequestRequest(reqInfo.buffer).username);
	if (signOutResponse.SignoutResponseStatus == LOGIN_NOT_OCCURED)
	{
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR while signing out: login didn't occure before." });

		return requestResult{ dataBeforeEncryption, nullptr };
	}
	else if (signOutResponse.SignoutResponseStatus == ERROR)
	{
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR while signing out." });

		return requestResult{ dataBeforeEncryption, nullptr };
	}
	dataBeforeEncryption = JsonResponsePacketSerializer::serializeSignoutResponse(signOutResponse);

	return requestResult{ dataBeforeEncryption, nullptr };
}

/*
Handles a log out request from the client

Input:

requestInfo reqInfo: a struct containing information about the request
int id: an integer representing the ID of the request
std::vector<unsigned char> buffer: a vector of unsigned characters representing the buffer of the request
Output:

requestResult: a struct containing the encrypted response and a pointer to a RequestHandler object or nullptr

std::vector<unsigned char> dataBeforeEncryption: a vector of unsigned characters representing the response before encryption
nullptr: since no RequestHandler object needs to be created in response to a log out request
*/
requestResult loginRequestHandler::logout(requestInfo reqInfo)
{
	LogoutResponse logoutResponse;
	std::vector<unsigned char> dataBeforeEncryption;

	logoutResponse.LogoutResponseStatus = m_loginManager->logout(JsonRequestPacketDeserializer::deserializelogOutRequestRequest(reqInfo.buffer).username);
	if (logoutResponse.LogoutResponseStatus == ERROR)
	{
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR while logging out." });

		return requestResult{ dataBeforeEncryption , nullptr };
	}
	dataBeforeEncryption = JsonResponsePacketSerializer::serializeLogoutResponse(logoutResponse);

	return requestResult{ dataBeforeEncryption , nullptr };
}

/*
Signs up a new user

input:
requestInfo reqInfo - the request data containing user's data such as username, password, and email

output:
requestResult - the response data containing a vector of bytes to be sent over the network and a pointer to a new request handler to handle further requests
*/
requestResult loginRequestHandler::signUp(requestInfo reqInfo)
{
	std::vector<unsigned char> data;
	registrationResponse response = registrationResponse();

	response.registrationResult = this->m_loginManager->signup(JsonRequestPacketDeserializer::deserializeSignupRequest(reqInfo.buffer));
	if (response.registrationResult == ERROR)
	{
		data = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR while signing up." });

		return requestResult{ data , nullptr };
	}
	data = JsonResponsePacketSerializer::serializeRegistrationResponse(response);

	return requestResult{ data, nullptr };
}

/*
Handle the request for the salt and SRP group of a user during the login process

input:
requestInfo reqInfo - struct containing the request information, including the buffer with the email of the user requesting the salt and SRP group

output:
requestResult - struct containing the response data to send back to the client, including the encrypted data and the new socket to use for communication
*/
requestResult loginRequestHandler::handleSaltAndSrpGroupRequest(requestInfo reqInfo)
{
	std::vector<unsigned char> dataBeforeEncryption;
	userData data;

	data = JsonRequestPacketDeserializer::deserializeSaltAndSrpGroupRequest(reqInfo.buffer);
	if (!this->_db->doesEmailExist(data))
	{
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR while checking if the user exists." });
		return requestResult{ dataBeforeEncryption, nullptr };
	}
	data = this->_db->getSaltAndSrpGroupByEmail(data);
	loginResponse dataOfClient;
	dataOfClient.salt = data.salt;
	dataOfClient.srpGroup = data.srpGroup;
	dataOfClient.loginResponseStatus = SUCCESSFUL_SALT_REQUEST;
	dataBeforeEncryption = JsonResponsePacketSerializer::serializeSaltAndSrpGroupReqestResponse(dataOfClient);

	return requestResult{ dataBeforeEncryption, nullptr };
}

/*
Handle the first phase of the verification process

input:
requestInfo reqInfo - information about the request containing the client's public key

output:
requestResult - contains the data of the client for the second phase of the verification process encrypted with the server's public key and a pointer to a ResponseHandler object to handle the response
*/
requestResult loginRequestHandler::handleFirstPhaseVerification(requestInfo reqInfo)
{
	std::vector<unsigned char> dataBeforeEncryption;
	verificationFirstPhaseResponse dataOfClient;

	Encryption::generate_keypair(dataOfClient.encryptionKey, this->m_decryption_key);
	dataOfClient.verificationResponseStatus = EXCHANGE_NEW_KEYS_SUCCESSFUL;
	dataBeforeEncryption = JsonResponsePacketSerializer::serializeFirstPhaseOfVerificationMessageResponse(dataOfClient);
	return requestResult{ dataBeforeEncryption, nullptr };
}

/*
Handles the second phase of the verification process, in which the client sends the username and the encryption key.
If the verifier and srp group are suitable, updates the m_clientsIp and m_clientsSocket maps accordingly.

input:
requestInfo reqInfo - a struct containing the ID of the request and its buffer
std::map<std::string, std::string>& m_clientsIp - a map that stores the clients' IPs
std::map<std::string, SOCKET>& m_clientsSocket - a map that stores the clients' sockets
SOCKET socket - the socket of the client that sent the request

output:
requestResult - a struct containing the response to the client's request and a pointer to a RequestHandler object
*/
requestResult loginRequestHandler::handleSecondPhaseVerification(requestInfo reqInfo, std::map<std::string, std::string>& m_clientsIp, std::map<std::string, SOCKET>& m_clientsSocket, SOCKET socket)
{
	std::vector<unsigned char> dataBeforeEncryption, tempKey;
	userData data;
	std::string tempString = "", fixedJsonMessage = "";
	int i = 0;

	data = JsonRequestPacketDeserializer::deserializeSecondPhaseMessageVerificationResponse(reqInfo.buffer);
	tempKey = Encryption::base64_decode(data.encryptionKey);
	this->m_encryption_key = vectorToString(tempKey);

	if (!this->_db->doesVerifierAndSrpGroupSuitable(data))
	{
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR while verifying the user." });
		return requestResult{ dataBeforeEncryption, nullptr };
	}

	dataBeforeEncryption = JsonResponsePacketSerializer::serializeSecondPhaseOfVerificationMessageResponse(std::to_string(SUCCESSFUL_VERIFICATION_FOR_MESSAGE));
	{
		std::unique_lock<std::mutex>ipUserMap_mutex(this->m_ipUserMap_mutex);
		m_clientsIp[data.username] = data.ip;
	}
	{
		std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
		m_clientsSocket[data.username] = socket;
	}

	return requestResult{ dataBeforeEncryption, nullptr};
}

/*
This function handles an IP request from a client to a peer user.
It first deserializes the request data containing the usernames of both the client and the peer,
and retrieves the socket of the peer from a map of sockets to usernames.
If the peer is not found in the map, an error response is returned.
If the peer is found, it checks if the peer is currently listening for requests. If not, an error response is returned.
If the peer is listening, it serializes the socket of the client in a response message, and returns it to the client.

input:
requestInfo reqInfo - the request data containing the usernames of the client and peer
std::map<std::string, SOCKET>& m_clientsSocket - a map of sockets to usernames
std::list<std::string> listeningUsers - a list of usernames of clients that are currently listening for requests

output:
requestResult - a struct containing the serialized response message and a pointer to additional data (which is not used in this function)
 */
requestResult loginRequestHandler::sendRequestIpToPeer(requestInfo reqInfo, std::map<std::string, SOCKET>& m_clientsSocket, std::list<std::string> listeningUsers)
{
	std::vector<unsigned char> dataBeforeEncryption;
	userData data;
	SOCKET socket;
	std::string tempString = "", fixedJsonMessage = "";
	int i = 0;

	data = JsonRequestPacketDeserializer::deserializeIpRequestMessage(reqInfo.buffer);
	{
		std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
		socket = m_clientsSocket[data.peerUsername];
	}
	if (socket == 0)
	{
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR, peer user not found" });
		return requestResult{ dataBeforeEncryption , nullptr };
	}

	auto it = std::find(listeningUsers.begin(), listeningUsers.end(), data.peerUsername);

	if (it == listeningUsers.end())
	{
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR, peer user not listening for requests" });
		return requestResult{ dataBeforeEncryption , nullptr };
	}

	dataBeforeEncryption = JsonResponsePacketSerializer::serializeSocketForIpRequestFromPeer(socket, data.username, data.peerUsername);
	tempString = vectorToString(dataBeforeEncryption);
	for (i = 0; i < tempString.length(); i++)
	{
		if (tempString[i] == SEARCH_FOR_CURLY_BARCKET)
		{
			break;
		}
	}
	for (int j = i; j < tempString.length(); j++)
	{
		fixedJsonMessage += tempString[j];
	}
	return requestResult{ stringToVector(fixedJsonMessage) , nullptr };
}

/*

The function handles a login request by returning the IP address of the user.
input:
requestInfo reqInfo - information about the request
std::map<std::string, std::string>& m_clientsIp - map of clients and their associated IP addresses
std::map<std::string, std::string>& m_clientsInitiatingRequestForIp - map of clients initiating a request for their IP address
std::liststd::string& listeningUsers - list of users currently listening
output:
requestResult - the IP address of the user in encrypted form
*/
requestResult loginRequestHandler::ipRequestAnswer(requestInfo reqInfo, std::map<std::string, std::string>& m_clientsIp, std::map<std::string, std::string>& m_clientsInitiatingRequestForIp, std::map<std::string, SOCKET>& m_clientsSocket, std::list<std::string>& listeningUsers)
{
	std::vector<unsigned char> dataBeforeEncryption;
	userData data;
	std::string peerUserIp = "", userIp = "", tempString = "", fixedJsonMessage = "";
	int i = 0;
	SOCKET userSocket;

	try
	{
		data = JsonRequestPacketDeserializer::deserializeIpResponseMessage(reqInfo.buffer);
		{
			std::unique_lock<std::mutex>ipUserMap_mutex(this->m_ipUserMap_mutex);
			userIp = m_clientsIp[data.username];
		}
		{
			std::unique_lock<std::mutex>ipUserMap_mutex(this->m_ipUserMap_mutex);
			peerUserIp = m_clientsIp[data.peerUsername];
		}
		{
			std::unique_lock<std::mutex>clientsInitiatingRequestForIp_mutex(this->m_clientsInitiatingRequestForIp_mutex);
			m_clientsInitiatingRequestForIp.erase(data.username);
		}
		{
			std::unique_lock<std::mutex>listeningUsersList_mutex(this->m_listeningUsersList_mutex);
			listeningUsers.remove(data.peerUsername);
		}
	}
	catch (...)
	{
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR, response was received too late" });
		return requestResult{ dataBeforeEncryption , nullptr };
	}
	dataBeforeEncryption = JsonResponsePacketSerializer::serializeIpRequestResponse(userIp);
	return requestResult{ dataBeforeEncryption, nullptr};
}

/*

The function initiates listening for a user.
input:
requestInfo reqInfo - information about the request
std::liststd::string& listeningUsers - list of users currently listening
output:
requestResult - a response indicating if listening was accepted
*/
requestResult loginRequestHandler::initiateListening(requestInfo reqInfo, std::list<std::string>& listeningUsers)
{
	std::vector<unsigned char> dataBeforeEncryption;
	userData data;

	data = JsonRequestPacketDeserializer::deserializeInitiateListening(reqInfo.buffer);

	{
		std::unique_lock<std::mutex>socketUserMap_mutex(this->m_listeningUsersList_mutex);
		listeningUsers.push_back(data.username);
	}
	dataBeforeEncryption = JsonResponsePacketSerializer::serializeInitiateListeningResponse(LISTEN_ACCEPTED);
	return requestResult{ dataBeforeEncryption , nullptr };
}

/*

The function removes a user from the listening list.

input:

requestInfo reqInfo - information about the request

std::liststd::string& listeningUsers - list of users currently listening

output:

requestResult - a response indicating if the user was successfully removed from the list
*/
requestResult loginRequestHandler::removeFromListeningList(requestInfo reqInfo, std::list<std::string>& listeningUsers)
{
	std::vector<unsigned char> dataBeforeEncryption;
	userData data;

	data = JsonRequestPacketDeserializer::deserializeInitiateListening(reqInfo.buffer);

	try
	{
		std::unique_lock<std::mutex>listeningUsersList_mutex(this->m_listeningUsersList_mutex);
		listeningUsers.remove(data.username);
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeInitiateListeningResponse(STOPPED_SUCCESSFULLY);
	}
	catch (...)
	{
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR, couldn't remove user from list" });
	}
	return requestResult{ dataBeforeEncryption , nullptr };
}

/*

The function checks if a user has a pending request from a peer and returns the peer's IP address if accepted.
input:
requestInfo reqInfo - information about the request
std::map<std::string, std::string> m_clientsInitiatingRequestForIp - map of clients initiating a request for their IP address
std::map<std::string, std::string> m_clientsIp - map of clients and their associated IP addresses
output:
requestResult - the IP address of the peer user in encrypted form, or an error message if the peer user hasn't accepted the connection yet
*/
requestResult loginRequestHandler::checkForRequest(requestInfo reqInfo, std::map<std::string, std::string> m_clientsInitiatingRequestForIp, std::map<std::string, std::string> m_clientsIp)
{
	std::vector<unsigned char> dataBeforeEncryption;
	userData data;

	data = JsonRequestPacketDeserializer::deserializeCheckRequest(reqInfo.buffer);
	for (auto it : m_clientsInitiatingRequestForIp)
	{
		if ((it.first == data.username) && (it.second == data.peerUsername))
		{
			dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR, peer user didn't accept connection yet" });
			return requestResult{ dataBeforeEncryption ,nullptr };
		}
	}
	dataBeforeEncryption = JsonResponsePacketSerializer::serializeIpRequestResponse(m_clientsIp[data.peerUsername]);
	return requestResult{ dataBeforeEncryption, nullptr };
}

/*

The function cancels a request initiated by a user.

input:

requestInfo reqInfo - information about the request

std::map<std::string, std::string>& m_clientsInitiatingRequestForIp - map of clients initiating a request for their IP address

output:

requestResult - a response indicating if the request was cancelled successfully or not
*/
requestResult loginRequestHandler::cancelRequest(requestInfo reqInfo, std::map<std::string, std::string>& m_clientsInitiatingRequestForIp)
{
	std::vector<unsigned char> dataBeforeEncryption;
	userData data;

	data = JsonRequestPacketDeserializer::deserializeCheckRequest(reqInfo.buffer);

	try
	{
		std::unique_lock<std::mutex>clientsInitiatingRequestForIp_mutex(this->m_clientsInitiatingRequestForIp_mutex);
		m_clientsInitiatingRequestForIp.erase(data.username);
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeCancelRequestResponse(std::to_string(CANCEL_REQUEST_SUCCESSFULLY));
	}
	catch (...)
	{
		dataBeforeEncryption = JsonResponsePacketSerializer::serializeErrorResponse(errorResponse{ "ERROR, failed to cancel request" });
	}
	return requestResult{ dataBeforeEncryption ,nullptr };
}

//getters

/*

The function returns the encryption key used for encryption and decryption.
output:
std::string - the encryption key
*/

std::string loginRequestHandler::getEncryptionKey() const
{
	return this->m_encryption_key;
}

/*

The function returns the decryption key used for encryption and decryption.
output:
std::string - the decryption key
*/
std::string loginRequestHandler::getDecryptionKey() const
{
	return this->m_decryption_key;
}

//setters

/*

The function sets the encryption key used for encryption and decryption.
input:
const std::string encryptionKey - the encryption key to set
*/
void loginRequestHandler::setEncryptionKey(const std::string encryptionKey)
{
	this->m_encryption_key = encryptionKey;
}

/*

The function sets the decryption key used for encryption and decryption.
input:
const std::string decryptionKey - the decryption key to set
*/
void loginRequestHandler::setDecryptionKey(const std::string decryptionKey)
{
	this->m_decryption_key = decryptionKey;
}

/*

The function converts a vector of unsigned chars to a string.
input:
std::vector<unsigned char>& vec - the vector to convert
output:
std::string - the resulting string
*/
std::string loginRequestHandler::vectorToString(std::vector<unsigned char>& vec)
{
	std::string jsonMessage = "";
	for (int i = 0; i < (int)vec.size(); i++)
	{
		jsonMessage += vec[i];
	}
	return jsonMessage;
}

/*

The function converts a string to a vector of unsigned chars.
input:
const std::string& str - the string to convert
output:
std::vector<unsigned char> - the resulting vector of unsigned chars
*/
std::vector<unsigned char> loginRequestHandler::stringToVector(const std::string& str)
{
	std::vector<unsigned char> result;
	for (auto it = str.begin(); it != str.end(); ++it) {
		result.push_back(static_cast<unsigned char>(*it));
	}
	return result;
}