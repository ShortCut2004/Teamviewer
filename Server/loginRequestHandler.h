#pragma once
#include "Database.h"
#include "IRequestHandler.h"
#include "JsonRequestPacketDeserializer.h"
#include "Encryption.h"
#include "LoginManager.h"
#include "RequestHandlerFactory.h"
#include <mutex>
#include <cstring>

#define SEARCH_FOR_CURLY_BARCKET '{'

class RequestHandlerFactory;

class loginRequestHandler : public IRequestHandler
{
public:
	loginRequestHandler(Database* database, LoginManager* loginManager, RequestHandlerFactory* handleFactory);
	virtual bool isRequestRelevant(requestInfo reqInfo);
	virtual requestResult handleRequest(requestInfo reqInfo, std::map<std::string, std::string>& m_clientsIp, std::map <std::string, SOCKET>& m_clientsSocket, SOCKET& socket, std::list<std::string>& listeningList, std::map<std::string, std::string>& m_clientsInitiatingRequestForIp);

	//getters
	std::string getEncryptionKey() const;
	std::string getDecryptionKey() const;


	//setters
	void setEncryptionKey(const std::string encryptionKey);
	void setDecryptionKey(const std::string decryptionKey);

	std::string vectorToString(std::vector<unsigned char>& vec);
	std::vector<unsigned char> stringToVector(const std::string& str);

private:
	Database* _db;
	LoginManager* m_loginManager;
	RequestHandlerFactory* m_handleFactory;

	requestResult handleSaltAndSrpGroupRequest(requestInfo reqInfo);
	requestResult handleFirstPhaseVerification(requestInfo reqInfo);
	requestResult handleSecondPhaseVerification(requestInfo reqInfo, std::map<std::string, std::string>& m_clientsIp, std::map<std::string, SOCKET>& m_clientsSocket, SOCKET socket);
	requestResult createExchangeKeys(requestInfo reqInfo);
	requestResult signUp(requestInfo reqInfo);
	requestResult logout(requestInfo reqInfo);
	requestResult login(requestInfo reqInfo);
	requestResult signOut(requestInfo reqInfo);
	requestResult ipRequestAnswer(requestInfo reqInfo, std::map<std::string, std::string>& m_clientsIp, std::map<std::string, std::string>& m_clientsInitiatingRequestForIp, std::map<std::string, SOCKET>& m_clientsSocket, std::list<std::string>& listeningUsers);
	requestResult sendRequestIpToPeer(requestInfo reqInfo, std::map<std::string, SOCKET>& m_clientsSocket, std::list<std::string> listeningUsers);
	requestResult initiateListening(requestInfo reqInfo, std::list<std::string>& listeningUsers);
	requestResult removeFromListeningList(requestInfo reqInfo, std::list<std::string>& listeningUsers);
	requestResult cancelRequest(requestInfo reqInfo, std::map<std::string, std::string>& m_clientsInitiatingRequestForIp);
	requestResult checkForRequest(requestInfo reqInfo, std::map<std::string, std::string> m_clientsInitiatingRequestForIp, std::map<std::string, std::string> m_clientsIp);

	std::string m_decryption_key;
	std::string m_encryption_key;
	std::mutex m_socketUserMap_mutex;
	std::mutex m_ipUserMap_mutex;
	std::mutex m_listeningUsersList_mutex;
	std::mutex m_clientsInitiatingRequestForIp_mutex;

};
