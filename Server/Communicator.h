#pragma once
#include <map>
#include <string>
#include <thread>
#include <iostream>
#include "RequestHandlerFactory.h"
#include "Helper.h"

#define SERVER_PORT 8080
#define MESSAGE_IF_ERROR "ERROR"
#define DEFAULT_RECV_SIZE 4096
#define END_OF_VECTOR 205

class Communicator
{
public:
    Communicator() = default;
    Communicator(RequestHandlerFactory* requestHandlerFactory);
    void startHandleRequest();

private:
    SOCKET m_serverSocket;
    RequestHandlerFactory* m_requestHandlerFactory;
    std::map<SOCKET, IRequestHandler*> m_clients;
    std::map<std::string, SOCKET> m_clientsSocket;
    std::map<std::string, std::string> m_clientsIp;
    std::map<SOCKET, IRequestHandler*> m_clientsEncryptionKeysHandlers;
    std::map<SOCKET, IRequestHandler*> m_clientsDecryptionKeysHandlers;
    std::list<std::string> listeningUsers;
    std::map<std::string, std::string> m_clientsInitiatingRequestForIp;

    std::mutex m_socketUserMap_mutex;
    std::mutex m_keysHandlersMap_mutex;
    std::mutex m_encryptionKeysHandlersMap_mutex;
    std::mutex m_decryptionKeysHandlersMap_mutex;
    std::mutex m_clientsInitiatingRequestForIp_mutex;
    std::mutex m_clientDecryption_mutex;
    std::mutex m_clientEncryption_mutex;

    std::string m_decryptionKey;
    std::string m_encryptionKey;
    
    void bindAndListen();
    void handleNewClient(SOCKET clientSocket);

    bool getInitialExchangeKeys(SOCKET& clientSocket);

    std::vector<unsigned char> cut_vector_at_character(const std::vector<unsigned char>& vec, int character);
    void handleIpRequestToPeer(userData& data, requestInfo& reqInfo, SOCKET clientSocket, requestResult& reqResult);
    void handleVerificationMessage(requestInfo& reqInfo, SOCKET& socket, requestResult& reqResult);
    void receiveData(SOCKET& clientSocket, loginRequestHandler* newRequest, requestInfo& reqInfo);
    void sendMessage(SOCKET& clientSocket, loginRequestHandler* newRequest, requestResult& reqResult, std::string& encryptionKey);
};