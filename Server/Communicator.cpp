#include "Communicator.h"

/*

The Communicator constructor.

input:

RequestHandlerFactory* requestHandlerFactory - pointer to the request handler factory used for creating request handlers
*/
Communicator::Communicator(RequestHandlerFactory* requestHandlerFactory)
    : m_requestHandlerFactory(requestHandlerFactory)
{
    // this server use TCP. that why SOCK_STREAM & IPPROTO_TCP
// if the server use UDP we will use: SOCK_DGRAM & IPPROTO_UDP
    m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (m_serverSocket == INVALID_SOCKET)
        throw std::exception(__FUNCTION__ " - socket");
    std::cout << "Starting..." << std::endl;
}

/*

The function starts handling incoming requests.
It accepts incoming client connections and creates a new thread for handling each client.
*/
void Communicator::startHandleRequest()
{
    bindAndListen();
    while (true)
    {
        // this accepts the client and create a specific socket from server to this client
        // the process will not continue until a client connects to the server
        SOCKET client_socket = accept(m_serverSocket, NULL, NULL);
        if (client_socket == INVALID_SOCKET)
            throw std::exception(__FUNCTION__);

        std::thread clientHandlerThread(&Communicator::handleNewClient, this, client_socket);
        clientHandlerThread.detach();
    }
}
/*

The function binds the server socket to a port and starts listening for incoming client connections.
*/
void Communicator::bindAndListen()
{
    struct sockaddr_in sa = { 0 };

    sa.sin_port = htons(SERVER_PORT); // port that server will listen for
    sa.sin_family = AF_INET;   // must be AF_INET
    sa.sin_addr.s_addr = INADDR_ANY;    // when there are few ip's for the machine. We will use always "INADDR_ANY"

    // Connects between the socket and the configuration (port and etc..)
    if (bind(m_serverSocket, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR)
        throw std::exception(__FUNCTION__ " - bind");

    std::cout << "binded" << std::endl;
    // Start listening for incoming requests of clients
    if (listen(m_serverSocket, SOMAXCONN) == SOCKET_ERROR)
        throw std::exception(__FUNCTION__ " - listen");
    std::cout << "listening..." << std::endl;
}

/*
Handles a new client connection by creating a new login request handler and handling the client's requests.
Parameters:

clientSocket: a SOCKET representing the client's socket
Returns: void
*/
void Communicator::handleNewClient(SOCKET clientSocket)
{
    loginRequestHandler* newRequest = this->m_requestHandlerFactory->createLoginRequestHandler();
    requestInfo reqInfo;
    errorResponse erResponse;
    requestResult reqResult;
    std::string decryptionKey = "", encryptionKey = "";
    userData data;
    bool flag = true;
    {
        std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
        m_clients[clientSocket] = newRequest;
    }
    try
    {
        if (getInitialExchangeKeys(clientSocket))
        {
            while (true)
            {
                receiveData(clientSocket, newRequest, reqInfo);
                if (!newRequest->isRequestRelevant(reqInfo))
                {
                    erResponse.error = MESSAGE_IF_ERROR;
                    reqResult.response = JsonResponsePacketSerializer::serializeErrorResponse(erResponse);
                }
                else
                {
                    reqResult = newRequest->handleRequest(reqInfo, this->m_clientsIp, this->m_clientsSocket, clientSocket, listeningUsers, m_clientsInitiatingRequestForIp);
                    switch (reqInfo.id)
                    {
                    case EXCHANGE_NEW_KEYS:
                        handleVerificationMessage(reqInfo, clientSocket, reqResult);
                        break;
                    case IP_REQUEST:
                        data = JsonRequestPacketDeserializer::deserializeSocketForIpRequest(reqResult.response);
                        handleIpRequestToPeer(data, reqInfo, clientSocket, reqResult);
                        reqResult.response = JsonResponsePacketSerializer::serializeRequestSentSuccessfully();
                        break;
                    case IP_RESPONSE_FROM_PEER:
                        {
                            std::unique_lock<std::mutex>encryptionKeysHandlersMap_mutex(this->m_encryptionKeysHandlersMap_mutex);
                            encryptionKey = ((loginRequestHandler*)m_clientsEncryptionKeysHandlers[clientSocket])->getEncryptionKey();
                        }
                        flag = false;
                        break;
                    default:
                        break;
                    }
                    reqResult.newHandler = this->m_requestHandlerFactory->createLoginRequestHandler();
                    {
                        std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
                        m_clients[clientSocket] = reqResult.newHandler;
                    }
                    {
                        std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
                        newRequest = (loginRequestHandler*)m_clients[clientSocket];
                    }
                }
                if(flag)
                {
                    std::unique_lock<std::mutex>clientEncryption_mutex(this->m_clientEncryption_mutex);
                    encryptionKey = m_encryptionKey;
                }
                sendMessage(clientSocket, newRequest, reqResult, encryptionKey);
            }
        }
    }
    catch (std::exception& e)
    {
        std::cout << "Error occured: " << e.what() << std::endl;
    }
}

/*
The function gets a socket and performs an initial exchange of keys with the client, in which it receives the encryption and decryption keys from the client.
If the client does not send the correct request, an error response will be sent.
input:
SOCKET& clientSocket - a socket representing a client that connected to the server.
output:
returns true if the exchange was successful, false otherwise.
*/
bool Communicator::getInitialExchangeKeys(SOCKET& clientSocket)
{
    requestInfo reqInfo;
    int sizeOfMessage = 0;
    errorResponse erResponse;
    requestResult reqResult;
    std::string jsonMessage = "", clientMessage = "";
    buffer dataToSend;
    std::string temp;
    std::vector<unsigned char> tempBuffer;
    loginRequestHandler* head = nullptr;
    {
        std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
        head = (loginRequestHandler*)m_clients[clientSocket];
    }
    clientMessage = Helper::getStringPartFromSocket(clientSocket, DEFAULT_RECV_SIZE);
    tempBuffer = head->stringToVector(clientMessage);
    reqInfo.buffer = cut_vector_at_character(tempBuffer, END_OF_VECTOR);
    reqInfo.id = JsonRequestPacketDeserializer::deserializeMessageCode(reqInfo.buffer);

    if (!(reqInfo.id == INITIAL_KEYS))
    {
        erResponse.error = MESSAGE_IF_ERROR;
        dataToSend = JsonResponsePacketSerializer::serializeErrorResponse(erResponse);
        for (int i = 0; i < (int)dataToSend.size(); i++)
        {
            jsonMessage += dataToSend[i];
        }
        auto temp = head->stringToVector(jsonMessage);
        Encryption::rsa_encryption((std::string&)head->getEncryptionKey(), temp, dataToSend);
        Helper::sendData(clientSocket, jsonMessage);
        return false;
    }
    else
    {
        loginRequestHandler* head = nullptr;
        {
            std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
            head = (loginRequestHandler*)m_clients[clientSocket];
        }
        reqResult = head->handleRequest(reqInfo, m_clientsIp, m_clientsSocket, clientSocket, listeningUsers, m_clientsInitiatingRequestForIp);
        {
            std::unique_lock<std::mutex>clientDecryption_mutex(this->m_clientDecryption_mutex);
            m_decryptionKey = head->getDecryptionKey();
        }
        {
            std::unique_lock<std::mutex>clientEncryption_mutex(this->m_clientEncryption_mutex);
            m_encryptionKey = head->getEncryptionKey();
        }
        Encryption::rsa_encryption((std::string&)head->getEncryptionKey(), reqResult.response, dataToSend);
        reqResult.newHandler = m_requestHandlerFactory->createLoginRequestHandler();
        {
            std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
            m_clients[clientSocket] = reqResult.newHandler;
        }
        Helper::sendData(clientSocket, head->vectorToString(dataToSend));
        return true;
    }
}

/*
Handles the verification message sent by the client after the initial exchange of keys.
The function decrypts the message sent by the client, checks if the message code is VERIFICATION_MESSAGE.
If it is, the function uses the current loginRequestHandler to handle the request, updates the encryption key,
and sends the response to the client encrypted with the updated key.
Otherwise, the function returns an error response to the client.
input:
reqInfo - the request info
socket - the client's socket
reqResult - the request result
output:
None
*/
void Communicator::handleVerificationMessage(requestInfo& reqInfo, SOCKET& socket, requestResult& reqResult)
{
    std::vector<unsigned char> dataToSend, tempBuffer, output;
    loginRequestHandler* curr = nullptr;
    loginRequestHandler* head = nullptr;
    std::string clientMessage = "", jsonMessage = "", encryptionKey = "", decryptionKey = "";
    errorResponse erResponse;

    {
        std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
        curr = (loginRequestHandler*)m_clients[socket];
    }
    {
        std::unique_lock<std::mutex>clientEncryption_mutex(this->m_clientEncryption_mutex);
        encryptionKey = m_encryptionKey;
    }

    Encryption::rsa_encryption(encryptionKey, reqResult.response, dataToSend);
    Helper::sendData(socket, curr->vectorToString(dataToSend));

    reqResult.newHandler = this->m_requestHandlerFactory->createLoginRequestHandler();
    {
        std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
        m_clients[socket] = reqResult.newHandler;
    }
    {
        std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
        head = (loginRequestHandler*)m_clients[socket];
    }
    {
        std::unique_lock<std::mutex>clientDecryption_mutex(this->m_clientDecryption_mutex);
        m_decryptionKey = curr->getDecryptionKey();
    }
    {
        std::unique_lock<std::mutex>clientDecryption_mutex(this->m_clientDecryption_mutex);
        decryptionKey = m_decryptionKey;
    }

    clientMessage = Helper::getStringPartFromSocket(socket, DEFAULT_RECV_SIZE);
    tempBuffer = head->stringToVector(clientMessage);
    Encryption::rsa_decryption(decryptionKey, tempBuffer, output);
    reqInfo.buffer = cut_vector_at_character(output, END_OF_VECTOR);
    reqInfo.id = JsonRequestPacketDeserializer::deserializeMessageCode(reqInfo.buffer);

    if (!(reqInfo.id == VERIFICATION_MESSAGE))
    {
        erResponse.error = MESSAGE_IF_ERROR;
        dataToSend = JsonResponsePacketSerializer::serializeErrorResponse(erResponse);
        for (int i = 0; i < (int)dataToSend.size(); i++)
        {
            jsonMessage += dataToSend[i];
        }
        reqResult.response = head->stringToVector(jsonMessage);
    }
    else
    {
        reqResult.response.clear();
        reqResult = head->handleRequest(reqInfo, m_clientsIp, m_clientsSocket, socket, listeningUsers, m_clientsInitiatingRequestForIp);
        {
            std::unique_lock<std::mutex>encryptionKeysHandlersMap_mutex(this->m_encryptionKeysHandlersMap_mutex);
            m_clientsEncryptionKeysHandlers[socket] = head;
        }
        {
            std::unique_lock<std::mutex>clientEncryption_mutex(this->m_clientEncryption_mutex);
            m_encryptionKey = head->getEncryptionKey();
        }
    }
}

/*

This function handles an IP request to a peer. It serializes the IP request using the given user data and encrypts it using the encryption key of the handler that is responsible for encryption for the given socket. The encrypted message is sent to the socket using the head handler.

Input:
userData& data - user data containing the socket and username information
requestInfo& reqInfo - request information

Output:
None
*/
void Communicator::handleIpRequestToPeer(userData& data, requestInfo& reqInfo, SOCKET clientSocket, requestResult& reqResult)
{
    std::vector<unsigned char> dataToSend, tempBuffer, output;
    loginRequestHandler* head = nullptr;
    std::string clientMessage = "", encryptionKey = "";

    {
        std::unique_lock<std::mutex>socketUserMap_mutex(this->m_socketUserMap_mutex);
        head = (loginRequestHandler*)m_clients[(SOCKET)data.socket];
    }
    {
        std::unique_lock<std::mutex>encryptionKeysHandlersMap_mutex(this->m_encryptionKeysHandlersMap_mutex);
        encryptionKey = ((loginRequestHandler*)m_clientsEncryptionKeysHandlers[(SOCKET)data.socket])->getEncryptionKey();
    }

    reqInfo.buffer = JsonResponsePacketSerializer::serializeIpRequestFromPeer(data.username);
    Encryption::rsa_encryption(encryptionKey, reqInfo.buffer, dataToSend);
    Helper::sendData((SOCKET)data.socket, head->vectorToString(dataToSend));
    {
        std::unique_lock<std::mutex>socketUserMap_mutex(this->m_clientsInitiatingRequestForIp_mutex);
        m_clientsInitiatingRequestForIp[data.username] = data.peerUsername;
        //self user is the data.peerUsername because the message is sent to that peer and so as the data.username
    }
}

/*
The function takes a vector and a character as input, and returns a new vector
with all elements from the input vector up to (but not including) the first occurrence
of the character. If the character is not found in the vector, the function returns
the input vector itself.

Inputs:
vec: a vector of unsigned char
character: an integer representing the ASCII code of the character to search for
Output:

std::vector<unsigned char>: a new vector containing all elements of the input vector up to (but not including)
the first occurrence of the character, or the input vector itself if the character is not found
*/
std::vector<unsigned char> Communicator::cut_vector_at_character(const std::vector<unsigned char>& vec, int character)
{
    std::vector<unsigned char> newVec;
    for (int i = 0; i < vec.size(); i++)
    {
        if ((int)vec[i] != character)
        {
            newVec.push_back(vec[i]);
        }
        else
        {
            return newVec;
        }
    }
    return newVec;
}

/*
This function receives data from a given client socketand processes it using an instance of the loginRequestHandler
class.The received data is decrypted using an RSA decryption algorithmand stored in a requestInfo struct.

Inputs :
clientSocket : a reference to a SOCKET object representing the client socket from which to receive data
newRequest : a pointer to a loginRequestHandler object used to process the received data
reqInfo : a reference to a requestInfo object in which to store the processed data

Output :
None
*/
void Communicator::receiveData(SOCKET& clientSocket, loginRequestHandler* newRequest, requestInfo& reqInfo)
{
    std::string clientMessage = "", decryptionKey = "";
    std::vector<unsigned char> tempBuffer, output;

    {
        std::unique_lock<std::mutex>clientDecryption_mutex(this->m_clientDecryption_mutex);
        decryptionKey = m_decryptionKey;
    }

    clientMessage = Helper::getStringPartFromSocket(clientSocket, DEFAULT_RECV_SIZE);
    tempBuffer = newRequest->stringToVector(clientMessage);
    Encryption::rsa_decryption(decryptionKey, tempBuffer, output);
    reqInfo.buffer = cut_vector_at_character(output, END_OF_VECTOR);
    reqInfo.id = JsonRequestPacketDeserializer::deserializeMessageCode(reqInfo.buffer);
}

/*
Sends a message to the client socket using an instance of the loginRequestHandler class.

Inputs:
clientSocket: a reference to a SOCKET object representing the client socket to which the message will be sent.
newRequest: a pointer to a loginRequestHandler object used to process the message.
reqResult: a reference to a requestResult object containing the message to be sent.
encryptionKey: a reference to a string containing the RSA encryption key used to encrypt the message.

Output:
None
*/
void Communicator::sendMessage(SOCKET& clientSocket, loginRequestHandler* newRequest, requestResult& reqResult, std::string& encryptionKey)
{
    std::vector<unsigned char> tempBuffer, dataToSend;

    Encryption::rsa_encryption(encryptionKey, reqResult.response, dataToSend);
    Helper::sendData(clientSocket, newRequest->vectorToString(dataToSend));
}