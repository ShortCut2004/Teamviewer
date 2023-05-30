#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <time.h>
#include "json.hpp"
#include <chrono>
#include <ctime> 
#include "JsonResponsePacketSerializer.h"
#include <WinSock2.h>
#include <Windows.h>



typedef struct requestInfo
{
    int id;
    std::vector<unsigned char> buffer;
}requestInfo;

class IRequestHandler;
typedef struct requestResult
{
    std::vector<unsigned char> response;
    IRequestHandler* newHandler = nullptr;
}requestResult;

class IRequestHandler
{
public:
    virtual bool isRequestRelevant(requestInfo reqInfo) = 0;
    virtual requestResult handleRequest(requestInfo reqInfo, std::map<std::string, std::string>& m_clientsIp, std::map <std::string, SOCKET>& m_clientsSocket, SOCKET& socket, std::list<std::string>& listeningList, std::map<std::string, std::string>& m_clientsInitiatingRequestForIp) = 0;
};