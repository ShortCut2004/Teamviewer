#pragma once
#include <WinSock2.h>
#include <Windows.h>
#include <mutex>
#include <set>
#include <string>
#include <fstream>
#include <sstream>
#include <queue>
#include <iostream>
#include <string>
#include <thread>
#include <map>
#include <condition_variable>
#include "Helper.h"
#include "Communicator.h"
#include "Database.h"


typedef struct Messages
{
	std::string _srcName;
	std::string _dstName;
	std::string _message;
}Messages;

class Server
{
public:
	Server(const Server&) = delete;
	Server(Database* database);
	void run();
	~Server();

private:
	SOCKET _serverSocket;
	Communicator m_communicator;
	Database* m_database;
	RequestHandlerFactory m_handleFactory;
};