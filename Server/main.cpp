#pragma comment (lib, "ws2_32.lib")

#include "WSAInitializer.h"
#include "Server.h"
#include <iostream>
#include <exception>


#define SERVER_PORT 8080

int main()
{
	try
	{
		Database* database = new Database();
		WSAInitializer wsaInit;
		Server myServer(database);
		std::thread mainThread(&Server::run, &myServer);
		mainThread.detach();
		std::string input = "";
		while (input != "stop")
		{
			std::cin >> input;
		}
		database->close();
	}
	catch (std::exception& e)
	{
		std::cout << "Error occured: " << e.what() << std::endl;
	}
	system("PAUSE");
	return 0;
}
