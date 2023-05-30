#include "Server.h"

/*

The Server constructor.
input:
Database* database - pointer to the database used for data storage and retrieval
*/
Server::Server(Database* database) : m_handleFactory(database), m_communicator(&m_handleFactory)
{
	this->m_database = database;
}

/*

The Server destructor.
It closes the server socket and deletes the database object.
*/
Server::~Server()
{
	try
	{
		// the only use of the destructor should be for freeing 
		// resources that was allocated in the constructor
		closesocket(_serverSocket);
		delete this->m_database;
	}
	catch (...) {}
}

/*

The function starts the server and listens for incoming requests.
*/
void Server::run()
{
	std::string exitKey;
	std::thread t_connector(&Communicator::startHandleRequest, &m_communicator);
	t_connector.detach();

	std::cout << "Enter input: " << std::endl;
	while (exitKey != "EXIT")
	{
		std::cin >> exitKey;
	}

}