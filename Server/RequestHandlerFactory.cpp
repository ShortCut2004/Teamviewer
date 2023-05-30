#include "RequestHandlerFactory.h"

/*

The RequestHandlerFactory constructor.
input:
Database* database - pointer to the database used for data storage and retrieval
*/
RequestHandlerFactory::RequestHandlerFactory(Database* database) : m_database(database), m_loginManager(database)
{
}

/*

The function creates a new login request handler.
output:
loginRequestHandler* - pointer to the created login request handler
*/
loginRequestHandler* RequestHandlerFactory::createLoginRequestHandler()
{
	return new loginRequestHandler(this->m_database, &(this->m_loginManager), this);
}

/*

The function returns the login manager.
output:
LoginManager - the login manager
*/
LoginManager RequestHandlerFactory::getLoginManager()
{
	return this->m_loginManager;
}