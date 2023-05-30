#pragma once
#include <string>
#include <vector>
#include <iostream>
#include "loginRequestHandler.h"

class loginRequestHandler;

class RequestHandlerFactory
{
public:
	RequestHandlerFactory(Database* m_database);
	loginRequestHandler* createLoginRequestHandler();
	LoginManager getLoginManager();

private:
	Database* m_database;
	LoginManager m_loginManager;
};
