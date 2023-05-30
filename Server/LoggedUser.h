#pragma once
#include <string>
#include <iostream>

class LoggedUser
{
public:
	LoggedUser(std::string userName);
	std::string getUsername();
private:
	std::string m_username;
};
