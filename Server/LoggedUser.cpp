#include "LoggedUser.h"

/*
Constructor for the LoggedUser class.

input:
std::string userName - the username of the logged-in user

output:
None
*/
LoggedUser::LoggedUser(std::string userName)
{
	m_username = userName;
}

/*
Return the username of the LoggedUser

input: None

output:
std::string - the username of the LoggedUser
*/
std::string LoggedUser::getUsername()
{
	return m_username;
}
