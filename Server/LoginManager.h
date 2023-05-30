#pragma once
#include "Database.h"
#include <vector>
#include "LoggedUser.h"

#define LOGIN_NOT_OCCURED 1

class LoginManager
{
public:
    LoginManager(Database* database);
    unsigned int signup(userData dataOfUser);
    unsigned int login(userData dataOfUser);
    unsigned int logout(std::string userName);
    unsigned int signOut(std::string userName);
private:
    Database* m_database;
    std::vector<LoggedUser> m_loggedusers;
};