#include "LoginManager.h"

/*
Constructor for LoginManager class

input:
Database* database - pointer to a Database object used to access the user data
*/
LoginManager::LoginManager(Database* database) : m_database(database)
{}

/*
Sign up a new user

input:
userData dataOfUser - struct containing user's data such as username, password, and email

output:
unsigned int - return code indicating whether the registration was successful or not
*/
unsigned int LoginManager::signup(userData dataOfUser)
{
    if (m_database->addNewUser(dataOfUser))
    {
        return SUCCESSFUL_REGISTRATION;
    }
    return ERROR;
}

/*
Log in a user

input:
userData dataOfUser - struct containing user's data such as username and password

output:
unsigned int - return code indicating whether the login was successful or not
*/
unsigned int LoginManager::login(userData dataOfUser)
{
    int i = 0;
    if (m_database->doesEmailExist(dataOfUser))
    {
        bool found = false;
        for (std::vector<LoggedUser>::iterator it = m_loggedusers.begin(); it != m_loggedusers.end(); it++)
        {
            if (it->getUsername() == dataOfUser.username)
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            m_loggedusers.push_back(LoggedUser::LoggedUser(dataOfUser.username));
            std::cout << "The user is now logged in." << std::endl;
            return LOG_IN_SUCCESSFULLY;
        }
    }
    return ERROR;
}

/*
Logs out a user

input:
std::string userName - the username of the user who wants to log out

output:
unsigned int - return code indicating whether the logout was successful or not
*/
unsigned int LoginManager::logout(std::string userName)
{
    for (std::vector<LoggedUser>::iterator it = this->m_loggedusers.begin(); it != this->m_loggedusers.end(); it++)
    {
        if (it->getUsername() == userName)
        {
            this->m_loggedusers.erase(it);
            return LOG_OUT_SUCCESSFULLY;
        }
    }
    return ERROR;
}

/*
Sign out a user and delete their account from the database.

input:
std::string userName - the username of the user to sign out

output:
unsigned int - a return code indicating whether the sign out was successful, failed due to the user not being logged in, or failed due to a problem deleting the user account from the database.
*/
unsigned int LoginManager::signOut(std::string userName)
{
    if (logout(userName))
    {
        if (this->m_database->deleteUser(userName))
        {
            return SIGN_OUT_SUCCESSFULLY;
        }
        else
        {
            return ERROR;
        }
    }
    return LOGIN_NOT_OCCURED;
}