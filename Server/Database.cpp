#include "Database.h"

/*
Constructor of TeamViewerDataBase
Input: None
Output: None
*/
Database::Database()
{
	if (!this->open())
		throw std::exception("Couldnt connect to database.");
}

/*

Destructor of TeamViewerDataBase
Input: None
Output: None
*/
Database::~Database()
{
	clear();
	close();
}

/*
Opening the database if exists. if not creating new database
Input: None
Output: true if opened or created succesfuly
*/
bool Database::open()
{
	std::vector<const char*> tableCreationQueries;
	char* errMessage = new char[1000];
	const char* CreateTableUsers = "CREATE TABLE USERS("  \
		"USER_ID			   INTEGER PRIMARY KEY NOT NULL," \
		"USER_NAME			   TEXT				NOT NULL," \
		"EMAIL				   TEXT				NOT NULL," \
		"SALT				   TEXT				NOT NULL," \
		"SRP_GROUP			   TEXT				NOT NULL," \
		"VERIFIER			   TEXT				NOT NULL);";

	tableCreationQueries.push_back(CreateTableUsers);
	std::string dbFileName = "TeamviewerDB.sqlite";

	int file_exist = _access(dbFileName.c_str(), 0);

	int res = sqlite3_open(dbFileName.c_str(), &this->_database);

	if (res != SQLITE_OK)
	{
		std::cerr << "Cant open db" << std::endl;
		this->_database = nullptr;
		return false;
	}
	else if (file_exist != 0)
	{
		//initializing database
		for (unsigned int i = 0; i < (unsigned int)tableCreationQueries.size(); i++)
		{
			res = sqlite3_exec(_database, tableCreationQueries[i], nullptr, nullptr, &errMessage);
			if (res != SQLITE_OK)
			{
				std::cerr << i + 1 << std::endl;
				std::cerr << errMessage << std::endl;
				delete[] errMessage;
				return false;
			}
		}
	}
	delete[] errMessage;
	return true;
}

/*

This function closes the database connection and sets the _database pointer to null.
input: none
output: none
*/
void Database::close()
{
	sqlite3_close(_database);
	_database = nullptr;
}

/*

The function frees the memory associated with the SQLite database handle.
Note that this function only frees the handle and does not close the database itself.
After calling this function, the database handle will be set to null.
*/
void Database::clear()
{
	sqlite3_free(_database);
}

// Declare a global atomic variable to count num of users
std::atomic<int> count_id(0);

/*
The function adds a new user to the database - userid, username, email, salt, srp group, verifier
input:
const userData& userdata - the user's data
output:
boolean value resembling the success of the user addition
*/
bool Database::addNewUser(const userData& userdata) const
{
	// Get the last USER_ID value from the database
	const char* maxUserIDQuery = "SELECT MAX(USER_ID) FROM USERS;";
	sqlite3_stmt* statement;

	if (doesUserExist(userdata))
	{
		std::cerr << "Couldn't create user, user already exists!" << std::endl;
		return false;
	}

	int res = sqlite3_prepare_v2(this->_database, maxUserIDQuery, -1, &statement, nullptr);

	if (res != SQLITE_OK)
	{
		std::cerr << "Couldn't get last USER_ID, Error code: " << res << ", Error message: " << sqlite3_errmsg(this->_database) << std::endl;
		return false;
	}

	res = sqlite3_step(statement);
	int lastUserID = res == SQLITE_ROW ? sqlite3_column_int(statement, 0) : 0;
	sqlite3_finalize(statement);

	// Increment the USER_ID value
	int newUserID = lastUserID + 1;
	count_id.store(newUserID);
	
	// Construct the INSERT query with the new USER_ID value using a prepared statement
	const char* createUserQuery = "INSERT INTO USERS VALUES(?, ?, ?, ?, ?, ?);";
	res = sqlite3_prepare_v2(this->_database, createUserQuery, -1, &statement, nullptr);

	if (res != SQLITE_OK)
	{
		std::cerr << "Couldn't create prepared statement, Error code: " << res << ", Error message: " << sqlite3_errmsg(this->_database) << std::endl;
		return false;
	}

	sqlite3_bind_int(statement, 1, newUserID);
	sqlite3_bind_text(statement, 2, userdata.username.c_str(), -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(statement, 3, userdata.email.c_str(), -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(statement, 4, userdata.salt.c_str(), -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(statement, 5, userdata.srpGroup.c_str(), -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(statement, 6, userdata.verifier.c_str(), -1, SQLITE_TRANSIENT);

	// Execute the prepared statement
	res = sqlite3_step(statement);
	sqlite3_finalize(statement);

	if (res != SQLITE_DONE)
	{
		std::cerr << "Couldn't create user, Error code: " << res << ", Error message: " << sqlite3_errmsg(this->_database) << std::endl;
		return false;
	}

	return true;
}

/*
The function checks if a user exists in the database by their username.
input:
const userData& userdata - the user's data
output:
boolean value resembling the existence of the user in the database
*/
bool Database::doesUserExist(const userData& userdata) const
{
	sqlite3_stmt* statement;
	const char* query = "SELECT * FROM USERS WHERE USER_NAME = ?;";
	int res = sqlite3_prepare_v2(this->_database, query, -1, &statement, nullptr);

	if (res != SQLITE_OK)
	{
		std::cout << "Error code: " << res << std::endl;
		return false;
	}

	sqlite3_bind_text(statement, 1, userdata.username.c_str(), -1, SQLITE_TRANSIENT);

	res = sqlite3_step(statement);
	if (res != SQLITE_ROW)
	{
		if (res != SQLITE_DONE)
		{
			std::cout << "Error code: " << res << std::endl;
		}
		sqlite3_finalize(statement);
		return false;
	}

	sqlite3_finalize(statement);
	return true;
}

/*
The function deletes a user from the USERS table in the database based on the provided username.
input:
const std::string& username - a reference to the username string
output:
true if the user was successfully deleted, false otherwise
*/
bool Database::deleteUser(const std::string& username) const
{
	sqlite3_stmt* statement;
	const char* query = "DELETE FROM USERS WHERE USER_NAME = ?;";
	int res = sqlite3_prepare_v2(this->_database, query, -1, &statement, nullptr);

	if (res != SQLITE_OK)
	{
		std::cerr << "Could not prepare statement, Error code: " << res << std::endl;
		return false;
	}

	sqlite3_bind_text(statement, 1, username.c_str(), -1, SQLITE_TRANSIENT);

	res = sqlite3_step(statement);
	if (res != SQLITE_DONE)
	{
		std::cerr << "Could not execute statement, Error code: " << res << std::endl;
		sqlite3_finalize(statement);
		return false;
	}

	sqlite3_finalize(statement);
	return true;
}

/*

The function retrieves the salt for a user by their email.
input:
const userData& userdata - the user's data, including their email
output:
userData - a userData object containing the retrieved salt, or an empty userData object if the salt could not be retrieved.
*/
userData Database::getSaltByEmail(const userData& userdata) const
{
	std::string query = "SELECT SALT FROM USERS WHERE EMAIL = ?;";
	sqlite3_stmt* statement;
	int res = sqlite3_prepare_v2(this->_database, query.c_str(), -1, &statement, nullptr);
	if (res != SQLITE_OK)
	{
		std::cerr << "Could not prepare statement: " << sqlite3_errmsg(this->_database) << std::endl;
		return userData();
	}
	res = sqlite3_bind_text(statement, 1, userdata.email.c_str(), -1, SQLITE_TRANSIENT);
	if (res != SQLITE_OK)
	{
		std::cerr << "Could not bind parameter: " << sqlite3_errmsg(this->_database) << std::endl;
		sqlite3_finalize(statement);
		return userData();
	}
	std::list<userData> listUsersMatch;
	res = sqlite3_step(statement);
	if (res == SQLITE_ROW) {
		userData user;
		user.salt = std::string(reinterpret_cast<const char*>(sqlite3_column_text(statement, 0)));
		listUsersMatch.push_back(user);
	}
	sqlite3_finalize(statement);
	if (!listUsersMatch.empty())
	{
		return listUsersMatch.front();
	}
	return userData();
}

/*
This function retrieves the salt and SRP group values from the USERS table in the database, given an email address. It is assumed that the email address belongs to a registered user.

Input:
userdata - an object of type userData that contains the email address of the user whose salt and SRP group values are to be retrieved.

Output:
A userData object that contains the salt and SRP group values of the user corresponding to the email address provided. If the email address is not found in the database or an error occurs, an empty userData object is returned.
*/
userData Database::getSaltAndSrpGroupByEmail(const userData& userdata) const
{
	std::string query = "SELECT SALT, SRP_GROUP FROM USERS WHERE EMAIL = ?;";
	sqlite3_stmt* statement;
	int res = sqlite3_prepare_v2(this->_database, query.c_str(), -1, &statement, nullptr);
	if (res != SQLITE_OK)
	{
		std::cerr << "Could not prepare statement: " << sqlite3_errmsg(this->_database) << std::endl;
		return userData();
	}
	res = sqlite3_bind_text(statement, 1, userdata.email.c_str(), -1, SQLITE_TRANSIENT);
	if (res != SQLITE_OK)
	{
		std::cerr << "Could not bind parameter: " << sqlite3_errmsg(this->_database) << std::endl;
		sqlite3_finalize(statement);
		return userData();
	}
	std::list<userData> listUsersMatch;
	res = sqlite3_step(statement);
	if (res == SQLITE_ROW) {
		userData user;
		user.salt = std::string(reinterpret_cast<const char*>(sqlite3_column_text(statement, 0)));
		user.srpGroup = std::string(reinterpret_cast<const char*>(sqlite3_column_text(statement, 1)));
		listUsersMatch.push_back(user);
	}
	sqlite3_finalize(statement);
	if (!listUsersMatch.empty())
	{
		return listUsersMatch.front();
	}
	return userData();
}

/*

This function retrieves the salt and SRP group associated with a given user email from the database.
input:
const userData& userdata - a const reference to the user data containing the email for which to retrieve the salt and SRP group
output:
userData - a user data object containing the retrieved salt and SRP group, or an empty object if the email was not found in the database
*/
bool Database::doesEmailExist(const userData& userdata) const
{
	sqlite3_stmt* statement;
	const char* query = "SELECT * FROM USERS WHERE EMAIL = ?;";
	int res = sqlite3_prepare_v2(this->_database, query, -1, &statement, nullptr);

	if (res != SQLITE_OK)
	{
		std::cerr << "Could not prepare statement, Error code: " << res << std::endl;
		return false;
	}

	sqlite3_bind_text(statement, 1, userdata.email.c_str(), -1, SQLITE_TRANSIENT);

	res = sqlite3_step(statement);
	if (res == SQLITE_ROW)
	{
		sqlite3_finalize(statement);
		return true;
	}
	else if (res != SQLITE_DONE)
	{
		std::cerr << "Could not execute statement, Error code: " << res << std::endl;
	}

	sqlite3_finalize(statement);
	return false;
}

/*

The function checks if there is a user in the database with the same SRP group and verifier as the input user data.
input:
const userData& userdata - a reference to the user data containing the SRP group and verifier to be checked
output:
true if there is a matching user in the database, false otherwise
*/
bool Database::doesVerifierAndSrpGroupSuitable(const userData& userdata) const
{
	std::string query = "SELECT VERIFIER, SRP_GROUP FROM USERS;";
	sqlite3_stmt* statement;
	int res = sqlite3_prepare_v2(this->_database, query.c_str(), -1, &statement, nullptr);
	if (res != SQLITE_OK)
	{
		std::cerr << "Could not prepare statement: " << sqlite3_errmsg(this->_database) << std::endl;
		return false;
	}
	userData user;
	while ((res = sqlite3_step(statement)) == SQLITE_ROW)
	{
		user.verifier = std::string(reinterpret_cast<const char*>(sqlite3_column_text(statement, 0)));
		user.srpGroup = std::string(reinterpret_cast<const char*>(sqlite3_column_text(statement, 1)));
		if ((user.verifier == userdata.verifier) && (user.srpGroup == userdata.srpGroup))
		{
			sqlite3_finalize(statement);
			return true;
		}
	}
	sqlite3_finalize(statement);
	return false;
}


/*
function receives sql statement, callback function, and data pointer and executes the sql query and returns the returned value back
input: 
	const std::string& statement - a reference to the sql statement
	int(*callback)(void*, int, char**, char**) - pointer to call back function
	void* data - data pointer
output:
	returned value from sql query
*/
int Database::executeSqlQuery(const std::string& statement, int(*callback)(void*, int, char**, char**), void* data)
{
	const char* sqlStatement = statement.c_str();
	char** errMessage = nullptr;
	int res = sqlite3_exec(this->_database, sqlStatement, callback, data, errMessage);
	return res;
}