#pragma once
#include "sqlite3.h"
#include "io.h"
#include <iostream>
#include <string>
#include <list>
#include <vector>
#include "JsonRequestPacketDeserializer.h"
#include <atomic>

typedef struct userData userData;

class Database
{
public:

	//ctor and dtor
	Database();
	~Database();

	//queries
	bool addNewUser(const userData& userdata) const;
	bool doesUserExist(const userData& userdata) const;
	bool doesEmailExist(const userData& userdata) const;
	bool deleteUser(const std::string& username) const;
	bool doesVerifierAndSrpGroupSuitable(const userData& userdata) const;

	userData getSaltAndSrpGroupByEmail(const userData& userdata) const;
	userData getSaltByEmail(const userData& userdata) const;

	//general
	bool open();
	void clear();
	void close();

private:
	sqlite3* _database;
	int executeSqlQuery(const std::string& statement, int(*callback)(void*, int, char**, char**), void* data);
};
