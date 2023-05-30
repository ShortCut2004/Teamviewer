#pragma once
#include "Database.h"
#include "IRequestHandler.h"
#include "JsonRequestPacketDeserializer.h"
#include "CreateKeysHandler.h"

class Database;


class RegistrationHandler : public IRequestHandler
{
public:
	RegistrationHandler(Database* database);
	virtual bool isRequestRelevant(requestInfo reqInfo);
	virtual requestResult handleRequest(requestInfo reqInfo);
private:
	requestResult registeration(requestInfo reqInfo);
	Database* _db;
};
