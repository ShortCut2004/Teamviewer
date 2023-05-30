#include "JsonRequestPacketDeserializer.h"

/*
Deserialize a login request from a given buffer, which contains JSON data. Extracts the "user_name" and "email" fields from the JSON data and stores them in a userData struct.

input:
buffer& buffer - a reference to the buffer containing the JSON data

output:
userData - a userData struct containing the "user_name" and "email" fields extracted from the JSON data

throws:
None - any errors encountered during deserialization will be caught and handled internally.
*/
userData JsonRequestPacketDeserializer::deserializeLoginRequest(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	userData returnVar;

	try
	{
		returnVar.username = data["user_name"];
		returnVar.email = data["email"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing Login Request" << std::endl;
	}
	return returnVar;
}

/*
Deserializes a Signup Request from a buffer and returns the user data.

input:
buffer& buffer - a reference to the buffer to deserialize

output:
userData - the user data extracted from the buffer
*/
userData JsonRequestPacketDeserializer::deserializeSignupRequest(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	userData returnVar;

	try
	{
		returnVar.salt = data["salt"];
		returnVar.srpGroup = data["srp_group"];
		returnVar.username = data["user_name"];
		returnVar.email = data["email"];
		returnVar.verifier = data["verifier"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing Signup Request" << std::endl;
	}
	return returnVar;
}

/*
Deserializes a SecondPhaseMessageVerificationResponse object from a given buffer.

input:
buffer& buffer - a reference to the buffer containing the data to be deserialized.

output:
userData - a struct containing the deserialized data.

throws:
none
*/
userData JsonRequestPacketDeserializer::deserializeSecondPhaseMessageVerificationResponse(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	userData returnVar;

	try
	{
		returnVar.srpGroup = data["srp_group"];
		returnVar.verifier = data["verifier"];
		returnVar.encryptionKey = data["encryption_key"];
		returnVar.username = data["user_name"];
		returnVar.ip = data["ip"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing Verification of Keys Request" << std::endl;
	}
	return returnVar;
}

/*
Brief description of what the function does and how it works

input:
buffer& buffer - a reference to the buffer that contains the serialized data

output:
logOutRequest - a struct that contains the username of the user who wants to log out

throws:
none
*/
logOutRequest JsonRequestPacketDeserializer::deserializelogOutRequestRequest(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	logOutRequest returnVar;

	try
	{
		returnVar.username = data["user_name"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing Logout Request" << std::endl;
	}
	return returnVar;
}

/*
Function deserializes Sign Out request buffer and returns a signOutRequest object

Input:
buffer& buffer - a reference to the buffer holding the request data

Output:
signOutRequest - an object representing the Sign Out request, including the username of the user who initiated the request
*/
signOutRequest JsonRequestPacketDeserializer::deserializeSignOutRequestRequest(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	signOutRequest returnVar;

	try
	{
		returnVar.username = data["user_name"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing Signout Request" << std::endl;
	}
	return returnVar;
}

/*
Function deserializes a request for salt and SRP group from a JSON buffer.
The function parses the JSON data and returns a userData object containing the email field.

input:
buffer& buffer - a reference to the buffer containing the JSON data.

output:
userData - a userData object containing the email field.

throws:
None
*/
userData JsonRequestPacketDeserializer::deserializeSaltAndSrpGroupRequest(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	userData returnVar;

	try
	{
		returnVar.email = data["email"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing Login Request" << std::endl;
	}
	return returnVar;
}

/*
Deserializes a buffer to an object of type userData containing the peer username and username.

input:
buffer& buffer - a reference to the buffer to deserialize

output:
userData - an object of type userData containing the peer username and username
*/
userData JsonRequestPacketDeserializer::deserializeIpRequestMessage(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	userData returnVar;

	try
	{
		returnVar.username = data["user_name"];
		returnVar.peerUsername = data["peer_user_name"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing Ip Request" << std::endl;
	}
	return returnVar;
}

/*
Deserialize an incoming message that contains IP response of a peer.

input:
buffer& buffer - reference to the received buffer.

output:
userData - a userData struct containing the data from the deserialized message.
*/
userData JsonRequestPacketDeserializer::deserializeIpResponseMessage(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	userData returnVar;

	try
	{
		returnVar.peerUsername = data["user_name"];
		returnVar.username = data["peer_user_name"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing Ip Response Of Peer" << std::endl;
	}
	return returnVar;
}

/*
Deserialize the buffer to an initiate listening request

input:
buffer - the buffer that contains the initiate listening request

output:
userData - a userData struct that contains the username of the client that initiates the listening request
*/
userData JsonRequestPacketDeserializer::deserializeInitiateListening(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	userData returnVar;

	try
	{
		returnVar.username = data["user_name"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing Ip Response Of Peer" << std::endl;
	}
	return returnVar;
}

/*
Deserializes a Check Request packet from a buffer.

input:
buffer - a reference to a buffer object containing the message bytes.

output:
userData - a struct containing the parsed username and peer username from the message.
*/
userData JsonRequestPacketDeserializer::deserializeCheckRequest(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	userData returnVar;

	try
	{
		returnVar.username = data["user_name"];
		returnVar.peerUsername = data["peer_user_name"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing Ip Response Of Peer" << std::endl;
	}
	return returnVar;
}

/*
This function deserializes a message containing socket and user information to be used to get the IP address of a peer user.

input:
buffer - the buffer containing the serialized message to deserialize.

output:
userData - a struct containing the socket, username, and peer username information from the message.

throws:
none
*/
userData JsonRequestPacketDeserializer::deserializeSocketForIpRequest(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	userData returnvar;

	try
	{
		returnvar.socket = std::stoi((std::string)data["socket"]);
		returnvar.username = data["peer_user_name"];
		returnvar.peerUsername = data["user_name"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing Socket for Ip Request" << std::endl;
	}
	return returnvar;
}

/*
Deserialize the message code from the buffer.
input:
buffer - A vector containing the message buffer to deserialize.

output:
int - The message code.

throws:
None.
*/
int JsonRequestPacketDeserializer::deserializeMessageCode(buffer buffer)
{
	json data = getMessageFromVector(buffer);
	int returnVar = 0;

	try
	{
		returnVar = std::stoi((std::string)data["code"]);
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing code of message" << std::endl;
	}
	return returnVar;
}

/*
This function deserializes the encryption key from a given buffer.

input:

buffer: a buffer containing the serialized encryption key
output:

returnVar: a string containing the encryption key
throws:

This function does not throw any exceptions.
*/
std::string JsonRequestPacketDeserializer::deserializeKeyResponse(buffer& buffer)
{
	json data = getMessageFromVector(buffer);
	userData returnVar;

	try
	{
		returnVar.encryptionKey = data["encryption_key"];
	}
	catch (...)
	{
		std::cerr << "Encountered an error when deserializing initial key Request" << std::endl;
	}
	return returnVar.encryptionKey;
}

/*
getting the message out of the vector
Input: std::vector<unsigned char>& vectorToGetFrom
Output: json - the message
*/
json JsonRequestPacketDeserializer::getMessageFromVector(buffer& vectorToGetFrom)
{
	std::string jsonData = "";

	for (int i = 0; i < vectorToGetFrom.size(); i++)
	{
		jsonData += vectorToGetFrom[i];
	}

	return parseString(jsonData);
}

/*
Parses a string into a JSON object. The string should be in the format "key1": "value1", "key2": "value2", ...
and the function returns a JSON object containing the key-value pairs.

Input:

data: a string representing a JSON object in the format "key1": "value1", "key2": "value2", ...
Output:

a JSON object containing the key-value pairs parsed from the input string.
*/
json JsonRequestPacketDeserializer::parseString(std::string& data)
{
	json msg;
	std::string field = "";
	std::string dataValue = "";
	bool var = false;
	for (int i = 1; i < data.length() - 1; i++)
	{
		if (data[i] != '\"' && data[i] != ':' && data[i] != ',' && !std::isspace(data[i]))
		{
			if (!var)
			{
				field += data[i];
			}
			else
			{
				dataValue += data[i];
			}
		}
		else if (data[i] == ':')
		{
			var = true;
		}
		else if (data[i] == ',')
		{
			msg[field] = dataValue;
			field = "";
			dataValue = "";
			var = false;
		}
	}
	msg[field] = dataValue;
	return msg;
}