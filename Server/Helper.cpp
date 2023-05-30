#include "Helper.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

using std::string;

/*
Returns the message type code received from a socket.

input:
SOCKET sc - the socket from which the message is received.

output:
int - the message type code received.

throws:
No exceptions.
*/
int Helper::getMessageTypeCode(const SOCKET sc)
{
	std::string msg = getPartFromSocket(sc, 1, 0);

	if (msg == "")
		return 0;

	return  ((int)msg[0]);
}

/*
Sends a message to a client with update information about a file and other users connected to the server.

input:
SOCKET sc - the socket to send the message to
const string& file_content - the content of the file that was updated
const string& second_username - the username of the user who made the update
const string& all_users - a list of all connected users

output:
none

throws:
std::exception - if an error occurs while sending the message to the client
*/
void Helper::send_update_message_to_client(const SOCKET sc, const string& file_content, const string& second_username, const string& all_users)
{
	//TRACE("all users: %s\n", all_users.c_str())
	const string code = std::to_string(MT_SERVER_UPDATE);
	const string current_file_size = getPaddedNumber(file_content.size(), 5);
	const string username_size = getPaddedNumber(second_username.size(), 2);
	const string all_users_size = getPaddedNumber(all_users.size(), 5);
	const string res = code + current_file_size + file_content + username_size + second_username + all_users_size + all_users;
	//TRACE("message: %s\n", res.c_str());
	sendData(sc, res);
}

/*
The function receives a socket and a number of bytes and returns an integer that was sent by the socket.

input:
SOCKET sc - the socket that received the integer
int bytesNum - the number of bytes that the integer is composed of

output:
int - the integer that was received from the socket

throws:
std::exception - if an error occurs while receiving the integer from the socket
*/
int Helper::getIntPartFromSocket(const SOCKET sc, const int bytesNum)
{
	return bytesToInt(getPartFromSocket(sc, bytesNum, 0));
}

/*
Converts a string of bytes to an integer value.

input:
bytes - a string of bytes to convert

output:
int - the integer value obtained from the input bytes

throws:
No exception is thrown by this function.
*/
int Helper::bytesToInt(std::string bytes)
{
	int result = 0;
	std::istringstream ss(bytes);
	char byte;
	while (ss.get(byte)) {
		result = (result << 8) + static_cast<unsigned char>(byte);
	}
	return result;
}

/*
This function receives a socket descriptor and the number of bytes to read from it, and returns the received data as a string.

input:
const SOCKET sc - socket descriptor.
const int bytesNum - the number of bytes to read from the socket.

output:
std::string - the received data as a string.
*/
string Helper::getStringPartFromSocket(const SOCKET sc, const int bytesNum)
{
	return getPartFromSocket(sc, bytesNum, 0);
}

/*
The function receives an integer and a number of digits, and pads the integer with leading zeros until it has the specified number of digits.

input:
const int num - the integer to be padded
const int digits - the desired number of digits after padding

output:
std::string - the padded integer as a string
*/
string Helper::getPaddedNumber(const int num, const int digits)
{
	std::ostringstream ostr;
	ostr << std::setw(digits) << std::setfill('0') << num;
	return ostr.str();

}

/*

This function receives a socket and the number of bytes to receive from it.
It returns a string containing the received data.

input:
SOCKET sc - the socket to receive data from.
int bytesNum - the number of bytes to receive.

output:
std::string - the received data as a string.

throws:
std::exception - if there was an error while receiving from the socket.
*/
std::string Helper::getPartFromSocket(const SOCKET sc, const int bytesNum)
{
	return getPartFromSocket(sc, bytesNum, 0);
}

/*
The function sends data to the provided socket.

input:
const SOCKET sc - the socket to send data to
const std::string message - the message to send

output:
None
*/
void Helper::sendData(const SOCKET sc, const std::string message)
{
	const char* data = message.c_str();

	if (send(sc, data, message.size(), 0) == INVALID_SOCKET)
	{
		throw std::exception("Error while sending message to client");
	}
}

/*

The function receives a socket, a number of bytes to receive, and flags for the recv() function.
It reads bytesNum bytes from the socket and returns the received data as a string.
If an error occurs during the receiving process, an exception is thrown.

input:
SOCKET sc - the socket to receive data from
const int bytesNum - the number of bytes to receive
const int flags - the flags parameter for the recv() function

output:
std::string - the received data as a string

throws:
std::exception - if an error occurs while receiving data from the socket
*/
std::string Helper::getPartFromSocket(const SOCKET sc, const int bytesNum, const int flags)
{
	if (bytesNum == 0)
	{
		return "";
	}

	char* data = new char[bytesNum + 1];
	int res = recv(sc, data, bytesNum, flags);
	if (res == INVALID_SOCKET)
	{
		std::string s = "Error while receiving from socket: ";
		s += std::to_string(sc);
		throw std::exception(s.c_str());
	}
	data[bytesNum] = 0;
	std::string received(data, bytesNum);
	delete[] data;
	return received;
}
