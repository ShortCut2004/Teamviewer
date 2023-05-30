import time

import srt_client
import srt_host
import remote_control_connector
import remote_control_host
import srp
import socket
import threading
import CustomDataStructures as structs

#   Constants
bufferSize = 1024
data_queue = structs.DequeQueue(0)
queue_lock = threading.Lock()
condition = threading.Event()

#   Constant Variables - Message Codes
STOP = 0
GET_NEXT_FRAME = 1
INITIALIZE_SOCKET = 2
CREATE_INITIAL_KEYS_EXCHANGE_HANDLER = 3
REGISTRATION_HANDLER = 4
VERIFICATION_HANDLER = 5
VERIFICATION_KEYS_HANDLER = 6
SET_PASSWORD = 7
SET_USER_NAME = 8
SET_EMAIL = 9
GET_PASSWORD = 10
GET_USER_NAME = 11
GET_EMAIL = 12
INITIALIZE_INFO_FOR_REGISTRATION = 13
RUN_HOST = 14
RUN_CONNECTOR = 15
START_KEYBOARD_CONTROL = 16
START_MOUSE_CONTROL = 17
START_TRANSMISSION_HOST = 18
START_TRANSMISSION_CONNECTOR = 19
STOP_KEYBOARD_CONTROL = 20
STOP_MOUSE_CONTROL = 21
STOP_TRANSMISSION = 22
Null = 23
Message = 24
ScreenMsg = 25
login = 26
Error = 27
IP_REQUEST_HANDLER = 28
IP_RESPONSE_PEER_HANDLER = 29
SET_IP = 30
STOP_LISTENING_FOR_REQUESTS = 31
SIGN_OUT = 32
DELETE_ACCOUNT = 33
ALLOW_CONNECTION_REQUEST = 34
DENY_CONNECTION_REQUEST = 35
logout = 36
START_LISTENING = 37

#   global variables
srt_client_connector = 0
srt_client_host = 0
remote_control_host_side = 0
remote_control_connector_side = 0
srp_client = 0
sock = 0
connector = False


class DataMessage:
    def __init__(self, data):
        self._user_name = ""
        self._message_data = ""
        self._message_code = 0

        if data is not None:
            try:
                self._message_code = int.from_bytes(data[0:4], 'little')
                name_length = int.from_bytes(data[4:8], 'little')
                msg_length = int.from_bytes(data[8:12], 'little')
                if name_length > 0:
                    try:
                        self._user_name = data[12:12 + name_length].decode()
                    except Exception:
                        pass
                if msg_length > 0:
                    try:
                        self._message_data = data[12 + name_length:12 + name_length + msg_length].decode()
                    except Exception:
                        self._message_data = data[12 + name_length:12 + name_length + msg_length]
            except Exception as e:
                print("Exception caught while trying to deserialize data - " + str(e))

    def to_bytes(self):
        """
        Converts the message object to bytes for sending over the network.
        The resulting bytes include the message code, the length of the username and message data, and the encoded username and message data.
        Returns the resulting bytes.

        :return: The object's data converted to bytes
        :rtype: bytearray
        """

        return int(self._message_code).to_bytes(4, 'little') + len(self._user_name).to_bytes(4, 'little') + len(
            self._message_data).to_bytes(4, 'little') + self._user_name.encode() + self._message_data


def data_receiver_thread():
    """
    The function receives data from a socket, and puts the received data inside a queue object
    """
    while True:
        temp = sock.recv(bufferSize)
        data = DataMessage(temp)
        if data._message_code != login:
            queue_lock.acquire()
            data_queue.put(data)
            queue_lock.release()
        if not (data_queue.empty()):
            condition.set()


def start_srt_protocol(connector, srt_client_connector, srt_client_host):
    """
    Starts the SRT protocol for screen sharing and messaging between clients.
    :param connector: True if client is connecting to another client, False if client is hosting
    :type connector: bool
    :param srt_client_connector: SRT client connector object
    :type srt_client_connector: SrtClientConnector
    :param srt_client_host: SRT client host object
    :type srt_client_host: SrtClientHost
    :return: None
    """
    if connector:
        try:
            threading.Thread(target=srt_client_connector.run_connector, args=(srt_client_connector,)).start()
            threading.Thread(target=send_screen_image_thread, args=(srt_client_connector,)).start()
            threading.Thread(target=send_messages_thread, args=(srt_client_connector,)).start()

        except Exception:
            pass
    else:
        try:
            threading.Thread(target=srt_client_host.run_host, args=(srt_client_host,)).start()
            threading.Thread(target=send_messages_thread, args=(srt_client_host,)).start()

        except Exception:
            pass


def send_screen_image_thread(srt_client):
    """
     Sends screen images from the SRT client to another SRT client in a separate thread.
     :param srt_client: SRT client object
     :type srt_client: SrtClient
     :return: None
     """

    temp_response = DataMessage(None)
    while True:
        if srt_client._received_frame_buffer.empty():
            srt_client._received_frame_event.clear()
            srt_client._received_frame_event.wait()

        while not (srt_client._received_frame_buffer.empty()):
            try:
                temp_response._message_data = srt_client.get_next_frame()
                temp_response._message_code = ScreenMsg
                temp_response._user_name = srt_client._user_name
                sock.sendall(temp_response.to_bytes())
            except Exception:
                pass


def send_messages_thread(srt_client):
    """
    Sends chat messages from the SRT client to another SRT client in a separate thread.
    :param srt_client: SRT client object
    :type srt_client: SrtClient
    :return: None
    """

    temp_response = DataMessage(None)
    while True:
        if srt_client._chat_messages.empty():
            srt_client._received_chat_message_event.wait()
            srt_client._received_chat_message_event.clear()

        while not (srt_client._chat_messages.empty()):
            try:
                temp_response._message_data = srt_client.get_next_message().encode()
                temp_response._message_code = Message
                temp_response._user_name = ""
                sock.sendall(temp_response.to_bytes())
            except Exception as e:
                print(e)


def create_message(code, data):
    """
    Creates a binary message to be sent to the other SRT client.

    :param code: The message code.
    :type code: int
    :param data: The message data.
    :type data: bytes
    :return: The binary message.
    :rtype: bytes
    """

    temp_response = DataMessage(None)
    temp_response._message_code = code
    temp_response._message_data = data
    return temp_response.to_bytes()


def wait_for_requests(srp_client):
    """
    Waits for incoming connection requests from other clients, and sends back an IP response message with the
    username of the requester in a separate thread.

    :param srp_client: SRP client object
    :type srp_client: SrpClient
    :return: None
    """

    global sock
    temp_request = ""
    while srp_client._listening_condition:
        if srp_client._requests_queue.empty():
            srp_client._received_request_event.wait()
            srp_client._received_request_event.clear()
        else:
            with srp_client._requests_lock:
                temp_request = srp_client._requests_queue.get()
            sock.sendall(create_message(IP_RESPONSE_PEER_HANDLER,
                                        temp_request.encode()))  # Sending the user name of the user who requested a connection


def code_switch_case(data):
    """
    The function performs a switch case on the received data, the function runs the correct method according to the data it received
    :param data: the data received
    :type data: DataMessage
    :return: None
    :rtype: None
    """
    global srt_client_connector, srt_client_host, srp_client, remote_control_host_side, remote_control_connector_side, sock, connector

    code = data._message_code
    if code == STOP:
        var = False
    elif code == GET_NEXT_FRAME:
        sock.sendall(create_message(ScreenMsg, srt_client_connector.get_next_frame()))
    elif code == INITIALIZE_SOCKET:
        srp_client.initialize_socket()
    elif code == CREATE_INITIAL_KEYS_EXCHANGE_HANDLER:
        srp_client.create_initial_keys_exchange_handler()
    elif code == REGISTRATION_HANDLER:
        temp = srp_client.registration_handler()
        if temp[0]:
            sock.sendall(create_message(REGISTRATION_HANDLER, "1".encode()))
        else:
            sock.sendall(create_message(REGISTRATION_HANDLER, "0".encode()))
            sock.sendall(create_message(Error, temp[1].encode()))
    elif code == VERIFICATION_HANDLER:
        temp = srp_client.login()
        if temp[0]:
            sock.sendall(create_message(VERIFICATION_HANDLER, "1".encode()))
        else:
            sock.sendall(create_message(VERIFICATION_HANDLER, "0".encode()))
            sock.sendall(create_message(Error, temp[1].encode()))
    elif code == SET_PASSWORD:
        srp_client.set_password(data._message_data)
    elif code == SET_USER_NAME:
        srp_client.set_user_name(data._message_data)
    elif code == SET_EMAIL:
        srp_client.set_email(data._message_data)
    elif code == GET_PASSWORD:
        sock.sendall(create_message(GET_PASSWORD, srp_client.get_password().encode()))
    elif code == GET_USER_NAME:
        sock.sendall(create_message(GET_USER_NAME, srp_client.get_user_name().encode()))
    elif code == GET_EMAIL:
        sock.sendall(create_message(GET_EMAIL, srp_client.get_email().encode()))
    elif code == RUN_HOST:
        connector = False
        threading.Thread(target=remote_control_host.remote_control_host.start_remote_control_host,
                         args=(remote_control_host_side,)).start()
        time.sleep(5)
        start_srt_protocol(connector, srt_client_connector, srt_client_host)
    elif code == RUN_CONNECTOR:
        connector = True
        start_srt_protocol(connector, srt_client_connector, srt_client_host)
        threading.Thread(
            target=remote_control_connector.remote_control_connector.start_remote_control_connector,
            args=(remote_control_connector_side,)).start()
    elif code == START_TRANSMISSION_HOST:
        srt_client_host.start_transmission_host()
    elif code == START_TRANSMISSION_CONNECTOR:
        srt_client_connector.start_transmission_connector()
    elif code == STOP_TRANSMISSION:
        if connector:
            srt_client_connector.stop_transmission()
        else:
            srt_client_host.stop_transmission()
    elif code == SET_IP:
        srt_client_host._ip = data._message_data
        srt_client_connector._ip = data._message_data
    elif code == STOP_LISTENING_FOR_REQUESTS:
        temp = srp_client.stop_listening()
        if temp[0]:
            sock.sendall(create_message(STOP_LISTENING_FOR_REQUESTS, "1".encode()))
        else:
            sock.sendall(create_message(STOP_LISTENING_FOR_REQUESTS, "0".encode()))
            sock.sendall(create_message(Error, temp[1].encode()))
    elif code == SIGN_OUT:
        temp = srp_client.logout()
        if temp[0]:
            sock.sendall(create_message(SIGN_OUT, "1".encode()))
        else:
            sock.sendall(create_message(SIGN_OUT, "0".encode()))
            sock.sendall(create_message(Error, temp[1].encode()))
    elif code == DELETE_ACCOUNT:
        temp = srp_client.signout()
        if temp[0]:
            sock.sendall(create_message(DELETE_ACCOUNT, "1".encode()))
        else:
            sock.sendall(create_message(DELETE_ACCOUNT, "0".encode()))
            sock.sendall(create_message(Error, temp[1].encode()))
    elif code == START_LISTENING:
        temp = srp_client.initiate_listening()
        if temp[0]:
            threading.Thread(target=srp_client.ip_response_peer_handler, args=(srp_client,)).start()
            threading.Thread(target=wait_for_requests, args=(srp_client,)).start()
            sock.sendall(create_message(START_LISTENING, "1".encode()))
        else:
            sock.sendall(create_message(START_LISTENING, "0".encode()))
            sock.sendall(create_message(Error, temp[1].encode()))
    elif code == ALLOW_CONNECTION_REQUEST:
        temp = srp_client.accept_connection()
        if temp[0]:
            sock.sendall(create_message(ALLOW_CONNECTION_REQUEST, "1".encode()))
            srt_client_host._user_name = srp_client.get_user_name()  # setting the user name of the srt transmission to be the same as the srp
            srt_client_host._ip = temp[1]  # Setting the ip as the ip of the srt protocol part
            remote_control_host_side._ip = temp[1]  # Setting the ip as the ip of the remote control part
        else:
            sock.sendall(create_message(ALLOW_CONNECTION_REQUEST, "0".encode()))
            sock.sendall(create_message(Error, temp[1].encode()))
    elif code == Message:
        if connector:
            srt_client_connector.send_chat_message(data._message_data)
        else:
            srt_client_host.send_chat_message(data._message_data)
    elif code == IP_REQUEST_HANDLER:
        temp = srp_client.ip_request_handler(data._message_data)
        if temp[0]:
            sock.sendall(create_message(IP_REQUEST_HANDLER, "1".encode()))
            srt_client_connector._user_name = srp_client.get_user_name()  # setting the user name of the srt transmission to be the same as the srp
            srt_client_connector._ip = temp[1]  # Setting the ip as the ip of the srt protocol part
            remote_control_connector_side._ip = temp[1]  # Setting the ip as the ip of the remote control part
        else:
            sock.sendall(create_message(IP_REQUEST_HANDLER, "0".encode()))
            sock.sendall(create_message(Error, temp[1].encode()))
    else:
        print(code)
        print("ERROR - Unknown Code!")


def main():
    """
    The main function - runs the receiver thread and uses objects accordingly
    """
    global srt_client_connector, srt_client_host, srp_client, remote_control_host_side, remote_control_connector_side, sock, connector

    listening_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # initializing objects
    srp_client = srp.srp("127.0.0.1", 8080)
    srt_client_host = srt_host.srt_host("192.168.1.38", 8082, 11, "host")
    srt_client_connector = srt_client.srt_connector("192.168.1.50", 8081, 11, "connector")
    remote_control_host_side = remote_control_host.remote_control_host("192.168.1.38")
    remote_control_connector_side = remote_control_connector.remote_control_connector("192.168.1.50")

    listening_sock.bind(('127.0.0.1', 10048))
    listening_sock.listen()
    sock, client_address = listening_sock.accept()

    receiver_thread = threading.Thread(target=data_receiver_thread, args=())
    receiver_thread.start()
    connector = True  # boolean value indicating if the client is the connector - temp
    var = True
    try:
        srp_client.initialize_socket()
        srp_client.create_initial_keys_exchange_handler()
    except Exception:
        pass
    while var:
        try:
            if data_queue.empty():
                condition.clear()
                condition.wait()
                print("Thread was woken up")

            if not data_queue.empty():
                queue_lock.acquire()
                data = data_queue.get()
                queue_lock.release()
                code_switch_case(data)
        except Exception as e:
            print("Exception caught - " + str(e))


if __name__ == "__main__":
    main()
