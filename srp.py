import socket
import json
import secrets
import base64
import ipaddress
import netifaces
import threading
import queue
import time

import Crypto.Protocol.KDF
import Crypto.Hash.SHA512
import Crypto.Random
from Crypto.PublicKey import RSA as key_class
from Crypto.Cipher import PKCS1_OAEP

KEYS_CREATION = '1'
LOGIN = '11'
LOG_IN_SUCCESSFULLY = '12'
LOG_OUT = '13'
LOG_OUT_SUCCESSFULLY = '14'
REGISTRATION = '15'
SUCCESSFUL_REGISTRATION = '16'
SIGN_OUT = '17'
SIGN_OUT_SUCCESSFULLY = '18'

SALT_REQUEST = '21'
SUCCESSFUL_SALT_REQUEST = '22'
EXCHANGE_NEW_KEYS = '23'
EXCHANGE_NEW_KEYS_SUCCESSFUL = '24'
VERIFICATION_MESSAGE = '25'
SUCCESSFUL_VERIFICATION_FOR_MESSAGE = '26'

IP_REQUEST = '31'
IP_REQUEST_FROM_PEER = '32'
IP_RESPONSE_FROM_PEER = '33'
IP_RESPONSE = '34'
CHECK_FOR_REQUEST = '35'
REQUEST_SENT_SUCCESSFULLY = '36'
CANCEL_REQUEST = '37'
CANCEL_REQUEST_SUCCESSFULLY = '38'

ERROR_CODE = '41'

LISTEN_REQUEST = '51'
LISTEN_ACCEPTED = '52'
STOP_LISTENING = '53'
STOPPED_SUCCESSFULLY = '54'

SERVER_IP = "127.0.0.1"  # The server's hostname or IP address
PORT = 8080  # The port used by the server

NUM_OF_ITERATIONS = 1000000
INDEX_OF_PASSWORD = 1
INDEX_OF_USER_NAME = 0
INDEX_OF_EMAIL = 2
SIZE_OF_REGISTRATION_INFO = 64
SIZE_OF_KEYS = 32
NUM_OF_BYTES_FOR_SALT = 16
NUM_OF_BYTES_TO_RECV = 2048
SIZE_OF_KEY_IN_BITS = 512
OAEP_PADDING_OVERHEAD = 42
START_OF_DESERIALIZATION = 5
COUNTER_FOR_ERROR_CASES = 3
RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE = 2048

SRP_PRIME = int("0x6fb66ed0e00d6b33bf691b4081a2329fc5b0d04c933ac693e4e32cf5d9161ac5", 16)


class srp:
    def __init__(self, server_ip, tcp_port):
        self._received_request_event = threading.Event()
        self._requests_queue = queue.Queue()
        self._requests_lock = threading.Lock()
        self._received_packets = queue.Queue()
        self._received_packet_event = threading.Event()
        self._received_packets_lock = threading.Lock()
        self._request_event = threading.Event()
        self._other_packet_event = threading.Event()
        self._ip_response_event = threading.Event()
        self._decryption_key = None  # self decryption key
        self._encryption_key = None  # other side's encryption key
        self._tcp_port = tcp_port
        self._server_ip = server_ip
        self._tcp_sock = None
        self._user_name = None
        self._email = None
        self._password = None
        self._salt = None
        self._verifier = None
        self._srp_group = None
        self._listening_condition = True
        self._peer_user_name = None

    def initialize_socket(self):
        """
           Initializes a TCP socket for the SRT client and connects to the specified server IP and port.
           :return: None
        """
        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_sock.connect((self._server_ip, self._tcp_port))

    def create_initial_keys_exchange_handler(self):
        """
           Creates an initial keys exchange with the other party over the TCP socket using the SRP protocol.
           :return: True if the exchange was successful and encryption and decryption keys were imported, False otherwise
        """
        try:
            count = 0
            while count < COUNTER_FOR_ERROR_CASES:
                public_key, self._decryption_key = srp.generate_keypair()

                # Send the public key to the other party over the TCP socket
                msg = srp.serialize_creation_keys(public_key)
                self._tcp_sock.sendall(msg)

                # Receive the other party's public key over the TCP socket, decrypt it using the private key, and import it
                received_data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                decrypted_data = srp.rsa_decryption(received_data, self._decryption_key)
                deserialized_data = srp.deserialization(decrypted_data)
                code = deserialized_data["code"]
                if code == KEYS_CREATION:
                    self._encryption_key = key_class.import_key(deserialized_data["encryption_key"]).export_key()
                    return True
                count += 1
            return False
        except Exception as e:
            print("create_initial_keys_exchange_handler -", str(e))
            return False

    def registration_handler(self):
        """
           Sends registration information to the server using the SRP protocol.
           :return: Tuple containing True if registration was successful and an empty string, False if it failed and an error message
        """
        try:
            count = 0
            deserialized_data = ""
            while count < COUNTER_FOR_ERROR_CASES:
                srp.get_random_salt(self)
                srp.calculateVerifierAndSrpGroup(self, bytes.fromhex(self._salt))
                message = srp.serialize_info_for_registration(self._user_name, self._verifier, self._srp_group,
                                                              self._salt, self._email)
                message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(message)
                received_data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                decrypted_data = srp.rsa_decryption(received_data, self._decryption_key)
                deserialized_data = srp.deserialization(decrypted_data)
                code = deserialized_data["code"]
                if code == SUCCESSFUL_REGISTRATION:
                    return (True, "")
                count += 1
            return (False, deserialized_data["message"])
        except Exception as e:
            print("registration_handler -", str(e))
            return (False, "ERROR")

    def login_handler(self):
        """
        Handles the process of logging in to the server by sending the user's login information, receiving and processing
        the server's response, and returning a tuple indicating whether the login was successful and a message if necessary.
        :return: A tuple containing a boolean indicating whether the login was successful, and a message.
        :rtype: tuple(bool, str)
        """
        try:
            count = 0
            deserialized_data = ""
            while count < COUNTER_FOR_ERROR_CASES:
                message = srp.serialize_info_for_login(self._user_name, self._email)
                message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(message)
                received_data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                decrypted_data = srp.rsa_decryption(received_data, self._decryption_key)
                deserialized_data = srp.deserialization(decrypted_data)
                code = deserialized_data["code"]
                if code == LOG_IN_SUCCESSFULLY:
                    self._salt = deserialized_data["salt"]
                    return (True, "")
                count += 1
            return (False, deserialized_data["message"])
        except Exception as e:
            print("login_handler -", str(e))
            return (False, "ERROR")

    def logout(self):
        """
        Logs out of the server using the SRP protocol.
        :return: Tuple containing True if logout was successful and an empty string, False if it failed and an error message
        """
        try:
            count = 0
            deserialized_data = ""
            while count < COUNTER_FOR_ERROR_CASES:
                message = srp.serialize_info_for_logout(self._user_name)
                message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(message)
                received_data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                decrypted_data = srp.rsa_decryption(received_data, self._decryption_key)
                code = srp.deserialization(decrypted_data)["code"]
                if code == LOG_OUT_SUCCESSFULLY:
                    return (True, "")
                count += 1
            return (False, deserialized_data["message"])
        except Exception as e:
            print("logout_handler -", str(e))
            return (False, "ERROR")

    def signout(self):
        """
        Signs out of the server using the SRP protocol.
        :return: Tuple containing True if signout was successful and an empty string, False if it failed and an error message
        """
        try:
            count = 0
            deserialized_data = ""
            while count < COUNTER_FOR_ERROR_CASES:
                message = srp.serialize_info_for_signout(self._user_name)
                message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(message)
                received_data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                decrypted_data = srp.rsa_decryption(received_data, self._decryption_key)
                code = srp.deserialization(decrypted_data)["code"]
                if code == SIGN_OUT_SUCCESSFULLY:
                    return (True, "")
                count += 1
            return (False, deserialized_data["message"])
        except Exception as e:
            print("signout_handler -", str(e))
            return (False, "ERROR")

    def login(self):
        """
        The function performs the login procedure on the user
        """
        return_var = srp.login_handler(self)
        if return_var[0]:
            return_var = srp.verification_handler(self)
            if return_var[0]:
                return_var = srp.exchange_new_keys(self)
        return return_var

    def verification_handler(self):
        """
         Sends a verification message to the server using the SRP protocol to confirm salt and SRP group.
         :return: Tuple containing True if verification was successful and an empty string, False if it failed and an error message
         """
        try:
            count = 0
            deserialized_data = ""
            while count < COUNTER_FOR_ERROR_CASES:
                message = srp.serialize_verification(self._email)
                message = srp.rsa_encryption(message, self._encryption_key)
                srp.calculateVerifierAndSrpGroup(self, bytes.fromhex(self._salt))
                self._tcp_sock.sendall(message)
                received_data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                decrypted_data = srp.rsa_decryption(received_data, self._decryption_key)
                deserialized_data = srp.deserialization(decrypted_data)
                code = deserialized_data["code"]
                srp_group = deserialized_data["srp_group"]
                salt = deserialized_data["salt"]
                if code == SUCCESSFUL_SALT_REQUEST and srp_group == self._srp_group and salt == self._salt:
                    return (True, "")
                count += 1
            return (False, deserialized_data["message"])
        except Exception as e:
            print("verification_handler -", str(e))
            return (False, "ERROR")

    def exchange_new_keys(self):
        """
        Generates a new encryption keypair and sends a verification message to the server, then receives and processes the
        server's response. This is done to verify the server's authenticity and establish a secure connection.
        :return: A tuple containing a boolean indicating whether the operation was successful, and a message.
        :rtype: tuple(bool, str)
        """
        try:
            count = 0
            deserialized_data = ""
            while count < COUNTER_FOR_ERROR_CASES:
                message = srp.serialize_new_key_exchange_request()
                message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(message)
                received_data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                decrypted_data = srp.rsa_decryption(received_data, self._decryption_key)
                deserialized_data = srp.deserialization(decrypted_data)
                code = deserialized_data["code"]
                self._encryption_key = key_class.import_key(deserialized_data["encryption_key"]).export_key()
                if code == EXCHANGE_NEW_KEYS_SUCCESSFUL:
                    return srp.exchange_new_keys_and_verify_server(self)
                count += 1
            return (False, deserialized_data["message"])

        except Exception as e:
            print("exchange_new_keys -", str(e))
            return (False, "ERROR")

    def exchange_new_keys_and_verify_server(self):
        """
        Generates a new encryption keypair and sends a verification message to the server, then receives and processes the
        server's response. This is done to verify the server's authenticity and establish a secure connection.
        :return: A tuple containing a boolean indicating whether the operation was successful, and a message.
        :rtype: tuple(bool, str)
        """
        try:
            count = 0
            deserialized_data = ""
            while count < COUNTER_FOR_ERROR_CASES:
                encryption_key, self._decryption_key = srp.generate_keypair()
                ip = srp.get_ip_of_user()
                message = srp.serialize_verification_message(self._srp_group, self._verifier, self._user_name, str(ip),
                                                             encryption_key)
                organized_message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(organized_message)
                received_data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                decrypted_data = srp.rsa_decryption(received_data, self._decryption_key)
                deserialized_data = srp.deserialization(decrypted_data)
                code = deserialized_data["code"]
                if code == SUCCESSFUL_VERIFICATION_FOR_MESSAGE:
                    return (True, "")
                count += 1
            return (False, deserialized_data["message"])

        except Exception as e:
            print("exchange_new_keys_and_verify_server -", str(e))
            return (False, "ERROR")

    def ip_request_handler(self, peer_user_name):
        """
        Sends an IP request to a peer user and waits for a response. Returns a tuple indicating success and the IP if successful.
        :param peer_user_name: The name of the peer user to request an IP from.
        :type peer_user_name: str
        :return: Tuple indicating success (bool) and the IP (str) if successful, or error message (str) if unsuccessful.
        """
        try:
            count = 0
            data = ""
            self._peer_user_name = peer_user_name
            while count < COUNTER_FOR_ERROR_CASES:
                message = srp.serialize_ip_request(self._peer_user_name, self._user_name)
                organized_message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(organized_message)
                data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                data = srp.rsa_decryption(data, self._decryption_key)
                data = srp.deserialization(data)
                if data["code"] == REQUEST_SENT_SUCCESSFULLY:
                    return_var = srp.check_ip_request(self)
                    if return_var[0]:
                        return return_var
                    return srp.cancel_ip_request(self)
                count += 1
            return (False, data["message"])

        except Exception as e:
            print("ip_request_handler -", str(e))
            return (False, "ERROR")

    def check_ip_request(self):
        """
        Sends a check request to the peer user to obtain their IP address. Waits for the response from the peer user and returns
        the IP address if a valid response is received. If no valid response is received after a certain number of attempts, returns
        an error message.
        :return: A tuple containing a boolean indicating whether a valid response was received and either the IP address or error message.
        :rtype: tuple(bool, str)
        """
        try:
            count = 0
            data = ""
            while count < COUNTER_FOR_ERROR_CASES:
                time.sleep(5)
                message = srp.serialize_check_request(self._user_name, self._peer_user_name)
                organized_message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(organized_message)
                data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                data = srp.rsa_decryption(data, self._decryption_key)
                data = srp.deserialization(data)
                if data["code"] == IP_RESPONSE:
                    return (True, data["ip"])
                count += 1
            return (False, data["message"])

        except Exception as e:
            print("check_ip_request -", str(e))
            return (False, "ERROR")

    def cancel_ip_request(self):
        """
        Cancels an IP request made to a peer by sending a serialized cancel request to the peer.
        :return: A tuple indicating whether the request was successful or not, and a message describing the result.
        :rtype: tuple(bool, str)
        """
        try:
            count = 0
            data = ""
            while count < COUNTER_FOR_ERROR_CASES:
                message = srp.serialize_cancel_request(self._user_name, self._peer_user_name)
                organized_message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(organized_message)
                data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                data = srp.rsa_decryption(data, self._decryption_key)
                data = srp.deserialization(data)
                if data["code"] == CANCEL_REQUEST_SUCCESSFULLY:
                    return (True, data["message"])
                count += 1
            return (False, data["message"])

        except Exception as e:
            print("cancel_ip_request -", str(e))
            return (False, "ERROR")

    def ip_response_peer_handler(self, thread_obj):
        """
        Handles incoming IP response packets from peers. Updates the requests queue and sets the received_request_event when an IP request packet is received.
        :param thread_obj: The thread object.
        :type thread_obj: threading.Thread
        """
        try:
            while self._listening_condition:
                try:
                    self._request_event.wait()
                    self._request_event.clear()
                    if not self._listening_condition:
                        break
                    with self._received_packets_lock:
                        data = self._received_packets.get()
                    code = data["code"]
                    if code == IP_REQUEST_FROM_PEER:
                        self._peer_user_name = data["peer_user_name"]
                        with self._requests_lock:
                            self._requests_queue.put(data["peer_user_name"])
                        self._received_request_event.set()
                except socket.timeout as e:
                    pass

        except Exception as e:
            print("ip_response_peer_handler -", str(e))

    def initiate_listening(self):
        """
        Initiates the listening process for incoming connection requests.

        :return: A tuple containing a boolean value indicating whether the listening process was initiated successfully, and a
                 message string providing additional information about the result.
        :rtype: tuple of (bool, str)
        """
        try:
            count = 0
            deserialized_data = ""
            while count < COUNTER_FOR_ERROR_CASES:
                message = srp.serialize_listening_request(self._user_name)
                message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(message)
                received_data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
                decrypted_data = srp.rsa_decryption(received_data, self._decryption_key)
                deserialized_data = srp.deserialization(decrypted_data)
                code = deserialized_data["code"]
                if code == LISTEN_ACCEPTED:
                    self._listening_condition = True
                    threading.Thread(target=self.packet_receiver_thread, args=(self,)).start()
                    return (True, "Initiated listening successfully")
                count += 1
            return (False, deserialized_data["message"])
        except Exception as e:
            print("initiate_listening -", str(e))
            return (False, "ERROR")

    def packet_receiver_thread(self, thread_obj):
        """
        Listens for incoming packets on the TCP socket and processes them accordingly. Updates the appropriate events depending
        on the type of packet received.
        :param thread_obj: The thread object.
        :type thread_obj: threading.Thread
        """
        while self._listening_condition:
            # Receive data from the TCP socket and process it
            data = self._tcp_sock.recv(NUM_OF_BYTES_TO_RECV)
            data = srp.rsa_decryption(data, self._decryption_key)
            data = srp.deserialization(data)

            # Add the received packet to the queue of received packets
            with self._received_packets_lock:
                self._received_packets.put(data)

            # Set the request event if the received packet is an IP request from the peer user
            if data["code"] == IP_REQUEST_FROM_PEER:
                self._request_event.set()

            # Set the IP response event if the received packet is an IP response
            elif data["code"] == IP_RESPONSE:
                self._ip_response_event.set()

            # Set the other packet event if the received packet is any other type of packet
            else:
                self._other_packet_event.set()

            # Check if the received packet is a "stopped successfully" message and set the appropriate events and exit the loop
            if data["code"] == STOPPED_SUCCESSFULLY:
                self._other_packet_event.set()
                self._request_event.set()
                break

    def stop_listening(self):
        """
        Sends a request to stop listening for incoming connections to the server.
        :return: A tuple with a boolean indicating success or failure, and a string message.
                 If success is True, the message will be an empty string.
                 If success is False, the message will contain an error message.
        :rtype: tuple(bool, str)
        """
        try:
            count = 0
            deserialized_data = ""
            while count < COUNTER_FOR_ERROR_CASES:
                message = srp.serialize_stop_listening_request(self._user_name)
                message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(message)
                self._other_packet_event.wait()
                self._other_packet_event.clear()
                with self._received_packets_lock:
                    data = self._received_packets.get()
                code = data["code"]
                if code == STOPPED_SUCCESSFULLY:
                    self._listening_condition = False
                    return (True, "")
                count += 1
            return (False, deserialized_data["message"])
        except Exception as e:
            print("stop_listening -", str(e))
            return (False, "ERROR")

    def accept_connection(self):
        """
        Sends an IP peer request to the peer user and waits for a response. Returns a tuple indicating whether the
        connection was accepted and the IP address of the peer user (if the connection was accepted) or an error
        message (if the connection was not accepted).
        :return: A tuple indicating whether the connection was accepted
        and the IP address of the peer user (if the connection was accepted) or an error message (if the connection
        was not accepted).
        """
        try:
            count = 0
            message = ""
            while count < COUNTER_FOR_ERROR_CASES:
                # Send IP peer request to the peer user and wait for response
                message = srp.serialize_ip_peer_request(self._user_name, self._peer_user_name)
                organized_message = srp.rsa_encryption(message, self._encryption_key)
                self._tcp_sock.sendall(organized_message)
                self._ip_response_event.wait()
                self._ip_response_event.clear()
                with self._received_packets_lock:
                    message = self._received_packets.get()

                # Check if the received message is an IP response and return the IP address if it is
                if message["code"] == IP_RESPONSE:
                    return (True, message["ip"])

                # Increment the counter and try again if the received message is not an IP response
                count += 1

            # Return an error message if the connection could not be established after multiple attempts
            return (False, message["message"])

        except Exception as e:
            print("accept_connection -", str(e))
            return (False, "ERROR")

    @staticmethod
    def serialize_new_key_exchange_request():
        """
        This function creates a message requesting a new key exchange.
        :return: The serialized message in JSON format.
        :rtype: bytes
        """
        json_string = {"code": EXCHANGE_NEW_KEYS, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_ip_peer_request(user_name, peer_user_name):
        """
        This function creates a message requesting the IP address of a peer user.
        :param user_name: The name of the current user.
        :type user_name: str
        :param peer_user_name: The name of the peer user whose IP address is requested.
        :type peer_user_name: str
        :return: The serialized message in JSON format.
        :rtype: bytes
        """
        json_string = {"code": IP_RESPONSE_FROM_PEER, "user_name": user_name, "peer_user_name": peer_user_name,
                       "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_ip_peer_request_negative():
        """
        This function creates a message indicating that the request for the IP address of a peer user was unsuccessful.
        :return: The serialized message in JSON format.
        :rtype: bytes
        """
        json_string = {"code": ERROR_CODE, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_ip_request(peer_user_name, user_name):
        json_string = {"code": IP_REQUEST, "peer_user_name": peer_user_name, "user_name": user_name, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_creation_keys(encryption_key):
        """
        This function creates a message with a new encryption key for the client.
        :param encryption_key: The new encryption key.
        :type encryption_key: bytes
        :return: The serialized message in JSON format.
        :rtype: bytes
        """
        encryption_key = base64.b64encode(encryption_key).decode('utf-8')
        json_string = {"code": KEYS_CREATION, "encryption_key": encryption_key, "t": "1"}
        msg = json.dumps(json_string).encode('utf-8')
        return msg

    @staticmethod
    def serialize_verification_message(srp_group, verifier, user_name, ip, encryption_key):
        encryption_key = base64.b64encode(encryption_key).decode('utf-8')
        json_string = {"code": VERIFICATION_MESSAGE, "srp_group": srp_group, "verifier": verifier, "ip": ip,
                       "encryption_key": encryption_key, "user_name": user_name, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_info_for_registration(user_name, verifier, srp_group, salt, email):
        json_string = {"code": REGISTRATION, "user_name": user_name, "verifier": verifier,
                       "srp_group": srp_group,
                       "salt": salt, "email": email, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_info_for_login(user_name, email):
        """
        Serialize login data for server communication
        :return: bytes
        """
        json_string = {"code": LOGIN, "user_name": user_name, "email": email,
                       "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_info_for_logout(user_name):
        """
        Serialize logout data for server communication
        :return: bytes
        """
        json_string = {"code": LOG_OUT, "user_name": user_name, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_info_for_signout(user_name):
        """
        Serialize signout data for server communication
        :return: bytes
        """
        json_string = {"code": SIGN_OUT, "user_name": user_name, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_verification(email):
        """
        Serialize salt request data for server communication
        :return: bytes
        """
        json_string = {"code": SALT_REQUEST, "email": email, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_listening_request(user_name):
        """
        Serialize listening request data for server communication
        :return: bytes
        """
        json_string = {"code": LISTEN_REQUEST, "user_name": user_name, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_stop_listening_request(user_name):
        """
        Serialize stop listening request data for server communication
        :return: bytes
        """
        json_string = {"code": STOP_LISTENING, "user_name": user_name, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_check_request(user_name, peer_user_name):
        """
        Serialize check request data for server communication
        :return: bytes
        """
        json_string = {"code": CHECK_FOR_REQUEST, "user_name": user_name, "peer_user_name": peer_user_name, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def serialize_cancel_request(user_name, peer_user_name):
        """
        Serialize cancel request data for server communication
        :return: bytes
        """
        json_string = {"code": CANCEL_REQUEST, "user_name": user_name, "peer_user_name": peer_user_name, "t": "1"}
        return json.dumps(json_string).encode('utf-8')

    @staticmethod
    def deserialization(data):
        """
        Deserializes a JSON-formatted byte string and returns it as a Python object.
        :param data: The byte string to deserialize.
        :type data: bytes
        :return: The deserialized Python object.
        :rtype: any
        """
        return json.loads(data[START_OF_DESERIALIZATION:].decode('utf-8'))

    def set_password(self, password):
        """
        Sets the password for the user.
        :param password: The password to set.
        :type password: str
        :return: None
        """
        self._password = password

    def set_user_name(self, user_name):
        """
        Sets the username for the user.
        :param user_name: The username to set.
        :type user_name: str
        :return: None
        """
        self._user_name = user_name

    def set_email(self, email):
        """
        Sets the email address for the user.
        :param email: The email address to set.
        :type email: str
        :return: None
        """
        self._email = email

    def get_password(self):
        """
        Returns the password for the user.
        :return: The password for the user.
        :rtype: str
        """
        return self._password

    def get_user_name(self):
        """
        Returns the username for the user.
        :return: The username for the user.
        :rtype: str
        """
        return self._user_name

    def get_email(self):
        """
        Returns the email address for the user.
        :return: The email address for the user.
        :rtype: str
        """
        return self._email

    @staticmethod
    def generate_keypair():
        """
        Generates an RSA key pair (public and private keys).
        :return: A tuple containing the public key and private key as bytes
        :rtype: tuple
        """
        key = key_class.generate(RSA_KEY_SIZE)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return public_key, private_key

    @staticmethod
    def rsa_encryption(data, public_key):
        """
        Encrypts data using RSA encryption algorithm.
        :param data: The data to be encrypted
        :type data: bytes
        :param public_key: The public key to use for encryption
        :type public_key: bytes
        :return: The encrypted data
        :rtype: bytes
        """
        rsa_key = key_class.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)

        max_chunk_size = rsa_key.size_in_bytes() - OAEP_PADDING_OVERHEAD  # 42 bytes is the OAEP padding overhead
        encrypted_data = bytearray()

        for i in range(0, len(data), max_chunk_size):
            chunk = data[i:i + max_chunk_size]
            encrypted_chunk = cipher.encrypt(chunk)
            encrypted_data.extend(encrypted_chunk)

        return encrypted_data

    @staticmethod
    def rsa_decryption(encrypted_data, private_key):
        """
        Decrypts data using RSA decryption algorithm.
        :param encrypted_data: The encrypted data
        :type encrypted_data: bytes
        :param private_key: The private key to use for decryption
        :type private_key: bytes
        :return: The decrypted data
        :rtype: bytes
        """
        rsa_key = key_class.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)

        chunk_size = rsa_key.size_in_bytes()
        decrypted_data = bytearray()

        for i in range(0, len(encrypted_data), chunk_size):
            chunk = encrypted_data[i:i + chunk_size]
            decrypted_chunk = cipher.decrypt(chunk)
            decrypted_data.extend(decrypted_chunk)

        return decrypted_data

    def initialize_info(self, user_name, password, email):
        """
        Initializes the required information for sending messages.
        :param user_name: The user's name
        :type user_name: str
        :param password: The user's password
        :type password: str
        :param email: The user's email
        :type email: str
        :rtype: None
        """
        self._user_name = user_name
        self._password = password
        self._email = email

    def calculateVerifierAndSrpGroup(self, salt):
        """
        Calculates the SRP verifier and SRP group using the given salt and password, and stores them as hexadecimal strings in
        the instance variables self._verifier and self._srp_group, respectively.
        :param salt: A random salt to use for the SRP calculation.
        :type salt: bytes
        :return: None
        """
        registration_info = Crypto.Protocol.KDF.PBKDF2(self._password, salt, SIZE_OF_REGISTRATION_INFO,
                                                       count=NUM_OF_ITERATIONS, hmac_hash_module=Crypto.Hash.SHA512)
        # Split registration_info into SRP verifier and SRP group
        verifier = registration_info[:(SIZE_OF_REGISTRATION_INFO // 2)]
        srp_group = registration_info[(SIZE_OF_REGISTRATION_INFO // 2):]

        # Convert verifier and srp_group byte strings to hexadecimal strings and store them in self._verifier and self._srp_group
        self._verifier, self._srp_group = verifier.hex(), srp_group.hex()

    def get_random_salt(self):
        """
        Generates a random salt and stores it as a hexadecimal string in the instance variable self._salt.
        :return: None
        """
        salt = secrets.token_bytes(
            NUM_OF_BYTES_FOR_SALT)  # Generate a random byte string of length NUM_OF_BYTES_FOR_SALT
        self._salt = salt.hex()  # Convert the byte string to a hexadecimal string and store it in self._salt


    @staticmethod
    def get_ip_of_user(iface=None):
        """
        Returns the IP address of the user on the given network interface (or any interface if no interface is provided).
        :param iface: The name of the network interface to use (optional)
        :type iface: str or None
        :return: The user's IP address on the given network interface (or any interface if no interface is provided)
        :rtype: str or None
        """
        gateways = netifaces.gateways()
        addr_default_gateway = gateways['default'][netifaces.AF_INET][0]

        for interface in netifaces.interfaces():
            if not iface or iface == interface:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs and 'broadcast' in addrs[netifaces.AF_INET][0]:
                    ip = ipaddress.ip_interface(
                        f"{addrs[netifaces.AF_INET][0]['addr']}/{addrs[netifaces.AF_INET][0]['netmask']}")
                    if ip.version == 4 and interface in netifaces.gateways()['default'][netifaces.AF_INET][1]:
                        return ip.ip
        return None
