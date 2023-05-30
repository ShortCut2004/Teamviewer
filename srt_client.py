from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import ECC
import time
import socket
import pyautogui
import queue
import CustomDataStructures as structs
import random
import threading

# Constant Variables
ENCRYPTION_KEYS_EXCHANGE_CODE = 1
MAX_SEQ = 2 ** 30
DEFAULT_RECV_SIZE = 70000
SIZE_OF_KEY_IN_BITS = 2048
MOUSE_POSITION_REPORTING_CODE = 1
MOUSE_PRESSES_REPORTING_CODE = 2
MOUSE_RELEASE_REPORTING_CODE = 3
KEYBOARD_PRESSES_REPORTING_CODE = 4
ISN_MESSAGE_CODE = 5
RESOLUTION_EXCHANGE_MESSAGE_CODE = 6
CHAT_MESSAGE_CODE = 7


class srt_connector:
    """
    SRT protocol class,
    consists of two sides:
    connector(the side who controls the other - the master)
    host(the side who get controlled by the other - the slave)
    """

    def __init__(self, ip, udp_port, tcp_port, user_name):
        self._decryption_key = None  # self decryption key
        self._encryption_key = None  # other side's encryption key
        self._shared_key = None
        self._counter_key = None
        self._tcp_sock = None
        self._udp_server_address = None  # other side's server address
        self._udp_sock = None
        self._keepalive = True
        self._curr_seq = 0  # current sequence number
        self._curr_seq_lock = threading.Lock()
        self._curr_windowsize = DEFAULT_RECV_SIZE  # current window size
        self._curr_windowsize_lock = threading.Lock()
        self._user_name = user_name
        self._frame_rate = 30
        self._DST_HEIGHT = 1080
        self._DST_WIDTH = 1920
        self._SRC_HEIGHT = int(pyautogui.screenshot().height * 0.95)
        self._SRC_WIDTH = pyautogui.screenshot().width
        self._next_expected_seq_number = 0
        self._next_expected_seq_number_lock = threading.Lock()
        self._black_bars = False
        self._keyboard_pressed_queue = queue.Queue()  # pressed keyboard keys queue
        self._keyboard_pressed_lock = threading.Lock()  # the lock that is used for the keyboard presses queue
        self._mouse_released_queue = queue.Queue()  # released mouse buttons queue
        self._mouse_released_lock = threading.Lock()  # the lock that is used for the mouses releases queue
        self._mouse_pressed_queue = queue.Queue()  # pressed mouse buttons queue
        self._mouse_pressed_lock = threading.Lock()  # the lock that is used for the mouse presses queue
        self._received_frame_buffer = structs.DequeQueue(100)  # the received frames buffer
        self._received_frames_lock = threading.Lock()  # the lock that is used for the received frame buffer queue
        self._received_packet_buffer = []  # the received packets buffer
        self._received_packets_lock = threading.Lock()  # the lock that is used for the received packets dict
        self._transmission_condition = threading.Condition()  # The condition used to stop threads when connection disconnects
        self._mouse_control_condition = threading.Condition()  # The condition used to stop the threads responsible for sending mouse button presses and location reporting
        self._keyboard_control_condition = threading.Condition()  # The condition used to stop threads responsible for sending keyboard button presses
        self._chat_messages = structs.DequeQueue(100)
        self._chat_messages_lock = threading.Lock()
        self._print_lock = threading.Lock()
        self._received_frame_event = threading.Event()
        self._received_chat_message_event = threading.Event()
        self._disconnection_event = threading.Event()
        self._ip = ip
        self._udp_port = udp_port
        self._tcp_port = tcp_port

    def initialize_sockets_connector(self):
        """
        Initializes the TCP and UDP sockets for the connector side.
        :rtype: None
        """
        # Create a UDP socket
        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.bind(('', 8082))
        self._udp_server_address = (self._ip, self._udp_port)

        # Hole punching: receive the message from the server's UDP socket
        while True:
            try:
                self._udp_sock.settimeout(5)
                data, _ = self._udp_sock.recvfrom(DEFAULT_RECV_SIZE)
                if data == b'hole_punch':
                    break
            except Exception:
                pass

        # Send the "test" message
        try:
            self._udp_sock.settimeout(5)
            self._udp_sock.sendto(b"test", self._udp_server_address)
            data, _ = self._udp_sock.recvfrom(DEFAULT_RECV_SIZE)
            print("Received - " + data.decode())
        except Exception:
            pass

        try:
            threading.Thread(target=self.keep_alive_connector, args=(self,)).start()
        except Exception:
            pass

        # Create the TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Hole punching: set SO_REUSEADDR to reuse the same port
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_address = (self._ip, self._tcp_port)
        sock.connect(server_address)
        print("Connected to other client successfully!")
        self._tcp_sock = sock

    def encryption_keys_exchange_connector(self):
        """
        Exchanges encryption keys and ISN values for secure communication between connector and host.
        :rtype: None
        """

        private_key, public_key = srt_connector.generate_keys()

        # Receive the other party's public key over the TCP socket, decrypt it using the private key, and import it
        msg = self.tcp_deserialization(self._tcp_sock.recv(DEFAULT_RECV_SIZE))
        if msg['code'] == ENCRYPTION_KEYS_EXCHANGE_CODE:
            other_public_key = ECC.import_key(msg['data'].decode())
        else:
            raise Exception("Haven't received public key of other side")

        # Send the public key to the other party over the TCP socket
        self._tcp_sock.sendall(
            self.tcp_serialization(ENCRYPTION_KEYS_EXCHANGE_CODE, public_key.export_key(format="PEM").encode()))
        self._shared_key = srt_connector.derive_shared_key(private_key, other_public_key)
        self._counter_key = srt_connector.derive_counter(self._shared_key)

        msg = self.tcp_deserialization(
            self.aes_ctr_decrypt(self._tcp_sock.recv(DEFAULT_RECV_SIZE), self._shared_key, self._counter_key))

        if msg['code'] == ISN_MESSAGE_CODE:
            self._next_expected_seq_number = int.from_bytes(msg['data'], 'big')
        else:
            raise Exception("Haven't received ISN value of other side")
        print("Other Seq number: " + str(self._next_expected_seq_number))
        # generating a random ISN value between 2 to the power of 8 and 2 to the power of 24
        self._curr_seq = random.randint(2 ** 8, 2 ** 24)
        print("Self Seq number: " + str(self._curr_seq))
        # Sending own ISN value
        self._tcp_sock.sendall(self.aes_ctr_encrypt(self.tcp_serialization(ISN_MESSAGE_CODE,
                                                                           self._curr_seq.to_bytes(
                                                                               4, "big")), self._shared_key,
                                                    self._counter_key))
        msg = self.tcp_deserialization(
            self.aes_ctr_decrypt(self._tcp_sock.recv(DEFAULT_RECV_SIZE), self._shared_key, self._counter_key))
        if msg['code'] == RESOLUTION_EXCHANGE_MESSAGE_CODE:
            self._DST_WIDTH = int.from_bytes(msg['data'][0:2], 'big')
            self._DST_HEIGHT = int.from_bytes(msg['data'][2:4], 'big')
        else:
            raise Exception("Haven't received other side's resolution")
        self._tcp_sock.sendall(self.aes_ctr_encrypt(self.tcp_serialization(RESOLUTION_EXCHANGE_MESSAGE_CODE,
                                                                           self._SRC_WIDTH.to_bytes(2,
                                                                                                    'big') + self._SRC_HEIGHT.to_bytes(
                                                                               2, 'big')),
                                                    self._shared_key, self._counter_key))

    @staticmethod
    def generate_keys():
        """
        Generate an ECC key pair.

        :return: A tuple containing the private key and the public key.
        :rtype: tuple
        """
        key = ECC.generate(curve="P-256")
        private_key = key
        public_key = key.public_key()
        return private_key, public_key

    @staticmethod
    def derive_shared_key(self_private_key, other_public_key):
        """
        Derive a shared secret key using the provided private key and the other party's public key.

        :param self_private_key: The private key of one party.
        :param other_public_key: The public key of the other party.
        :type self_private_key: ECC Private Key
        :type other_public_key: ECC Public Key
        :return: The derived shared secret key (32 bytes).
        :rtype: bytes
        """
        shared_key = self_private_key.d * other_public_key.pointQ
        shared_key_bytes = shared_key.x.to_bytes(32, byteorder="big")
        derived_key = scrypt(shared_key_bytes, b"", 32, N=2 ** 14, r=8, p=1)
        return derived_key

    @staticmethod
    def derive_counter(shared_key):
        """
        Derive an initial counter value from the shared secret key.

        :param shared_key: The shared secret key (32 bytes).
        :type shared_key: bytes
        :return: A Counter object with the initial counter value.
        :rtype: Counter
        """
        initial_value = int.from_bytes(shared_key[:16], "big")
        return Counter.new(128, initial_value=initial_value)

    @staticmethod
    def aes_ctr_encrypt(data, key, ctr):
        """
        Encrypt data using AES-CTR mode with the given key and counter.

        :param data: The data to encrypt.
        :param key: The encryption key (32 bytes).
        :param ctr: A Counter object representing the counter value for AES-CTR.
        :type data: bytes
        :type key: bytes
        :type ctr: Counter
        :return: The encrypted data (ciphertext).
        :rtype: bytes
        """

        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        ciphertext = cipher.encrypt(data)
        return ciphertext

    @staticmethod
    def aes_ctr_decrypt(ciphertext, key, ctr):
        """
        Decrypt data using AES-CTR mode with the given key and counter.

        :param ciphertext: The encrypted data (ciphertext).
        :param key: The decryption key (32 bytes).
        :param ctr: A Counter object representing the counter value for AES-CTR.
        :type ciphertext: bytes
        :type key: bytes
        :type ctr: Counter
        :return: The decrypted data (plaintext).
        :rtype: bytes
        """

        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        data = cipher.decrypt(ciphertext)
        return data

    @staticmethod
    def udp_serialization(nak, rt_ack, seq_number, data):
        """
        Serializes the UDP packet with the given flags, sequence number and data.
        :param nak: Packet nak flag value
        :param rt_ack: Packet rt_ack flag value
        :param seq_number: Packet sequence number
        :param data: Packet's data
        :type nak: bool
        :type rt_ack: bool
        :type seq_number: int
        :type data: bytes
        :rtype: bytes
        """

        if data is not None:
            return int(nak).to_bytes(1, 'big') + int(rt_ack).to_bytes(1, 'big') + seq_number.to_bytes(
                4, 'big') + data
        return int(nak).to_bytes(1, 'big') + int(rt_ack).to_bytes(1, 'big') + seq_number.to_bytes(
            4, 'big')

    @staticmethod
    def tcp_serialization(code, data):
        """
        Serializes the TCP packet with the given code and data.
        :param code: Packet code
        :param data: Packet data
        :type code: int
        :type data: bytes
        :rtype: bytes
        """

        return code.to_bytes(1, 'big') + data

    @staticmethod
    def udp_deserialization(data):
        """
        Deserializes the UDP packet and returns the packet flags, seq number and data.
        :param data: Packet data
        :type data: bytes
        :rtype: dict
        """

        return {
            # Extract the first byte, which represents the 'nak' and 'rt_ack' variables
            'nak': int.from_bytes(data[0:1], 'big'),
            'rt_ack': int.from_bytes(data[1:2], 'big'),
            # Extract the next 3 bytes, which represent the 'hour', 'minute', and 'second' variables
            #   'hour': int.from_bytes(data[1:2], 'big'),
            #   'minute': int.from_bytes(data[2:3], 'big'),
            #   'second': int.from_bytes(data[3:4], 'big'),
            # Extract the next 4 bytes, which represent the 'seq_number' variable
            'seq_number': int.from_bytes(data[2:6], 'big'),
            'data': data[6:]}

    @staticmethod
    def tcp_deserialization(data):
        """
        Deserializes the TCP packet and returns the packet code and data.
        :param data: Packet data
        :type data: bytes
        :rtype: dict
        """

        return {
            'code': int.from_bytes(data[0:1], 'big'),
            'data': data[1:]}

    def window_size_thread(self, thread_obj):
        """
        determines the current window size of the other side.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
        :rtype: None
        """
        # updating the window size 10 time per second
        while True:
            try:
                #   stopping the thread if transmission had been stopped
                if self._transmission_condition:
                    break
                # subtracting 5 percent from the real window size to account for variable change and setting it as windowsize if smaller than receive size

                temp_windowsize = int(self._udp_sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) * 0.95)
                self._curr_windowsize_lock.acquire()
                if temp_windowsize > DEFAULT_RECV_SIZE:
                    self._curr_windowsize = DEFAULT_RECV_SIZE
                else:
                    self._curr_windowsize = temp_windowsize
                self._curr_windowsize_lock.release()
                time.sleep(0.1)
            except Exception as e:
                print("Exception caught in window_size_thread - " + str(e))

    def receive_packets(self, thread_obj):
        """
        Receives video frames from the TCP socket and adds them to the received frame buffer.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
        :rtype: None
        """

        while True:
            #   stopping the thread if transmission had been stopped
            if self._transmission_condition:
                break
            try:
                data = self._udp_sock.recvfrom(DEFAULT_RECV_SIZE)
                msg = srt_connector.udp_deserialization(
                    srt_connector.aes_ctr_decrypt(data[0], self._shared_key, self._counter_key))
                # adding the current packet to the temp buffer, with a boolean variable that resembles if the packet is the last one for the current frame
                self._received_packets_lock.acquire()
                self._received_packet_buffer.append([msg['seq_number'], tuple((msg['data'], msg['nak']))])
                self._received_packets_lock.release()
                # self._print_lock.acquire()
                # print("received packet " + str(msg["seq_number"]) + " of size " + str(len(msg['data']) + 6))
                # self._print_lock.release()
                self._next_expected_seq_number_lock.acquire()
                if msg['seq_number'] != self._next_expected_seq_number and not (msg['rt_ack']):
                    self._next_expected_seq_number_lock.release()
                    #   send nak
                    self._udp_sock.sendto(
                        srt_connector.aes_ctr_encrypt(self.udp_serialization(True, False,
                                                                             self._next_expected_seq_number, None),
                                                      self._shared_key,
                                                      self._counter_key), self._udp_server_address)
                try:
                    self._next_expected_seq_number_lock.release()
                except Exception:
                    pass

                if not (msg['rt_ack']):
                    self._next_expected_seq_number_lock.acquire()
                    self._next_expected_seq_number += len(msg['data']) + 6
                    self._next_expected_seq_number_lock.release()
                self.assemble_frames()  # calling a function that creates the frames from the packets
            except Exception as e:
                try:
                    self._received_packets_lock.release()
                except Exception:
                    pass
                try:
                    self._next_expected_seq_number_lock.release()
                except Exception:
                    pass

                print("Error encountered in receive_packets thread - " + str(e))

    def assemble_frames(self):
        """
        the method assembles frames based on packets received,
        if it managed to assemble a frame it deletes the packets from the buffer and pushes the frame into the frame buffer
        """

        # sorting function for received_packet_buffer
        def by_seq(ele):
            return ele[0]

        try:
            chunk_list = []
            # the index that resembles the beginning of the correct indexes list
            temp_index = 0
            length = 0
            index = 0
            self._received_packets_lock.acquire()
            sorted(self._received_packet_buffer, key=by_seq)
            next_packet = self._received_packet_buffer[0][0]
            self._received_packets_lock.release()
            # tup = [key(seq_number of packet), tuple(packet, bool - last packet for frame)]
            temp_snapshot = self._received_packet_buffer
            #   iterating over the received packet buffer and checking if the packets make up a frame and if they do,
            #   than the frame gets pushed into the frame buffer and the packets get popped
            for list_pair in temp_snapshot:
                # the next packet is the expected packet (the seq number order align)
                if list_pair[0] == next_packet:
                    length += 1
                    # adding the packet data to a chunk list
                    chunk_list.append(list_pair[1][0])
                    # offsetting the seq number we are searching for by the last "correct" packet's length
                    next_packet += len(chunk_list[-1]) + 6  # adding the size of the srt header
                    # checking if the packet is the last in the frame - we are able to make a full frame
                    if list_pair[1][1]:
                        # adding the frame into the received frame buffer
                        self._received_frames_lock.acquire()
                        self._received_frame_buffer.put(b''.join(chunk_list))
                        self._received_frames_lock.release()
                        self._received_frame_event.set()
                        # deleting all the packets from the received packets buffer
                        self._received_packets_lock.acquire()

                        for i in range(0, length):
                            self._received_packet_buffer.pop(temp_index)
                        chunk_list.clear()
                        self._received_packets_lock.release()

                # the packet is not the expected one
                else:
                    # checking if the packet is the last in the frame
                    if list_pair[1][1]:
                        next_packet = list_pair[0] + len(list_pair[1][0]) + 6  # adding the size of the srt header
                        temp_index = index + 1
                        length = 0
                        chunk_list.clear()
                    else:
                        continue
                index += 1

        except Exception as e:
            try:
                self._received_packets_lock.release()
                self._received_frames_lock.release()

            except Exception:
                pass
            print("Error encountered in assemble_frames function - " + str(e))

    def stop_transmission(self):
        """
        Stops all transmissions, clears buffers and resets threading conditions.
        :rtype: None
        """

        #   setting all the threading conditions to true, clearing all the data structures used for buffer
        self._transmission_condition = True
        self._received_packet_buffer.clear()
        self._received_frame_buffer.queue.clear()

    def start_transmission_connector(self):
        """
        Starts transmission for the connector by initializing and starting various threads.
        :rtype: None
        """

        if self._transmission_condition:
            self._transmission_condition = False
            self._mouse_control_condition = False
            self._keyboard_control_condition = False
            threading.Thread(target=self.window_size_thread, args=(self,)).start()
            threading.Thread(target=self.get_tcp_messages_thread, args=(self,)).start()
            t = threading.Thread(target=self.receive_packets, args=(self,))
            t.start()
            t.join()

    def run_connector(self, thread_obj):
        """
        Runs the connector by initializing sockets, exchanging encryption keys, and starting transmission.
        :rtype: None
        """

        self.initialize_sockets_connector()
        self.encryption_keys_exchange_connector()
        self._keepalive = False
        self._tcp_sock.settimeout(0.3)
        self._udp_sock.settimeout(0.3)
        self.start_transmission_connector()
        while True:
            self._disconnection_event.wait()

    def get_next_frame(self):
        """
        Retrieves the next frame from the received frame buffer.
        :return: The next frame
        :rtype: bytes
        """
        temp_frame = b''
        self._received_frames_lock.acquire()
        try:
            temp_frame = self._received_frame_buffer.get()
        except Exception as e:
            print("Encountered Exception when trying to pull frame - " + str(e))
            try:
                self._received_frames_lock.release()
            except Exception:
                pass
        self._received_frames_lock.release()
        return temp_frame

    def keep_alive_connector(self, thread_obj):
        """
        Sends and receives UDP keep-alive messages as a connector.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
        :rtype: None
        """
        while self._keepalive:
            try:
                self._udp_sock.sendto("".encode(), self._udp_server_address)
                data, _ = self._udp_sock.recvfrom(DEFAULT_RECV_SIZE)
            except Exception:
                pass
            time.sleep(0.5)

    def send_chat_message(self, data):
        """
        Sends a chat message to the server.
        :param data: Chat message text
        :type data: str
        :rtype: None
        """
        msg = self._user_name + ": " + data
        self._tcp_sock.sendall(
            self.aes_ctr_encrypt(self.tcp_serialization(CHAT_MESSAGE_CODE, msg.encode()), self._shared_key,
                                 self._counter_key))

        with self._chat_messages_lock:
            self._chat_messages.put(msg)
            self._received_chat_message_event.set()

    def get_next_message(self):
        """
        Retrieves the next chat message from the queue.
        :rtype: str
        """
        temp = ""
        try:
            with self._chat_messages_lock:
                temp = self._chat_messages.get()
        except Exception as e:
            pass
        return temp

    def get_tcp_messages_thread(self, thread_obj):
        """
        This method runs in a separate thread, receives and processes messages received
        from a TCP socket connection. It decrypts and deserializes the received data and
        processes the data according to its code.

        :param thread_obj: the object representing the thread
        :type thread_obj: threading.Thread object

        :return: None
        :rtype: None
        """

        while True:
            if self._transmission_condition:
                break

            try:
                data = self.tcp_deserialization(
                    self.aes_ctr_decrypt(self._tcp_sock.recv(DEFAULT_RECV_SIZE), self._shared_key, self._counter_key))
                if data['code'] == CHAT_MESSAGE_CODE:
                    with self._chat_messages_lock:
                        self._chat_messages.put(data['data'].decode())
                    self._received_chat_message_event.set()
                else:
                    with self._print_lock:
                        print("Wrong code received in tcp receiver thread")

            except socket.timeout:
                time.sleep(0)
            except socket.error as e:
                print(f"Socket error encountered in tcp_receiver thread - {str(e)}")
            except Exception as e:
                print("Encountered Exception in tcp messages receiver thread - " + str(e))

            time.sleep(0.3)
