from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import ECC
import time
import socket
import numpy as np
import cv2
import pyautogui
import CustomDataStructures as structs
import random
import threading
from Image import Image_Proccessing
from Image import Image_Coding
from PIL import Image, ImageDraw
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
TCP_PORT = 11
UDP_PORT = 8081


class srt_host:
    """
    srt_host protocol class,
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
        self._SRC_HEIGHT = pyautogui.screenshot().height
        self._SRC_WIDTH = pyautogui.screenshot().width
        self._next_expected_seq_number = 0
        self._next_expected_seq_number_lock = threading.Lock()
        self._black_bars = False
        self._frame_buffer = structs.DequeQueue(100)  # buffer queue - packets that need to be sent
        self._frame_buffer_lock = threading.Lock()  # the lock that is used for the frame buffer queue
        self._sent_packets = structs.MaxSizeDict(2000)  # sent packets dict - includes tuple[initial_seq(int),packet]
        self._sent_packets_lock = threading.Lock()  # the lock that is used for the set packets dict
        self._sleeper_event = threading.Event()  # The sleeping event used to wake the sender thread if it is sleeping
        self._transmission_condition = threading.Condition()  # The condition used to stop threads when connection disconnects
        self._mouse_control_condition = threading.Condition()  # The condition used to stop the threads responsible for sending mouse button presses and location reporting
        self._keyboard_control_condition = threading.Condition()  # The condition used to stop threads responsible for sending keyboard button presses
        self._received_udp_data = structs.DequeQueue(1000)
        self._chat_messages = structs.DequeQueue(100)
        self._chat_messages_lock = threading.Lock()
        self._received_chat_message_event = threading.Event()
        self._disconnection_event = threading.Event()
        self._received_udp_data_lock = threading.Lock()
        self._print_lock = threading.Lock()
        self._temp_event = threading.Event()
        self._ip = ip
        self._udp_port = udp_port
        self._tcp_port = tcp_port

    def initialize_sockets_host(self):
        """
        Initializes the TCP and UDP sockets for the host side.
        :rtype: None
        """

        # Create a UDP socket
        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_server_address = (self._ip, self._udp_port)
        self._udp_sock.bind(('', UDP_PORT))

        # Trying to holepunch
        while True:
            # Hole punching: send a message to the client's UDP socket
            self._udp_sock.sendto(b'hole_punch', self._udp_server_address)
            try:
                data, address = self._udp_sock.recvfrom(DEFAULT_RECV_SIZE)
                break
            except Exception:
                pass

        # checking that socket works correctly
        while True:
            try:
                # Set the socket's timeout to 5 seconds
                self._udp_sock.settimeout(5)
                data, address = self._udp_sock.recvfrom(DEFAULT_RECV_SIZE)
                self._udp_server_address = address
                print("Received - " + data.decode())
                self._udp_sock.sendto(data, self._udp_server_address)
                break

            except Exception:
                pass

        print("UDP socket successfully connected!")
        try:
            threading.Thread(target=self.keep_alive_host, args=(self,)).start()
        except Exception:
            pass

        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('', TCP_PORT)
        sock.bind(server_address)
        sock.listen()

        # Hole punching: set SO_REUSEADDR to reuse the same port
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        print("waiting for connection")

        # Accept a connection from the client
        client_sock, client_address = sock.accept()
        print("Other client has been connected successfully!")
        self._tcp_sock = client_sock
        sock.close()

    def encryption_keys_exchange_host(self):
        """
        Exchanges encryption keys and ISN values for secure communication between host and connector.
        :rtype: None
        """

        private_key, public_key = srt_host.generate_keys()

        # Send the public key to the other party over the TCP socket
        self._tcp_sock.sendall(
            self.tcp_serialization(ENCRYPTION_KEYS_EXCHANGE_CODE, public_key.export_key(format="PEM").encode()))

        # Receive the other party's public key over the TCP socket, decrypt it using the private key, and import it
        other_public_key = ECC.import_key(
            self.tcp_deserialization(self._tcp_sock.recv(DEFAULT_RECV_SIZE))['data'].decode())

        self._shared_key = srt_host.derive_shared_key(private_key, other_public_key)

        self._counter_key = srt_host.derive_counter(self._shared_key)

        # generating a random ISN value between 2 to the power of 8 and 2 to the power of 24
        self._curr_seq = random.randint(2 ** 8, 2 ** 24)
        print("Self Seq number: " + str(self._curr_seq))
        self._tcp_sock.sendall(self.aes_ctr_encrypt(self.tcp_serialization(ISN_MESSAGE_CODE, self._curr_seq.to_bytes(
            4, 'big')), self._shared_key, self._counter_key))
        msg = self.tcp_deserialization(
            self.aes_ctr_decrypt(self._tcp_sock.recv(DEFAULT_RECV_SIZE), self._shared_key, self._counter_key))
        if msg['code'] == ISN_MESSAGE_CODE:
            self._next_expected_seq_number = int.from_bytes(msg['data'], 'big')
        else:
            raise Exception("Haven't received ISN value of master side")
        print("Other Seq number: " + str(self._next_expected_seq_number))
        self._tcp_sock.sendall(self.aes_ctr_encrypt(self.tcp_serialization(RESOLUTION_EXCHANGE_MESSAGE_CODE,
                                                                           self._SRC_WIDTH.to_bytes(2,
                                                                                                    'big') + self._SRC_HEIGHT.to_bytes(
                                                                               2, 'big')),
                                                    self._shared_key, self._counter_key))
        msg = self.tcp_deserialization(
            self.aes_ctr_decrypt(self._tcp_sock.recv(DEFAULT_RECV_SIZE), self._shared_key, self._counter_key))
        if msg['code'] == RESOLUTION_EXCHANGE_MESSAGE_CODE:
            self._DST_WIDTH = int.from_bytes(msg['data'][0:2], 'big')
            self._DST_HEIGHT = int.from_bytes(msg['data'][2:4], 'big')
        else:
            raise Exception("Haven't received other side's resolution")

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

    @staticmethod
    def take_screenshot_and_save_as_rgb_array():
        """
        The method takes a screenshot of the main screen, and returns it as a cv2 array
        :return: the screenshot
        :rtype: numpy.ndarray
        """

        # Take a screenshot
        screenshot = pyautogui.screenshot()

        # Get the current mouse position
        mouse_x, mouse_y = pyautogui.position()

        # Draw the mouse cursor on the screenshot
        cursor = Image.new('RGBA', (20, 20), (0, 0, 0, 0))
        draw = ImageDraw.Draw(cursor)
        draw.ellipse([(0, 0), (20, 20)], fill='white', outline='black', width=2)

        # Paste the cursor onto the screenshot at the mouse position
        screenshot.paste(cursor, (mouse_x - 10, mouse_y - 10), cursor)

        # Convert the screenshot into an RGB array
        image = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2BGR)
        return image

    def send_frame(self, frame):
        """
        The method receives a frame and splits it into packets according to the window size, and sends the packets to the other side
        :param frame: the frame
        :type frame: numpy.ndarray
        """

        try:
            # Splitting the data into chunks according to the current window_size
            with self._curr_windowsize_lock:
                # Subtracting 6 bytes from windowsize to account for srt header size
                info = [frame[i:(i + self._curr_windowsize - 6)] for i in
                        range(0, len(frame), self._curr_windowsize - 6)]

            # Sending each packet
            for packet in info:
                with self._curr_seq_lock:
                    temp_seq = self._curr_seq
                serialized_packet = srt_host.aes_ctr_encrypt(srt_host.udp_serialization(packet == info[-1], False,
                                                                                        temp_seq, packet),
                                                             self._shared_key,
                                                             self._counter_key)

                with self._sent_packets_lock:
                    self._sent_packets[temp_seq] = [packet, packet == info[-1]]

                self._udp_sock.sendto(serialized_packet, self._udp_server_address)
                with self._curr_seq_lock:
                    self._curr_seq += len(serialized_packet)
        except Exception as e:
            print("Exception caught when trying to send frame" + str(e))

    def send_frames_thread(self, thread_obj):
        """
        Sends video frames through the UDP socket using threading.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
        :rtype: None
        """

        while True:
            try:
                # stopping the coroutine if transmission had been stopped
                if self._transmission_condition:
                    break

                if self._frame_buffer.empty():
                    self._sleeper_event.clear()
                    self._sleeper_event.wait()

                while not self._frame_buffer.empty():
                    with self._frame_buffer_lock:
                        curr_frame = self._frame_buffer.get()
                    self.send_frame(curr_frame)
                    time.sleep(0.01)
            except Exception as e:
                print("Exception caught in send_frames_thread - " + str(e))
            time.sleep(0.01)

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
                with self._curr_windowsize_lock:
                    if temp_windowsize > DEFAULT_RECV_SIZE:
                        self._curr_windowsize = DEFAULT_RECV_SIZE
                    else:
                        self._curr_windowsize = temp_windowsize
                time.sleep(0.1)
            except Exception as e:
                print("Exception caught in window_size_thread - " + str(e))

    def capture_frames(self, thread_obj):
        """
        Captures video frames and adds them to the frame buffer.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
        :rtype: None
        """

        same_resolution = self._SRC_HEIGHT == self._DST_HEIGHT and self._SRC_WIDTH == self._DST_WIDTH

        while True:
            #   stopping the thread if transmission had been stopped
            if self._transmission_condition:
                break
            #   sleep_time = 1 / self._frame_rate  # Calculating the amount the loop needs to sleep in order to capture another frame at good timing
            try:
                with self._frame_buffer_lock:
                    # The destination's resolution is the same as the source
                    if same_resolution:
                        self._frame_buffer.put(
                            Image_Coding.codec_frame(self._frame_buffer.queue[-1],
                                                     srt_host.take_screenshot_and_save_as_rgb_array()))
                    # The destination's resolution is different from the source
                    else:
                        self._frame_buffer.put(
                            Image_Coding.codec_frame(self._frame_buffer.queue[-1], Image_Proccessing.change_resolution(
                                srt_host.take_screenshot_and_save_as_rgb_array(), self._DST_HEIGHT, self._DST_WIDTH,
                                self._black_bars)))
            except IndexError:
                # releasing the frame buffer lock incase an exception has been raised to avoid starvation
                with self._frame_buffer_lock:
                    # The destination's resolution is the same as the source
                    if same_resolution:
                        self._frame_buffer.put(
                            Image_Coding.codec_frame_without_reference(
                                srt_host.take_screenshot_and_save_as_rgb_array()))
                    # The destination's resolution is different from the source
                    else:
                        self._frame_buffer.put(Image_Coding.codec_frame_without_reference(
                            Image_Proccessing.change_resolution(srt_host.take_screenshot_and_save_as_rgb_array(),
                                                                self._DST_HEIGHT,
                                                                self._DST_WIDTH,
                                                                self._black_bars)))

            # setting the event in order to wake up the frame sender thread
            self._sleeper_event.set()
            time.sleep(0.01)

    def receive_responses(self, thread_obj):
        """
        Receives responses from the connector and updates the next expected sequence number accordingly.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
        :rtype: None
        """

        while True:
            try:
                #   stopping the thread if transmission had been stopped
                if self._transmission_condition:
                    break

                data = self._udp_sock.recvfrom(DEFAULT_RECV_SIZE)
                msg = srt_host.udp_deserialization(
                    srt_host.aes_ctr_decrypt(data[0], self._shared_key, self._counter_key))
                if msg['nak']:
                    with self._sent_packets_lock:
                        # packet_data - [packet['data'],packet['nak']]
                        packet_data = self._sent_packets[msg['seq_number']]
                    self._udp_sock.sendto(
                        srt_host.aes_ctr_encrypt(self.udp_serialization(packet_data[1], True,
                                                                        msg['seq_number'],
                                                                        packet_data[0]), self._shared_key,
                                                 self._counter_key), self._udp_server_address)

            except socket.timeout:
                time.sleep(0)
            except KeyError:
                time.sleep(0.01)
            except Exception as e:
                print("Exception caught in receive_responses_thread - " + str(e))
            time.sleep(0.01)

    def receive_commands_thread(self, thread_obj):
        """
        Receives messages from the master.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
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
                    print("Unknown code was encountered in receive_commands thread")

            except socket.timeout:
                time.sleep(0)
            except socket.error as e:
                print(f"Socket error encountered in receive_commands thread - {str(e)}")
            except Exception as e:
                print("Error was encountered in receive_commands thread - " + str(e))
            time.sleep(0.6)

    def stop_transmission(self):
        """
        Stops all transmissions, clears buffers and resets threading conditions.
        :rtype: None
        """

        #   setting all the threading conditions to true, clearing all the data structures used for buffer
        self._transmission_condition = True
        self._frame_buffer.queue.clear()

    def start_transmission_host(self):

        """
        Starts transmission for the host by initializing and starting various threads.
        :rtype: None
        """

        if self._transmission_condition:
            self._transmission_condition = False

        threading.Thread(target=self.receive_commands_thread, args=(self,)).start()
        threading.Thread(target=self.receive_responses, args=(self,)).start()
        threading.Thread(target=self.send_frames_thread, args=(self,)).start()
        threading.Thread(target=self.window_size_thread, args=(self,)).start()
        t = threading.Thread(target=self.capture_frames, args=(self,))
        t.start()
        t.join()

    def run_host(self, thread_obj):
        """
        Runs the host by initializing sockets, exchanging encryption keys, and starting transmission.
        :rtype: None
        """

        self.initialize_sockets_host()
        self.encryption_keys_exchange_host()
        self._keepalive = False
        self._udp_sock.settimeout(0.05)
        self._tcp_sock.settimeout(0.05)
        self.start_transmission_host()

    def keep_alive_host(self, thread_obj):
        """
        Sends and receives UDP keep-alive messages as a host.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
        :rtype: None
        """
        while self._keepalive:
            try:
                data, _ = self._udp_sock.recvfrom(DEFAULT_RECV_SIZE)
                self._udp_sock.sendto("".encode(), self._udp_server_address)
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
