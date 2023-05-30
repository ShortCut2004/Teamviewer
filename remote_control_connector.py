import threading
import keylogger
import queue
import time
import socket
import srt_client
import pyautogui
import pickle

# Constant Variables
TCP_PORT = 8083
ENCRYPTION_KEYS_EXCHANGE_CODE = 1
RESOLUTION_EXCHANGE_MESSAGE_CODE = 2
MOUSE_POSITION_REPORTING_CODE = 3
MOUSE_PRESSES_REPORTING_CODE = 4
MOUSE_RELEASE_REPORTING_CODE = 5
KEYBOARD_PRESSES_REPORTING_CODE = 6
ALL_BUTTONS_CODE = 7
DEFAULT_RECV_SIZE = 2048


class remote_control_connector:
    def __init__(self, ip):
        self._tcp_sock = None
        self._ip = ip
        self._tcp_port = TCP_PORT
        self._shared_key = None
        self._counter_key = None
        self._keyboard_pressed_queue = queue.Queue()  # pressed keyboard keys queue
        self._keyboard_pressed_lock = threading.Lock()  # the lock that is used for the keyboard presses queue
        self._mouse_released_queue = queue.Queue()  # released mouse buttons queue
        self._mouse_released_lock = threading.Lock()  # the lock that is used for the mouses releases queue
        self._mouse_pressed_queue = queue.Queue()  # pressed mouse buttons queue
        self._mouse_pressed_lock = threading.Lock()  # the lock that is used for the mouse presses queue
        self._buttons = queue.Queue()
        self._buttons_lock = threading.Lock()
        self._DST_WIDTH = 1920
        self._DST_HEIGHT = 1080
        self._SRC_HEIGHT = int(pyautogui.screenshot().height * 0.95)
        self._SRC_WIDTH = pyautogui.screenshot().width

    def initialize_sockets_connector(self):
        """
        Initializes the TCP socket and connects to the remote host at the given IP address and port number. Uses SO_REUSEADDR to reuse the same port. This method blocks until a successful connection is made.

        :return: None
        :rtype: None
        """

        # Create the TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Hole punching: set SO_REUSEADDR to reuse the same port
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_address = (self._ip, self._tcp_port)
        var = True
        try:
            while var:
                sock.connect(server_address)
                var = False
        except Exception:
            pass

        print("Connected to other client successfully!")
        self._tcp_sock = sock

    def exchange_encryption_connector(self):
        """
        Exchange encryption details with the remote host.

        This method generates the public-private key pair, exchanges the public key with the remote host, and
        derives a shared key to be used for AES encryption of data between the two hosts. Additionally, it exchanges the
        resolutions of the two hosts.

        Raises:
            Exception: If public key of the other side has not been received or other side's resolution has not been
            received.

        :return: None
        :rtype: None
        """

        # Encryption Details Exchange
        private_key, public_key = srt_client.srt_connector.generate_keys()

        # Receive the other party's public key over the TCP socket, decrypt it using the private key, and import it
        msg = srt_client.srt_connector.tcp_deserialization(self._tcp_sock.recv(DEFAULT_RECV_SIZE))
        if msg['code'] == ENCRYPTION_KEYS_EXCHANGE_CODE:
            other_public_key = srt_client.ECC.import_key(msg['data'].decode())
        else:
            raise Exception("Haven't received public key of other side")

        # Send the public key to the other party over the TCP socket
        self._tcp_sock.sendall(
            srt_client.srt_connector.tcp_serialization(ENCRYPTION_KEYS_EXCHANGE_CODE,
                                                       public_key.export_key(format="PEM").encode()))
        self._shared_key = srt_client.srt_connector.derive_shared_key(private_key, other_public_key)
        self._counter_key = srt_client.srt_connector.derive_counter(self._shared_key)

        # RESOLUTION EXCHANGE
        msg = srt_client.srt_connector.tcp_deserialization(
            srt_client.srt_connector.aes_ctr_decrypt(self._tcp_sock.recv(DEFAULT_RECV_SIZE), self._shared_key,
                                                     self._counter_key))
        if msg['code'] == RESOLUTION_EXCHANGE_MESSAGE_CODE:
            self._DST_WIDTH = int.from_bytes(msg['data'][0:2], 'big')
            self._DST_HEIGHT = int.from_bytes(msg['data'][2:4], 'big')
        else:
            raise Exception("Haven't received other side's resolution")
        self._tcp_sock.sendall(srt_client.srt_connector.aes_ctr_encrypt(
            srt_client.srt_connector.tcp_serialization(RESOLUTION_EXCHANGE_MESSAGE_CODE,
                                                       self._SRC_WIDTH.to_bytes(2,
                                                                                'big') + self._SRC_HEIGHT.to_bytes(
                                                           2, 'big')),
            self._shared_key, self._counter_key))

    def mouse_logger_thread(self, thread_obj):
        """
        Starts a mouse keylogger thread.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
        :rtype: None
        """

        mouse_logger = threading.Thread(target=keylogger.start_mouse_logger,
                                        args=(
                                            self._buttons, self._buttons ,
                                            self._buttons_lock,  self._buttons_lock))
        mouse_logger.start()

    def send_mouse_position_thread(self, thread_obj):
        """
        Sends the current mouse position periodically.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
        :rtype: None
        """

        while True:
            pos = pyautogui.position()
            pos = keylogger.translate_coordinates(self._SRC_WIDTH, self._SRC_HEIGHT, self._DST_WIDTH,
                                                  self._DST_HEIGHT, pos.x, pos.y)
            try:
                self._tcp_sock.sendall(
                    srt_client.srt_connector.aes_ctr_encrypt(
                        srt_client.srt_connector.tcp_serialization(MOUSE_POSITION_REPORTING_CODE,
                                                                   pos[0].to_bytes(2,
                                                                                   'big') + pos[1].to_bytes(
                                                                       2,
                                                                       'big')), self._shared_key,
                        self._counter_key))

            except (socket.timeout, socket.error) as e:
                print(f"Error encountered in send_mouse_position_thread while sending data - {str(e)}")
            except Exception as e:
                print("Error encountered in mouse_position_sender thread - " + str(e))
            time.sleep(0.03)

    def keyboard_logger_thread(self, thread_obj):
        """
        Starts a keyboard keylogger thread.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
        :rtype: None
        """

        keyboard_logger = threading.Thread(target=keylogger.start_keyboard_logger,
                                           args=(self._buttons,  self._buttons_lock,))
        keyboard_logger.start()

    def input_sender_thread(self, thread_obj):
        """
        Sends input events (mouse and keyboard) to the slave.
        :param thread_obj: Thread object
        :type thread_obj: threading.Thread
        :rtype: None
        """

        # sending the queues to the slave and clearing the queues
        while True:
            try:
                if not self._buttons.empty():
                    with self._buttons_lock:
                        self._tcp_sock.sendall(srt_client.srt_connector.aes_ctr_encrypt(
                            srt_client.srt_connector.tcp_serialization(ALL_BUTTONS_CODE,
                                                                       pickle.dumps(self._buttons.queue)),
                            self._shared_key, self._counter_key))
                        self._buttons.queue.clear()
                time.sleep(0.03)
            except Exception as e:
                print("Error encountered in input_sender thread - " + str(e))

    def start_remote_control_connector(self):
        """
        Starts the remote control connector by initializing sockets, exchanging encryption details and starting multiple threads to handle mouse and keyboard logging, sending mouse position, and input sending. This function blocks until the input_sender_thread completes execution.

        Raises:
        Exception: If there is an error in exchanging encryption keys or resolution details with the remote host.

        :return: None
        :rtype: None
        """
        self.initialize_sockets_connector()
        self.exchange_encryption_connector()
        threading.Thread(target=self.mouse_logger_thread, args=(self,)).start()
        threading.Thread(target=self.keyboard_logger_thread, args=(self,)).start()
        threading.Thread(target=self.send_mouse_position_thread, args=(self,)).start()
        t = threading.Thread(target=self.input_sender_thread, args=(self,))
        t.start()
        t.join()


