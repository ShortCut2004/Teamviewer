import threading
import keylogger
import queue
import time
import socket
import srt_host
import pyautogui
import pickle
import collections

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


class remote_control_host:
    def __init__(self, ip):
        self._tcp_sock = None
        self._ip = ip
        self._tcp_port = TCP_PORT
        self._shared_key = None
        self._counter_key = None
        self._received_packets = queue.Queue()
        self._received_packets_lock = threading.Lock()
        self._packet_received = threading.Event()
        self._DST_WIDTH = 1920
        self._DST_HEIGHT = 1080
        self._SRC_HEIGHT = int(pyautogui.screenshot().height * 0.95)
        self._SRC_WIDTH = pyautogui.screenshot().width

    def initialize_sockets_host(self):
        """
        This method initializes a TCP socket to listen for incoming connections
        from a client. It sets the socket options for reusing the same port and
        accepts the connection from the client.

        :return: None
        :rtype: None
        """

        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('', self._tcp_port)
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

    def exchange_encryption_host(self):
        """
        This method performs the encryption key exchange process with the other party.
        It generates a private and a public key, sends the public key over the TCP socket
        to the other party, receives the other party's public key, derives the shared key
        and the counter key, and exchanges the resolution information with the other party.

        :return: None
        :rtype: None
        """

        private_key, public_key = srt_host.srt_host.generate_keys()

        # Send the public key to the other party over the TCP socket
        self._tcp_sock.sendall(
            srt_host.srt_host.tcp_serialization(ENCRYPTION_KEYS_EXCHANGE_CODE,
                                                public_key.export_key(format="PEM").encode()))

        # Receive the other party's public key over the TCP socket, decrypt it using the private key, and import it
        other_public_key = srt_host.ECC.import_key(
            srt_host.srt_host.tcp_deserialization(self._tcp_sock.recv(DEFAULT_RECV_SIZE))['data'].decode())

        self._shared_key = srt_host.srt_host.derive_shared_key(private_key, other_public_key)

        self._counter_key = srt_host.srt_host.derive_counter(self._shared_key)

        self._tcp_sock.sendall(
            srt_host.srt_host.aes_ctr_encrypt(srt_host.srt_host.tcp_serialization(RESOLUTION_EXCHANGE_MESSAGE_CODE,
                                                                                  self._SRC_WIDTH.to_bytes(2,
                                                                                                           'big') + self._SRC_HEIGHT.to_bytes(
                                                                                      2, 'big')),
                                              self._shared_key, self._counter_key))
        msg = srt_host.srt_host.tcp_deserialization(
            srt_host.srt_host.aes_ctr_decrypt(self._tcp_sock.recv(DEFAULT_RECV_SIZE), self._shared_key,
                                              self._counter_key))
        if msg['code'] == RESOLUTION_EXCHANGE_MESSAGE_CODE:
            self._DST_WIDTH = int.from_bytes(msg['data'][0:2], 'big')
            self._DST_HEIGHT = int.from_bytes(msg['data'][2:4], 'big')
        else:
            raise Exception("Haven't received other side's resolution")

    def receiver_thread(self, thread_obj):
        """
        This method runs in a separate thread and continuously receives the encrypted messages over the TCP socket.
        It decrypts the message and puts it into a thread-safe queue for further processing.

        :param thread_obj: an instance of threading.Thread representing the thread running the method
        :type thread_obj: threading.Thread
        :return: None
        :rtype: None
        """

        while True:
            try:
                msg = srt_host.srt_host.tcp_deserialization(
                    srt_host.srt_host.aes_ctr_decrypt(self._tcp_sock.recv(DEFAULT_RECV_SIZE), self._shared_key,
                                                      self._counter_key))
                with self._received_packets_lock:
                    self._received_packets.put(msg)
                self._packet_received.set()
                time.sleep(0.02)
            except Exception:
                pass

    def receive_commands_thread(self, thread_obj):
        """
        Receives input commands from the master and executes them.

        :param thread_obj: an instance of threading.Thread representing the thread running the method
        :type thread_obj: threading.Thread
        :return: None
        :rtype: None
        """
        data = []

        while True:
            try:
                if self._received_packets.empty():
                    self._packet_received.wait()
                    self._packet_received.clear()
                while not self._received_packets.empty():
                    with self._received_packets_lock:
                        data = self._received_packets.get()

                    if data['code'] == MOUSE_POSITION_REPORTING_CODE:
                        keylogger.move_mouse_pointer(int.from_bytes(data['data'][0:2], "big"),
                                                     int.from_bytes(data['data'][2:4], "big"))
                    elif data['code'] == MOUSE_PRESSES_REPORTING_CODE:
                        keylogger.input_mouse_presses(collections.deque(pickle.loads(data['data'])))
                    elif data['code'] == MOUSE_RELEASE_REPORTING_CODE:
                        keylogger.input_mouse_releases(collections.deque(pickle.loads(data['data'])))
                    elif data['code'] == KEYBOARD_PRESSES_REPORTING_CODE:
                        keylogger.input_keyboard_presses(collections.deque(pickle.loads(data['data'])))
                    elif data['code'] == ALL_BUTTONS_CODE:
                        keylogger.input_all_presses(collections.deque(pickle.loads(data['data'])))
                    else:
                        print("Unknown code was encountered in receive_commands thread")
                    time.sleep(0.01)

            except Exception as e:
                print("Error was encountered in receive_commands thread - " + str(e))

    def start_remote_control_host(self):
        """
        Initializes sockets, exchanges encryption keys, starts a receiver thread,
        and waits for incoming commands in a separate thread.

        :return: None
        :rtype: None
        """

        self.initialize_sockets_host()
        self.exchange_encryption_host()
        threading.Thread(target=self.receiver_thread, args=(self,)).start()
        t = threading.Thread(target=self.receive_commands_thread, args=(self,))
        t.start()
        t.join()

