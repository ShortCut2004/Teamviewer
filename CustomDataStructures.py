from collections import deque
from collections import OrderedDict
import pickle


class DequeQueue:
    """
    Custom queue class
    """

    def __init__(self, max_size):
        """
        Initializes the DequeQueue with a specified maximum size.

        :param max_size: The maximum size of the queue.
        :type max_size: int
        """
        if max_size == 0:
            self.queue = deque()
        else:
            self.queue = deque(maxlen=max_size)
        self.max_size = max_size

    def empty(self):
        """
        Checks if the queue is empty.

        :return: True if the queue is empty, False otherwise.
        :rtype: bool
        """
        return len(self.queue) == 0

    def is_full(self):
        """
        Checks if the queue is full.

        :return: True if the queue is full, False otherwise.
        :rtype: bool
        """
        if self.max_size == 0:
            return False
        return len(self.queue) == self.max_size

    def put(self, item):
        """
        Adds an item to the end of the queue. If the queue is full, removes the first item before adding the new one.

        :param item: The item to add to the queue.
        :type item: object
        """
        if self.is_full():
            self.queue.popleft()
        self.queue.append(item)

    def get(self):
        """
        Removes and returns the first item in the queue.

        :return: The first item in the queue.
        :rtype: object
        :raises IndexError: If the queue is empty.
        """
        if self.empty():
            raise IndexError("Get from an empty queue")
        return self.queue.popleft()

    def size(self):
        """
        Returns the current size of the queue.

        :return: The size of the queue.
        :rtype: int
        """
        return len(self.queue)

    def clear(self):
        """
        Removes all items from the queue.
        """
        self.queue.clear()

    def __bytes__(self):
        """
        Returns a bytes' representation of the DequeQueue.

        :return: A bytes object representing the DequeQueue.
        :rtype: bytes
        """
        return pickle.dumps(self.queue)

    @classmethod
    def from_bytes(cls, bytes_obj):
        """
        Creates a new DequeQueue instance from a bytes representation.

        :param bytes_obj: A bytes object representing the DequeQueue.
        :type bytes_obj: bytes
        :return: A new DequeQueue instance with the deserialized deque.
        :rtype: DequeQueue
        """
        deserialized_queue = pickle.loads(bytes_obj)
        max_size = deserialized_queue.maxlen
        new_queue = cls(max_size)
        new_queue.queue = deserialized_queue
        return new_queue


class MaxSizeDict(OrderedDict):
    def __init__(self, max_size):
        self.max_size = max_size
        super().__init__()

    def __setitem__(self, key, value):
        if key not in self and len(self) >= self.max_size:
            oldest_key = next(iter(self))
            del self[oldest_key]
        super().__setitem__(key, value)
