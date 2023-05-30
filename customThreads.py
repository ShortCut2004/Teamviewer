# Python program raising
# exceptions in a python
# thread

import threading
import ctypes
import time


class threadHelper(threading.Thread):
    @staticmethod
    def get_id(curr_thread):

        # returns id of the respective thread
        for thread_id, thread in threading._active.items():
            if thread is curr_thread:
                return thread_id

    @staticmethod
    def raise_exception(curr_thread):
        thread_id = curr_thread.get_id()
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id,
                                                         ctypes.py_object(SystemExit))
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            print('Exception raise failure')
