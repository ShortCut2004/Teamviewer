import threading

import pynput.mouse
from pynput import keyboard
from pynput import mouse
from threading import Thread
from time import sleep
import pyautogui
import CustomDataStructures as structs
import os

# Global queue variables
keyboard_pressed_queue = 0
mouse_pressed_queue = 0
mouse_released_queue = 0

# Global queue locks
keyboard_presses_lock = 0
mouse_presses_lock = 0
mouse_releases_lock = 0

# Global driver controller variables
mouse_eventer = mouse.Controller()
keyboard_eventer = keyboard.Controller()

# Global threading conditions
keyboard_logger_condition = 0
mouse_logger_condition = 0

# Global mouse keys dict
currently_pressed = {mouse.Button.left: False, mouse.Button.right: False, mouse.Button.middle: False}


def translate_coordinates(src_width, src_height, dst_width, dst_height, x, y):
    """
    The function calculates the equivalent coordinates in a new coordinate system
    with a different width and height, maintaining the aspect ratio.
    :param src_width: the width of the source coordinate system
    :type src_width: int
    :param src_height: the height of the source coordinate system
    :type src_height: int
    :param dst_width: the width of the destination coordinate system
    :type dst_width: int
    :param dst_height: the height of the destination coordinate system
    :type dst_height: int
    :param x: the x-coordinate in the source coordinate system
    :type x: int or float
    :param y: the y-coordinate in the source coordinate system
    :type y: int or float

    :return: the equivalent (x, y) coordinates in the destination coordinate system
    :rtype: list of int
    """
    return [int(x * (dst_width / src_width)), int(y * (dst_height / src_height))]


# this function runs each time a key is pressed
def on_press(key):
    """
    The function receives the keyboard key pressed and enters it into a queue
    :param key: the key pressed
    :type key: enum 'Key'
    """

    global keyboard_pressed_queue, keyboard_presses_lock
    keyboard_presses_lock.acquire()
    keyboard_pressed_queue.put(key)
    keyboard_presses_lock.release()
    print("keyboard key {0} was pressed".format(key))


# this function runs each time a mouse button is pressed
def on_click(x, y, button, pressed):
    """
    The function receives the button pressed and a boolean value that resembles if the button was pressed or released
    :param button: the mouse button pressed
    :param pressed: a boolean value resembling if the button was pressed or released
    :type button: enum 'Button'
    :type pressed: bool
    """

    global mouse_released_queue, mouse_pressed_queue, mouse_presses_lock, mouse_releases_lock
    if pressed:
        mouse_presses_lock.acquire()
        mouse_pressed_queue.put(button)
        mouse_presses_lock.release()
        print("mouse button {0} was pressed".format(str(button)))

    else:
        mouse_releases_lock.acquire()
        mouse_released_queue.put(button)
        mouse_releases_lock.release()
        print("mouse button {0} was released".format(str(button)))


def input_mouse_presses(mouse_press_queue):
    """
    The function receives a queue of mouse buttons that were pressed and inputs it
    :param mouse_press_queue: the queue of mouse buttons that need to be pressed
    :type mouse_press_queue: collections.deque
    """

    for button in mouse_press_queue:
        mouse_eventer.press(button)


def input_mouse_releases(mouse_release_queue):
    """
    The function receives a queue of mouse buttons that were released and inputs it
    :param mouse_release_queue: the queue of mouse buttons that need to be released
    :type mouse_release_queue: collections.deque
    """

    for button in mouse_release_queue:
        mouse_eventer.release(button)


def input_keyboard_presses(keyboard_press_queue):
    """
    The function receives a queue of keyboard buttons that were pressed and inputs it
    :param keyboard_press_queue: the queue of keyboard buttons that need to be pressed
    :type keyboard_press_queue: collections.deque
    """
    for button in keyboard_press_queue:
        keyboard_eventer.press(button)


def input_all_presses(general_queue):
    for button in general_queue:
        if type(button) == pynput.mouse.Button:
            if currently_pressed[button]:
                mouse_eventer.release(button)
                currently_pressed[button] = False
            else:
                mouse_eventer.press(button)
                currently_pressed[button] = True
        else:
            keyboard_eventer.press(button)


def move_mouse_pointer(x, y):
    """
    The function receives coordinates and moves the mouse to those coordinates
    :param x: the x value of the coordinate
    :param y: the y value of the coordinate
    :type x: int
    :type y: int
    """

    mouse_eventer.position = (x, y)


def start_keyboard_logger(keyboard_queue, keyboard_press_lock):
    """
    The function creates a thread that runs the keyboard keylogger
    :param keyboard_press_lock: the lock used for the keyboard presses queue
    :param keyboard_queue: a queue to enter keyboard presses to
    :type keyboard_queue: queue.Queue
    :type  keyboard_press_lock: threading.Lock
    """

    global keyboard_pressed_queue, keyboard_presses_lock
    keyboard_presses_lock = keyboard_press_lock
    keyboard_pressed_queue = keyboard_queue
    board_listener = keyboard.Listener(on_press=on_press)
    board_listener.start()
    board_listener.join()


def start_mouse_logger(mouse_press_queue, mouse_release_queue, mouse_press_lock, mouse_release_lock):
    """
    The function creates a thread that runs the keyboard keylogger
    :param mouse_release_lock: the lock used for the mouse releases queue
    :param mouse_press_lock: the lock used for the mouse presses queue
    :param mouse_press_queue: a queue to enter mouse button presses to
    :param mouse_release_queue: a queue to enter mouse button releases to
    :type mouse_press_queue: queue.Queue
    :type mouse_release_queue: queue.Queue
    :type mouse_press_lock: threading.Lock
    :type mouse_release_lock: threading.Lock
    """

    global mouse_released_queue, mouse_pressed_queue, mouse_presses_lock, mouse_releases_lock
    mouse_pressed_queue = mouse_press_queue
    mouse_released_queue = mouse_release_queue
    mouse_presses_lock = mouse_press_lock
    mouse_releases_lock = mouse_release_lock
    listener = mouse.Listener(on_click=on_click)
    listener.start()
    listener.join()
