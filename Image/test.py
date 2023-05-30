import numpy as np
import cv2
import pyautogui
import imutils
import time
from datetime import datetime


HEIGHT = 0
WIDTH = 1

def take_screenshot_and_save_as_rgb_array():
    # Take a screenshot
    image = pyautogui.screenshot()

    # Convert the screenshot into an RGB array
    image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
    return image


def find_difference_between_two_frames(last_frame, new_frame):
    # Calculate the absolute difference between the two frames
    return cv2.absdiff(last_frame, new_frame)


def translate_difference_into_bytes(difference):
    is_success, im_buf_arr = cv2.imencode(".jpg", difference)
    return im_buf_arr.tobytes()


def translate_bytes_into_difference(byte_arr):
    return np.frombuffer(byte_arr, dtype=np.uint8)


def compress_byte_array(data: bytes) -> bytes:
    # Initialize the variables for the compression
    uncompressed_index = 0
    compressed_data = bytearray()
    current_char = data[uncompressed_index]
    char_count = 1

    # Iterate through the data to find runs of the same character
    for i in range(1, len(data)):
        if data[i] == current_char:
            # Increase the count if the character is the same as the previous one
            char_count += 1
        else:
            # Append the character and its count to the compressed data
            compressed_data.append(current_char)
            compressed_data.append(char_count)

            # Reset the character and its count
            current_char = data[i]
            char_count = 1

    # Add the final character and its count to the compressed data
    compressed_data.append(current_char)
    compressed_data.append(char_count)

    # Return the compressed data as a bytes object
    return bytes(compressed_data)


def decompress_byte_array(compressed_data: bytes) -> bytes:
    # Initialize the variables for the decompression
    compressed_index = 0
    decompressed_data = bytearray()

    # Iterate through the compressed data
    while compressed_index < len(compressed_data):
        # Get the current character and its count
        current_char = compressed_data[compressed_index]
        char_count = compressed_data[compressed_index + 1]

        # Append the character to the decompressed data the number of times indicated by the count
        decompressed_data.extend([current_char] * char_count)

        # Move the index to the next character and its count
        compressed_index += 2

    # Return the decompressed data as a bytes object
    return bytes(decompressed_data)


def change_resolution(image, dst_height, dst_width, black_bars):
    if black_bars and dst_height > image.shape[HEIGHT] and dst_width > image.shape[WIDTH]:
        return apply_black_bars(image, dst_height, dst_width)
    return cv2.resize(image, dsize=(dst_width, dst_height), interpolation=cv2.INTER_CUBIC)


def apply_black_bars(image, dst_height, dst_width):
    blank_image = np.zeros((dst_height, dst_width, 3), np.uint8)
    height_start = (dst_height - image.shape[HEIGHT]) / 2
    width_start = (dst_width - image.shape[WIDTH]) / 2
    blank_image[int(height_start):int(height_start + image.shape[0]),
    int(width_start):int(width_start + image.shape[1])] = image
    return blank_image



first = take_screenshot_and_save_as_rgb_array()
time.sleep(2)
second = take_screenshot_and_save_as_rgb_array()
diff = find_difference_between_two_frames(first, second)
first_time = datetime.utcnow()
translate_bytes_into_difference(translate_difference_into_bytes(diff))
second_time = datetime.utcnow()
print("Time Passed(Without Compression):", second_time - first_time)
first_time = datetime.utcnow()
translate_bytes_into_difference(
    decompress_byte_array(compress_byte_array(translate_difference_into_bytes(diff))))
second_time = datetime.utcnow()
print("Time Passed(With Compression):", second_time - first_time)
