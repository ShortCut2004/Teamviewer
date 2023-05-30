import numpy as np
import cv2
TEMP_RESOLUTION = (1920, 1080, 3)


def find_difference_between_two_frames(last_frame, new_frame):
    # Calculate the absolute difference between the two frames
    return new_frame
    # return cv2.absdiff(last_frame, new_frame)


def translate_difference_into_bytes(diff):
    is_success, im_buf_arr = cv2.imencode(".jpg", diff)
    return im_buf_arr.tobytes()


def translate_bytes_into_difference(byte_arr, resolution):
    flatNp = np.frombuffer(byte_arr, dtype=np.uint8, count=-1)
    return np.resize(flatNp, resolution)


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


def codec_frame(last_frame, new_frame):
    # Calculate the difference between the two frames, translate it into text, and compress it
    return translate_difference_into_bytes(find_difference_between_two_frames(last_frame, new_frame))


def codec_frame_without_reference(new_frame):
    return translate_difference_into_bytes(new_frame)
