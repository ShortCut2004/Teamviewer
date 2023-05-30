import cv2
import numpy as np

HEIGHT = 0
WIDTH = 1


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


def apply_differnce_to_last_frame(last_frame,diff):
    last_frame[diff!=0] = diff
    return last_frame