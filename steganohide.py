"""This is a nice module."""

import argparse
from PIL import Image

def parse_args():
    """Parse the commandline arguments"""
    parser = argparse.ArgumentParser(description='This script hides a given text from a file steganographically in a given image. The result is saved to <imagefile>.ste.bmp')
    parser.add_argument('filetohide', metavar='textfile', type=argparse.FileType('r'),
                        help='The file that should be hidden inside the image.')
    parser.add_argument('image', metavar='imagefile', type=argparse.FileType('rb'),
                        help='The image.')
    args = parser.parse_args()
    return args

def open_image(img_file):
    """Open and return a file as image."""
    img = Image.open(img_file)
    return img

def get_image_data(img):
    """Get pixel-wise color data from given Image as list of RGB-values (int,int,int)"""
    img_data = list(img.getdata())
    return img_data

def str_to_bits(stri):
    """Convert a string to a list of its bits"""
    result = []
    for char in stri:
        bits = bin(ord(char))[2:]
        bits = '00000000'[len(bits):] + bits
        reso = []
        for bit in bits:
            reso.append(int(bit))
        result.append(reso)
    return result

def stegano_hide(img, text_to_hide):
    """Hides a text inside an image via least significant bit replacing"""
    img_data = get_image_data(img)
    str_data = str_to_bits(text_to_hide)
    # print str_data
    # print img_data[0]
    i = 0
    for char_data in str_data:
        # print char_data
        for char_bit in char_data:
            pixel_index = i / 3
            rgb_index = i % 3
            if rgb_index == 0:
                img_data[pixel_index] = list(img_data[pixel_index])
            # print 'Pixel: ' + str(pixel_index) + ' RGB: ' +  str(rgb_index) + ' Bit to set: ' + str(char_bit)
            i += 1
            new_img_pixel_rgb_data = override_least_significant_bit(img_data[pixel_index][rgb_index], char_bit)
            # print 'From ' + str(img_data[pixel_index][rgb_index]) + ' to ' + str(new_img_pixel_rgb_data)
            img_data[pixel_index][rgb_index] = new_img_pixel_rgb_data

    altered_pixels = i / 3
    overall_pixels = img.size[0] * img.size[1]
    altered_percentage = altered_pixels / float(overall_pixels)
    print 'Altered pixels: ' + str(altered_pixels) + ' of ' + str(overall_pixels) + ' (' + str((altered_percentage * 100)) + ' %)'
    new_data = [tuple(pixel) for pixel in img_data]
    # print new_data
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_data)
    return new_img

def override_least_significant_bit(integer, bit):
    """Overrides the last bit of an integer with the given one and returns the result"""
    # http://stackoverflow.com/questions/6059454/replace-least-significant-bit-with-bitwise-operations
    integer = (integer & ~1) | bit
    return integer

def main():
    """Main function"""
    args = parse_args()

    file_to_hide = args.filetohide
    text_to_hide = file_to_hide.readlines()

    imagefile = args.image
    img = open_image(imagefile)

    img_hidden = stegano_hide(img, text_to_hide[0])

    img_hidden.save(imagefile.name + '.ste.bmp', 'BMP')
    img.save(imagefile.name + '.bmp', 'BMP')

if __name__ == "__main__":
    main()
