"""
This script encrypts/decrypts a given text file with XTEA in CFB mode into a given picture via
steganography.
"""

import argparse
from hashlib import sha256
import hmac
from random import getrandbits
from PIL import Image

def parse_args():
    """Parse the commandline arguments."""
    parser = argparse.ArgumentParser(description='This script hides a given text from a file '\
        + 'steganographically in a given image. The result is saved to <imagefile>.ste.bmp')

    subparsers = parser.add_subparsers(help='sub-command help', dest='mode')

    # Encryption args
    parser_e = subparsers.add_parser('e', help='encryption mode')
    parser_e.add_argument('-m', metavar=('macpassword'),
                          nargs=1, required=True, help='The MAC password')
    parser_e.add_argument('-k', metavar=('password'),
                          nargs=1, required=True, help='The password')
    parser_e.add_argument('filetohide', metavar='textfile',
                          type=argparse.FileType('r'),
                          help='The file that should be hidden inside the image.')
    parser_e.add_argument('image', metavar='imagefile',
                          type=argparse.FileType('rb'), help='The image.')

    # Decryption args
    parser_d = subparsers.add_parser('d', help='decryption mode')
    parser_d.add_argument('-m', metavar=('macpassword'),
                          nargs=1, required=True, help='The MAC password')
    parser_d.add_argument('-k', metavar=('password'),
                          nargs=1, required=True, help='The password')
    parser_d.add_argument('image', metavar='imagefile',
                          type=argparse.FileType('rb'), help='The image.')

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
    return [int(bit) for byte in stri for bit in bin(ord(byte))[2:].zfill(8)]

def bits_to_str(bits):
    """Convert a string to a list of its bits"""
    bits_str = ''.join(str(x) for x in bits)
    return ''.join(chr(int(bits_str[i * 8 : i * 8 + 8], 2)) for i in range(len(bits_str) // 8))

def stegano_hide(img, str_data):
    """Hides a text inside an image via least significant bit replacing"""
    img_data = get_image_data(img)
    # print str_data
    # print img_data[0]
    i = 0

    for char_bit in str_data:
        pixel_index = i / 3
        rgb_index = i % 3
        if rgb_index == 0:
            img_data[pixel_index] = list(img_data[pixel_index])
        # print 'Pixel: ' + str(pixel_index) + ' RGB: ' +  str(rgb_index) + ' Bit to set: ' + str(char_bit)
        i += 1
        new_img_pixel_rgb_data = override_least_significant_bit(img_data[pixel_index][rgb_index],
                                                                char_bit)
        # print 'From ' + str(img_data[pixel_index][rgb_index]) + ' to ' + str(new_img_pixel_rgb_data)
        img_data[pixel_index][rgb_index] = new_img_pixel_rgb_data

    altered_pixels = i / 3
    overall_pixels = img.size[0] * img.size[1]
    altered_percentage = altered_pixels / float(overall_pixels)
    print 'Altered pixels: ' + str(altered_pixels) + ' of ' + str(overall_pixels) \
          + ' (' + str((altered_percentage * 100)) + ' %)'
    new_data = [tuple(pixel) for pixel in img_data]
    # print new_data
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_data)
    return new_img


def get_bits_from_least_significant_bits(img, start_at_bit, length):
    """Returns least significant bits from the RGB values of a given picture."""
    img_data = get_image_data(img)
    bits = []
    for i in range(start_at_bit, start_at_bit + length):
        pixel_index = i / 3
        rgb_index = i % 3
        if rgb_index == 0:
            img_data[pixel_index] = list(img_data[pixel_index])
        least_significant_bit = img_data[pixel_index][rgb_index] & 0x00000001
        bits.append(least_significant_bit)
    return bits

def encrypt(img_file, text_file, mac_passwd, passwd):
    """Encrypts a given textfile and its HMAC (SHA256) via XTEA CFB."""
    # text = ''.join(text_file.readlines())
    text = text_file.read()
    # print text

    img = open_image(img_file)
    # print img_data
    text_data = str_to_bits(text)
    # print text_data
    # 64 bit zum Text hinzufuegen
    text_data_length_64 = [int(x) for x in bin(len(text_data))[2:].zfill(64)]

    # print text_data

    ### Unteraufgabe 1 Authentizieren Sie die Daten mittels HMAC-SHA256
    # MAC Passwort mit SHA256 hashen
    mac_passwd_sha256 = sha256(mac_passwd.encode('utf-8'))
    # Aus SHA256 hash des MAC Passworts MAC erstellen
    mac_sha256 = hmac.new(mac_passwd_sha256.digest(),
                          ''.join([str(x) for x in text_data]).encode('utf-8'),
                          sha256)

    # Binaerdaten aus MAC erstellen (Laenge = 256-bit)
    mac_sha256_data = [int(x) for x in bin(int(mac_sha256.hexdigest(), 16))[2:].zfill(256)]

    # MAC und Laenge den Daten voranstellen
    hmac_length_text_data = mac_sha256_data + text_data_length_64 + text_data

    ## Sicherstellen, dass das ganze durch 64 teilbar ist
    if len(hmac_length_text_data) % 64 != 0:
        hmac_length_text_data += [0] * (64 - len(hmac_length_text_data) % 64)

    # Unteraufgabe 2 Verschluesseln Sie die Daten inklusive des MAC mit dem XTEA Algorithmus im
    # CFB Mode.

    passwd_sha256 = sha256(passwd.encode('utf-8'))
    # print text_plus_mac_data
    # print len(text_plus_mac_data)

    # Binaerdaten aus passwd_sha256 erstellen
    passwd_sha256_data = [int(x) for x in bin(int(passwd_sha256.hexdigest(), 16))[2:].zfill(256)]

    cipherKey = []
    for subList in [passwd_sha256_data[x:x+32] for x in range(0, 128, 32)] :
        cipherKey.append(listToNum(subList))

    IV = [getrandbits(32), getrandbits(32)]
    # print IV
    cipherBitList, current_IV = xtea_cfb_encrypt(IV, cipherKey, hmac_length_text_data)

    # IV zur Cipher hinzufuegen
    IV1 = list(map(int, bin(IV[0])[2:].zfill(32)))
    IV2 = list(map(int, bin(IV[1])[2:].zfill(32)))
    IV_complete = IV1 + IV2
    IV_data_plus_cipher_data = IV_complete + cipherBitList

    # print 'Encrypting:'
    # print '  Image:               ' + img_file.name
    # print '  Textfile:            ' + text_file.name
    # print '  Textfile content:    ' + text
    # print '  MAC-Password:        ' + mac_passwd
    # print '  Password:            ' + passwd
    # print '  MAC-Password SHA256: ' + mac_passwd_sha256.hexdigest()
    # print '  Password SHA256:     ' + passwd_sha256.hexdigest()
    # print '  HMAC (SHA256):       ' + mac_sha256.hexdigest()

    # print 'HMAC (256 bit):          ' + ''.join(str(x) for x in mac_sha256_data)
    # print 'Payload length (64 bit): ' + ''.join(str(x) for x in text_data_length_64)
    # print 'Payload length int:      ' + str(len(text_data))
    # print 'Payload:                 ' + ''.join(str(x) for x in text_data)
    # print 'HMAC+length+Payload:     ' + ''.join(str(x) for x in hmac_length_text_data)
    # print 'Cipher:                  ' + ''.join(str(x) for x in cipherBitList)
    # print 'Initial Vector (64 bit): ' + ''.join(str(x) for x in IV_complete)
    # print 'IV + Cipher:             ' + ''.join(str(x) for x in IV_data_plus_cipher_data)
    return IV_data_plus_cipher_data

def decrypt(img_file, mac_passwd, passwd):
    """
    Decrypts an XTEA CFB encrypted text from the least significant bits of an image and verifies
    its HMAC.
    """
    try:
        IV_LENGTH = 64
        HMAC_LENGTH = 256
        PAYLOAD_LENGTH_LENGTH = 64

        img = open_image(img_file)

        img_iv_data = get_bits_from_least_significant_bits(img, 0, IV_LENGTH)
        img_hmac_256_encrypted = get_bits_from_least_significant_bits(img, IV_LENGTH, HMAC_LENGTH)
        img_payload_length_encrypted = get_bits_from_least_significant_bits(img,
                                                                            IV_LENGTH + HMAC_LENGTH,
                                                                            PAYLOAD_LENGTH_LENGTH)

        # MAC Passwort mit SHA256 hashen
        mac_passwd_sha256 = sha256(mac_passwd.encode('utf-8'))

        # Passwort hashen
        passwd_sha256 = sha256(passwd.encode('utf-8'))
        passwd_sha256_data = [int(x) for x in bin(int(passwd_sha256.hexdigest(), 16))[2:].zfill(256)]

        cipher_key = []
        for sub_list in [passwd_sha256_data[x:x+32] for x in range(0, 128, 32)]:
            cipher_key.append(listToNum(sub_list))

        IV1 = img_iv_data[:32]
        IV2 = img_iv_data[32:64]
        # print IV1
        # print IV2
        IV = [int(''.join(str(x) for x in IV1), 2), int(''.join(str(x) for x in IV2), 2)]
        # print IV

        img_hmac_256_decrypted, IV = xtea_cfb_decrypt(IV, cipher_key, img_hmac_256_encrypted)


        img_payload_length_decrypted, IV = xtea_cfb_decrypt(IV, cipher_key, img_payload_length_encrypted)
        img_payload_length_decrypted_int = listToNum(img_payload_length_decrypted)
        img_payload_length_decrypted_int_filled = (64 - (img_payload_length_decrypted_int % 64)) + img_payload_length_decrypted_int
        img_payload_encrypted = get_bits_from_least_significant_bits(img, IV_LENGTH + HMAC_LENGTH + PAYLOAD_LENGTH_LENGTH, img_payload_length_decrypted_int_filled)
        img_payload_decrypted, IV = xtea_cfb_decrypt(IV, cipher_key, img_payload_encrypted)
        img_payload_decrypted_cropped = img_payload_decrypted[:img_payload_length_decrypted_int]
        payload = bits_to_str(img_payload_decrypted_cropped)

        # Aus SHA256 hash des MAC Passworts MAC erstellen
        mac_sha256 = hmac.new(mac_passwd_sha256.digest(),
                              ''.join([str(x) for x in img_payload_decrypted_cropped])
                              .encode('utf-8'),
                              sha256)

        # Binaerdaten aus MAC erstellen (Laenge = 256-bit)
        mac_sha256_data = [int(x) for x in bin(int(mac_sha256.hexdigest(), 16))[2:].zfill(256)]

        is_hmac_correct = img_hmac_256_decrypted == mac_sha256_data


        # print 'IV (img):                                  ' + ''.join(str(x) for x in img_iv_data)
        # print 'HMAC encrypted (img):                      ' + ''.join(str(x) for x in img_hmac_256_encrypted)
        # print 'HMAC decrypted (img):                      ' + ''.join(str(x) for x in img_hmac_256_decrypted)
        # print 'HMAC from decrypted payload:               ' + ''.join(str(x) for x in mac_sha256_data)
        # print 'Payload length encrypted (img):            ' + ''.join(str(x) for x in img_payload_length_encrypted)
        # print 'Payload length decrypted (img):            ' + ''.join(str(x) for x in img_payload_length_decrypted)
        # print 'Payload length decrypted int (img):        ' + str(img_payload_length_decrypted_int)
        # print 'Payload length decrypted int filled (img): ' + str(img_payload_length_decrypted_int_filled)
        # print 'Payload encrypted (img):                   ' + ''.join(str(x) for x in img_payload_encrypted)
        # print 'Payload decrypted cropped (img):           ' + ''.join(str(x) for x in img_payload_decrypted_cropped)
        # print 'Payload:                                   ' + payload
        # print 'HMAC correct:                              ' + str(is_hmac_correct)


        # print 'Decrypting:'
        # print '  Image:        ' + img_file.name
        # print '  MAC-Password: ' + mac_passwd
        # print '  Password:     ' + passwd
        if not is_hmac_correct:
            print '====The hmac is not correct. The payload could have been altered!===='.upper()
        return payload
    except Exception:
        return 'An error occurred. Maybe the entered key was wrong!'

def xtea_cfb_encrypt(initial_vector, key, data):
    """Encrypts data with XTEA CFB."""
    initial_vector_copy = initial_vector[:]
    cipher_bit_list = []
    for bit_64 in [data[x:x+64] for x in range(0, len(data), 64)]:

        ## block cipher encryption
        encipher(32, initial_vector_copy, key)

        ## get current plaintext
        num32 = [listToNum(bit_64[:32]), listToNum(bit_64[32:])]

        ## xor
        initial_vector_copy[0] ^= num32[0]
        initial_vector_copy[1] ^= num32[1]

        ## store encrypted text
        for num in initial_vector_copy:
            cipher_bit_list += list(map(int, bin(num)[2:].zfill(32)))

    return cipher_bit_list, initial_vector_copy

def xtea_cfb_decrypt(initial_vector, key, data):
    """Decrypts data with XTEA CFB."""
    initial_vector_copy = initial_vector[:]
    cipher_bit_list = []
    for bit_64 in [data[x:x+64] for x in range(0, len(data), 64)]:

        ## block cipher encryption
        encipher(32, initial_vector_copy, key)

        ## get current plaintext
        num32 = [listToNum(bit_64[:32]), listToNum(bit_64[32:])]

        ## xor
        plain = [initial_vector_copy[0] ^ num32[0], initial_vector_copy[1] ^ num32[1]]

        ## new IV is the old cipher text
        initial_vector_copy = num32

        ## store decrypted text
        for num in plain:
            cipher_bit_list += list(map(int, bin(num)[2:].zfill(32)))

    return cipher_bit_list, initial_vector_copy

def encipher(numRounds, dataBlocks, keyBlocks):
    """XTEA Encipher method."""
    '''
    void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
        unsigned int i;
        uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
        for (i=0; i < num_rounds; i++) {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
            sum += delta;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        }
        v[0]=v0; v[1]=v1;
    }
    '''

    ## preparation
    v0 = int(dataBlocks[0])
    v1 = int(dataBlocks[1])

    delta = 0x9E3779B9
    mask = 0xFFFFFFFF

    sum = 0

    ## magic
    for round in range(numRounds):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + keyBlocks[sum & 3]))) & mask
        sum = (sum + delta) & mask
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + keyBlocks[(sum >> 11) & 3]))) & mask

    ## store new values
    dataBlocks[0] = v0
    dataBlocks[1] = v1

def listToNum(list):
    """Converts a bit-list [0, 1, 0, 1] to an int."""
    return int(''.join(str(x) for x in list), 2)

def override_least_significant_bit(integer, bit):
    """Overrides the last bit of an integer with the given one and returns the result"""
    # http://stackoverflow.com/questions/6059454/replace-least-significant-bit-with-bitwise-operations
    integer = (integer & ~1) | bit
    return integer

def main():
    """Main function"""
    args = parse_args()
    # print vars(args)

    if args.mode == 'e':
        # print 'Entering encryption mode.'
        encrypted_bits = encrypt(args.image, args.filetohide, args.m[0], args.k[0])
        imagefile = args.image
        img = open_image(imagefile)
        img_hidden = stegano_hide(img, encrypted_bits)
        img_hidden.save(imagefile.name + '.sae.bmp', 'BMP')
        # img.save(imagefile.name + '.bmp', 'BMP')
    elif args.mode == 'd':
        # print 'Entering decryption mode.'
        payload = decrypt(args.image, args.m[0], args.k[0])
        print payload

if __name__ == "__main__":
    main()
