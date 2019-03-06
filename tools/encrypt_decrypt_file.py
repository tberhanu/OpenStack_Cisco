#!/usr/bin/python
"""
-------------------------- encrypt_decrypt_file.py --------------------------
Description: This python script can be used to encrypt or decrypt a file
             using a strong 32 bit key

Prerequisite: Initialize below ENV Variables -
              1. ENC_DEC_KEY

Note:
 Refer csb_credentials.py.enc_[prod|nonprod] for value against "ENC_DEC_KEY"

Usage:
1. for encrypting a file
python encrypt_decrypt_files.py -f <filename> -a enc -e [nonprod|prod]
2. for decrypting a file
python encrypt_decrypt_files.py -f <filename> -a dec

Author: Amardeep Kumar <amardkum@cisco.com>; March 06th, 2019

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------------
"""

import argparse
import os
import random
import struct

from Crypto.Cipher import AES

CHUNK_SIZE = 64*1024


def encrypt_file(key, in_filename):
    """
    Encrypts a file using AES (CBC mode) with the given key
    :param key: The encryption key
    :param in_filename:   Name of the input file
    :return: in_filename.enc
    """
    out_filename = in_filename + '.enc'
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))

    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))

def encrypt_file(key, in_filename, ext):
    """
    Encrypts a file using AES (CBC mode) with the given key
    :param key: The encryption key
    :param in_filename:   Name of the input file
    :param ext: extension
    :return: in_filename.enc
    """
    out_filename = in_filename + ext
    chunksize = 64*1024
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))

    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))



def decrypt_file(key, in_filename):
    """
    Decrypts a file using AES (CBC mode) with the given key.
    Parameters are similar to encrypt_file, with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    :param key: The encryption key
    :param in_filename:   Name of the input file
    :return: out_filename (in_filename without its last extension)
    """
    out_filename = os.path.splitext(in_filename)[0]
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Encrypt the file that holds confidential data')
    parser.add_argument("-f", "--filename", action="store", dest="filename",
                        help="Name of the file meant for encryption or decryption")
    parser.add_argument("-a", "--action", action="store", dest="action", help="Option to tell what needs to be done: encrypt(enc) or decrypt(dec)")
    parser.add_argument("-e", "--env_type", help="Environment Type(\"prod\" or \"nonprod\")", action="store", dest="env")

    args = parser.parse_args()
    filename = args.filename
    action = args.action

    if args.env and (args.env == "prod" or args.env == "nonprod"):
        env = args.env
        extension = ".enc_" + env
    else:
        print("INFO: Received ENV Type is not appropriate, hence going with default")
        extension = ".enc"

    key = os.environ["ENC_DEC_KEY"]

    if action == "enc":
        encrypt_file(key, filename, extension)
    elif action == "dec":
        decrypt_file(key, filename)
    else:
        print("ERROR: Invalid input. Please execute \"python encrypt_file -h\" to find right options and values")
