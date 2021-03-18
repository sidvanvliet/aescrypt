"""
AESCrypt v1.0.0

By S. van Vliet (HU University of Applied Sciences) @ https://github.com/sidvanvliet/aescrypt
AES-128 implementation by https://github.com/boppreh/aes
"""

import aes
import os
import sys

key: bytes
iv: bytes
file_path: str = 'file.dat'
file_output_path: str = 'file.dat'


# Preparation for encryption/decryption (globally defines the keys)
def prepare():
    global key, iv, file_path, file_output_path

    f_must_exist = ['iv.key', 'aes.key']

    # Cancel the preparation if one or more files are missing
    for file in f_must_exist:
        if os.path.exists(file) == 0:
            sys.exit('Error: One or more key files is/are missing. Create keys using the --create parameter.')

    with open('aes.key', 'rb') as key:
        key = key.read()

    with open('iv.key', 'rb') as iv:
        iv = iv.read()

    file_path = sys.argv[2]

    if len(sys.argv) > 3:
        file_output_path = sys.argv[3]


# Creates a private key + iv key
def create_keys():
    # Create aes.key (private key) and write as binary
    new_key = os.urandom(16)
    new_key_file = open('aes.key', 'wb')
    new_key_file.write(new_key)

    print('Created private key (aes.key)..')

    # Create iv.key (IV key) and write as binary
    new_iv = os.urandom(16)
    new_iv_file = open('iv.key', 'wb')
    new_iv_file.write(new_iv)

    print('Created initialization vector (iv.key)..')
    print('Done.')


def encrypt():
    print(f'Encrypting {file_path}')

    # Read file as binary and encrypt the bytes to file_output_path
    with open(file_path, 'rb') as file:
        content = aes.AES(key).encrypt_ctr(file.read(), iv)

        print(f'Writing encrypted bytes to {file_output_path}')
        file_dump = open(file_output_path, 'wb')
        file_dump.write(content)

        sys.exit('Done.')


def decrypt():
    print(f'Decrypting {file_path}')

    # Read file as binary and decrypt the bytes to file_output_path
    with open(file_path, 'rb') as file:
        content = aes.AES(key).decrypt_ctr(file.read(), iv)

        print(f'Writing decrypted bytes to {file_output_path}')
        file_dump = open(file_output_path, 'wb')
        file_dump.write(content)

        sys.exit('Done.')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--help':
        print('Basic usage: python aescrypt.py --encrypt <path>\n')
        print('  --create                              Creates key files')
        print('  --encrypt <path> <output (optional)>  Encrypt a file')
        print('  --decrypt <path> <output (optional)>  Decrypt a file')

    elif len(sys.argv) > 1 and sys.argv[1] == '--create':
        create_keys()

    elif len(sys.argv) > 1 and sys.argv[1] == '--encrypt':
        prepare()
        encrypt()

    elif len(sys.argv) > 1 and sys.argv[1] == '--decrypt':
        prepare()
        decrypt()

    else:
        print('Invalid usage. For help, try python aescrypt.py --help')
