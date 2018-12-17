import os
import sys
import os.path
import json
import hashlib
import hmac
import base64
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac


def Myencrypt(message, key):
	#Check the size of the key
	if(sys.getsizeof(key) < 32):
		print("The key  must be 32 bytes.")
		return


	#Generate random 16-byte IV
	IV = os.urandom(16)

	#CBC padding before encryption
	padder = padding.PKCS7(128).padder()
	padded_data = padder.update(message) + padder.finalize()
	backend = default_backend()

	#Encrypt using AES and CBC mode
	cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend = backend)
	encryptor = cipher.encryptor()

	#Generate ciphertext
	c_t = encryptor.update(padded_data) + encryptor.finalize()

	#print("Encryption complete.")
	return c_t, IV
def MyfileEncrypt(filepath):
	#Generate 32-byte key
	key = os.urandom(32)

	#Open the file to be encrypted
	file = open(filepath, 'rb')
	ext = os.path.splitext(filepath)[1]
	#Read data from file
	bin = file.read()
	bin = b64encode(bin)
	file.close()

	#Create ciphertext from file using Myencrypt
	c_t, IV = Myencrypt(bin, key)

	#Create new file, write the ciphertext to it
	#e_file = open("e_file", 'w')
	#e_file.write(c_t)
	#e_file.close()

	#print("Encyption to file completed.")
	return c_t, IV, key, ext

def Mydecrypt(c_t, key, iv):
    if len(key) != 32:
        print("The key must be 32 bytes in length.")
        return ()

    decryptor = Cipher( algorithms.AES(key), modes.CBC(iv), default_backend()).decryptor()

    # Decrypt the plaintext and get the associated ciphertext.
    plaintext = decryptor.update(c_t) + decryptor.finalize()

    return plaintext

def MyfileDecrypt(filepath, key, iv, ext):
	#open the file that will be decrypted
	file = open(filepath, 'rb')
	#read data
	bin = file.read()
	file.close()

	plaintext = Mydecrypt(bin, key, iv)
	plaintext = b64decode(plaintext)

	dec_file = open("dec_file" + ext, "wb")
	dec_file.write(plaintext)
	dec_file.close()

	print("Decryption completed") 

def saveFileAsJSON (filename, iv, key, c_t, ext):

    data = {
        'IV': iv,
        'Key': key,
        'Text': c_t,
        'Extension': ext
        }

    with open(filename, 'w') as outFile:
        json.dump(data, outFile)
    outFile.close()

def MyencryptMAC(message, EncKey, HMACKey):

	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
	h.update(c_t)
	h.finalize()
	return c_t, IV

def MyfileEncryptMAC(filepath):
	HMACKey = os.urandom(32)
	c_t, IV, EncKey, ext = MyfileEncrypt(filepath)
	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
	h.update(c_t)
	tag = h.finalize()
	return c_t, IV, tag, EncKey, HMACKey, ext

def MyfileDecryptMAC(filepath, c_t, IV, tag, EncKey, HMACKey, ext):
	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
	h.update(c_t)
	h.verify(tag)
	MyfileDecrypt("./e_file", EncKey, IV, ext)

#c_t, iv, key = MyfileEncrypt("/home/ubuntu/files/CECS378nodeserver/plaintext")
#saveFileAsJSON("plaintext.txt", iv, key, c_t,".txt")
#MyfileDecrypt("/home/ubuntu/files/CECS378nodeserver/e_file", key, iv)

#c_t, IV, key, ext = MyfileEncrypt("/home/ubuntu/files/CECS378nodeserver/example.jpg")
#MyfileDecrypt("/home/ubuntu/files/CECS378nodeserver/e_file", key, IV, ext)

#c_t, IV, tag, EncKey, HMACKey, ext = MyfileEncryptMAC("./example.jpg")
#MyfileDecryptMAC("./e_file", c_t, IV, tag, EncKey, HMACKey, ext)
