import encrypt
import os
import sys
import os.path
import json
import base64
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as a_padding
from cryptography.hazmat.primitives import serialization

PUB_KEY_PATH = "/home/ubuntu/files/CECS378nodeserver/Public.pem"
PRI_KEY_PATH = "/home/ubuntu/files/CECS378nodeserver/Private.pem"
cwd = os.getcwd()

def RSAKeyGen(PRIVATE_PATH, PUBLIC_PATH):
    private_key = rsa.generate_private_key(
	#The public exponent of the new key. Usually one of the small Fermat primes 3, 5, 17, 257, 65537.
	#If in doubt you should use 65537.
	public_exponent = 65537,
	#strongly recommended to use 2048, must not be less than 512
	key_size = 2048,
	backend = default_backend()
    )

    #key serialization, private key
    private_pem = private_key.private_bytes(
	encoding = serialization.Encoding.PEM,
	format = serialization.PrivateFormat.TraditionalOpenSSL,
	encryption_algorithm = serialization.NoEncryption()
    )
    private_pem.splitlines()[0]

    public_key = private_key.public_key()

    #key serialization, public key
    public_pem = public_key.public_bytes(
	encoding = serialization.Encoding.PEM,
	format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_pem.splitlines()[0]

    pub_file = open(PUBLIC_PATH, 'wb')
    pub_file.write(public_pem)
    pub_file.close()

    pri_file = open(PRIVATE_PATH, 'wb')
    pri_file.write(private_pem)
    pri_file.close()

def RSAEncrypt(filepath, RSA_Publickey_filepath):
    C, IV, tag, key, HMACKey, ext = encrypt.MyfileEncryptMAC(filepath)

    #Key loading
    with open(RSA_Publickey_filepath, "rb") as public_key:
	public_key = serialization.load_pem_public_key(
	    public_key.read(),
	    backend=default_backend()
	)

    #Encryption of public key
    RSACipher = public_key.encrypt(
	key,
	a_padding.OAEP(
	    mgf=a_padding.MGF1(algorithm=hashes.SHA256()),
	    algorithm = hashes.SHA256(),
	    label = None
	)
    )

    return(RSACipher, C, IV, tag, ext)

def MyRSADecrypt(RSACipher, ciphertext, iv, tag, ext, RSA_PrivateKeyPath):

    with open(RSA_PrivateKeyPath, "rb") as key_file:
	private_key = serialization.load_pem_private_key(
	    key_file.read(),
	    password = None,
	    backend = default_backend()
	)

    key = private_key.decrypt(RSACipher,
            a_padding.OAEP(mgf=a_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
	)

    plaintext = encrypt.Mydecrypt(ciphertext, key, iv)

    dec_file = open("dec_rsa_file" + ext, "wb")
    dec_file.write(plaintext)
    dec_file.close()

def directoryEncrypt():
	for filename in os.listdir(cwd):
		rsaciph, ciph_text, rsaiv, rsatag, rsaext = RSAEncrypt(filename, PUB_KEY_PATH)
		json_dict = {
			'RSACipher': b64encode(rsaciph).decode('utf-8'),
			'C': b64encode(ciph_text).decode('utf-8'),
			'IV': b64encode(rsaiv).decode('utf-8'),
			'tag': b64encode(rsatag).decode('utf-8'),
			'ext': rsaext
		}
		new_filename = filename + ".json"
		with open(new_filename, 'wb') as f:
			json.dump(json_dict, f)
		#os.remove(filename)
	print("Directory encrypt done")

def main():
	RSAKeyGen(PRI_KEY_PATH, PUB_KEY_PATH)
	RSACipher, ciphertext, iv, tag, ext = RSAEncrypt("example.jpg", PUB_KEY_PATH)
	MyRSADecrypt (RSACipher, ciphertext, iv, tag, ext, PRI_KEY_PATH)

if __name__ == "__main__":
	main()
