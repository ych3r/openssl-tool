'''
This script is for encrypt and decrypt
'''
import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

def encrypt(file_input, pub_key, file_output):
    #print("this is encrypt function")
    with open(file_input, "rb") as f:
        file2encrypt = f.read()
    #print("Plain text:\n" + str(file2encrypt))
    publicKey = RSA.import_key(open(pub_key, "rb").read())
    cipher = PKCS1_OAEP.new(publicKey)
    encryptedFile = base64.b64encode(cipher.encrypt(file2encrypt))
    #print("Encrypted text:\n" + str(encryptedFile))
    with open(file_output, "wb") as f:
        f.write(encryptedFile)
    print("Encrypted text saved into file: " + str(file_output))

def decrypt(file_input, priv_key, file_output):
    #print("this is decrypt function")
    with open(file_input, "r") as f:
        file2decrypt = f.read()
    #print("Encrypted text:\n" + str(file2decrypt))
    privateKey = RSA.import_key(open(priv_key, "rb").read())
    cipher = PKCS1_OAEP.new(privateKey)
    decryptedFile = cipher.decrypt(base64.b64decode(file2decrypt))
    #print("Decrypted text:\n" + str(decryptedFile.decode('utf-8')))
    with open(file_output, "w") as f:
        f.write(decryptedFile.decode('utf-8'))
    print("Decrypted text saved into file: " + str(file_output))