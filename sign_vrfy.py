'''
This script has function to sign and verify.

'''
from Cryptodome.Hash import SHA1,SHA256,SHA3_256,SHA3_512
from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.PublicKey import RSA, ECC
import os

def sign(file_input, priv_key, sign_file):
    #sign it
    with open(file_input, "rb") as f:
        f.read()
        print("[SHA1 SHA256 SHA3_256 SHA3_512]")
        hash_method = input("hash method:")
        if (hash_method == "SHA1"):
            hash_file = SHA1.new(f.read())
        elif (hash_method == "SHA256"):
            hash_file = SHA256.new(f.read())
        elif (hash_method == "SHA3_256"):
            hash_file = SHA3_256.new(f.read())
        elif (hash_method == "SHA3_512"):
            hash_file = SHA3_512.new(f.read())
        else:
            print("sorry...we don't support that hash method now")
    
    try:
        privateKey = RSA.import_key(open(priv_key, "rb").read())
        sign = pkcs1_15.new(privateKey).sign(hash_file)
    except (ValueError, TypeError):
        privateKey = ECC.import_key(open(priv_key, 'rt').read())
        sign = DSS.new(privateKey, 'fips-186-3').sign(hash_file)

    with open(sign_file, "wb") as f:
        f.write(sign)
    

def vrfy(file_input, pub_key, sign_file):
    #verify it
    
    with open(file_input, "rb") as f:
        f.read()
        print("[SHA1 SHA256 SHA3_256 SHA3_512]")
        hash_method = input("hash method:")
        if (hash_method == "SHA1"):
            hash_file = SHA1.new(f.read())
        elif (hash_method == "SHA256"):
            hash_file = SHA256.new(f.read())
        elif (hash_method == "SHA3_256"):
            hash_file = SHA3_256.new(f.read())
        elif (hash_method == "SHA3_512"):
            hash_file = SHA3_512.new(f.read())
        else:
            print("sorry...we don't support that hash method now")
    #hash_file = hash(file, 'SHA256')
    with open(sign_file, 'rb') as f:
        signature = f.read()
    #print(hash_file)
    #print(signature)
  
    try:
        publicKey = RSA.import_key(open(pub_key, "rb").read())
        try:
            pkcs1_15.new(publicKey).verify(hash_file,signature)
            print('\033[0;32;1m'"Yes, the signature is valid."'\033[m')
        except (ValueError, TypeError):
            print('\033[0;31;1m'"No, the signature is NOT valid."'\033[m')
    except (ValueError, TypeError):
        publicKey = ECC.import_key(open(pub_key, 'rt').read())
        verifier = DSS.new(publicKey, 'fips-186-3')
        try:
            verifier.verify(hash_file, signature)
            print('\033[0;32;1m'"Yes, the signature is valid."'\033[m')
        except (ValueError, TypeError):
            print('\033[0;31;1m'"No, the signature is NOT valid."'\033[m')




