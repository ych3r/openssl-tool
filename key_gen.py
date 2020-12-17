'''
This script includes rsa and ecc public key schemes.

'''
from Cryptodome.PublicKey import RSA,ECC

def gen_rsa():
    rsa_key = RSA.generate(2048)
    #print("for private key") 
    with open("rsa_priv_key.pem", "wb") as f:
        f.write(rsa_key.export_key(format='PEM'))
    #print("for public key")
    with open("rsa_pub_key.pem", "wb") as f:
        f.write(rsa_key.publickey().export_key(format='PEM'))
    print("Generated **RSA** public key and private key SUCCESSFULLY!")
    return 0

def gen_ecc():
    ecc_key = ECC.generate(curve='P-256')
    #print("for private key")
    with open("ecc_priv_key.pem", "wt") as f:
        f.write(ecc_key.export_key(format='PEM'))
    #print("for public key")
    with open("ecc_pub_key.pem", "wt") as f:
        f.write(ecc_key.public_key().export_key(format='PEM')) 
    print("Generated **ECC** public key and private key SUCCESSFULLY!")

#gen_rsa()
#gen_ecc()