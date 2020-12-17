#!/usr/bin/python3
'''
The purpose of this assignment is to sign a '.cast' file using a priv_key. Then use the pub_key to verify it. 
No bash tool allowed.

We have three other files which are 'key_gen', 'sign_vrfy' and 'enc_dec'.

'''
import optparse
from Cryptodome.PublicKey import RSA, ECC
import key_gen
import sign_vrfy
import enc_dec


def main():
    #print("hello")
    parser = optparse.OptionParser('usage %prog ' +\
        '\n\033[0;35;1mGenerate Keys:\033[0m ./OpenSSL.py [--rsa][--ecc]' +\
            '\n\n\033[0;36;1mSign file:\033[0m ./OpenSSL.py -i <input file> --priv <private key> -s <signature>' +\
                '\n\n\033[0;36;1mVerify signature:\033[0m ./OpenSSL.py -i <input file> --pub <public key> -s <signature>' +\
                    '\n\n\033[0;33;1mEncrypt(rsa):\033[0m ./OpenSSL.py -i <input file> --pub <public key> -o <output file(encrypted)>' +\
                        '\n\n\033[0;33;1mDecrypt(rsa):\033[0m ./OpenSSL.py -i <input file(encrypted)> --priv <private key> -o <output key(decrypted)>')
    # first thing first, we must have a function to generate keys. --rsa --ecc
    parser.add_option('--rsa', action='store_true', dest='gen_rsa', \
        help='generate rsa keys')
    parser.add_option('--ecc', action='store_true', dest='gen_ecc', \
        help='generate ecc keys')
    # next, we have -i for input, -o for output, --pub for public key, --priv for private key, -s for signature
    parser.add_option('-i', '--input', type='string', dest='input', \
        help='input some file')
    parser.add_option('-o', '--output', type='string', dest='output', \
        help='output some file')
    parser.add_option('--pub', type='string', dest='pub_key', \
        help='put public key here')
    parser.add_option('--priv', type='string', dest='priv_key', \
        help='put private key here')
    parser.add_option('-s', '--sign', type='string', dest='sign_file', \
        help='import signature')

    (options, args) = parser.parse_args()
    gen_rsa = options.gen_rsa
    gen_ecc = options.gen_ecc
    file_input = options.input
    file_output = options.output
    pub_key = options.pub_key
    priv_key = options.priv_key
    sign_file = options.sign_file
    
    #keygen part
    if (gen_rsa == True):
        key_gen.gen_rsa()
    elif (gen_ecc == True):
        key_gen.gen_ecc()
    else:
    
        #sign and verify part
        if (file_input == None):
            print(parser.usage)
            exit(0)
        elif (sign_file != None):
            if (priv_key != None):
                #sign a file
                sign_vrfy.sign(file_input, priv_key, sign_file)
            elif (pub_key != None):
                #verify it
                sign_vrfy.vrfy(file_input, pub_key, sign_file)
        elif (file_output != None):
            if (priv_key != None):
                #decrypt
                enc_dec.decrypt(file_input, priv_key, file_output)
            elif (pub_key != None):
                #encrypt
                enc_dec.encrypt(file_input, pub_key, file_output)


if __name__ == '__main__':
    main()
