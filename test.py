from RSA import *

if __name__ == '__main__':
    message = 'clues.txt'
    encoded = 'encoded.txt'
    N, E, D = gen_rsa_key()
#    N, E, D = 2051, 307, 331
    print(N, E, D)
    encrypt(message, [int(N), int(E)])
    decrypt(encoded, [int(N), int(D)])