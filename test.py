from RSA import *
import sys

if __name__ == '__main__':
#    message = 'clues.txt'
    message = sys.argv[1]
    encoded = 'encoded.txt'
    N, E, D = gen_rsa_key()
#    N, E, D = 2051, 307, 331
    N, E, D = 493156847, 250476953, 362832041
#    N, E, D = 7197075931, 5591067089, 4146567473   # overflows
    print(N, E, D)
    encrypt(message, [int(N), int(E)])
    decrypt(encoded, [int(N), int(D)])