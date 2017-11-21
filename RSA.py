# RSA Encryption/Decryption
# Jiashu Han
import numpy as np, random as r

# encryption procedure
def encrypt(path, key):
    message = load_file(path)
    m_code = convert(message)
    c_code = rsa(key, m_code)
    print(c_code)
    c_code_str = " ".join(c_code.astype(str))   #######
    save_file(c_code_str, 'encoded.txt')
    print('saved as encoded.txt in the working directory.')

# decryption procedure
def decrypt(path, key):
    c_code = load_encrypted_file(path)
    m_code = rsa(key, c_code)
    m_code1 = m_code.astype(int)
    message = convert(m_code1, code=True)
    print(message)
    save_file(message, 'decoded.txt')
    print('saved as decoded.txt in the working directory.')

# loads the message from file
def load_file(path):
    f = open(path, 'r')
    lines = []
    for line in f:
        lines.append(line)
    f.close()
    delim = ' '
    words = delim.join(lines)
    characters = list(words)
    return characters

# loads the encrypted code from file
def load_encrypted_file(path):
    f = open(path, 'r')
    codes = []
    delim = ' '
    for line in f:
        codes.extend(line.split(delim))
    f.close()
    codes = np.array(codes)
    return codes.astype(float).astype(int)

# converts letters and symbols to numbers; code must be an integer array; cannot use '?', this is problematic
def convert(text_or_code, code=False):
    codebook = ['a','A','b','B','c','C','d','D','e','E','f','F','g','G','h','H','i','I','j','J','k','K','l','L','m','M','n','N','o','O','p','P','q','Q','r','R','s','S','t','T','u','U','v','V','w','W','x','X','y','Y','z','Z',' ',',','.',';',':','!','"',"'",'(',')','[',']','-','0','1','2','3','4','5','6','7','8','9', '\n'] # the characters can be in any order
    if not code: # converts text to code
        code = []
        for i in range(len(text_or_code)):
            for j in range(len(codebook)):
                if text_or_code[i] == codebook[j]:
                    code.append(j)
        return code
    else: # converts code to text
        text_or_code = np.array(text_or_code)
        text = []
        code1 = text_or_code.astype(int)
        for i in range(len(code1)):
            for j in range(len(codebook)):
                if j == code1[i]:
                    text.append(codebook[j])
        delim = ''
        return delim.join(text)

# returns the first n primes
def primes(n):
    i = 2
    result = []
    while n > 0:
        isPrime = True
        for j in range(2, i):
            if i % j == 0:
                isPrime = False
                break
        if isPrime:
            result.append(i)
            n -= 1
        i += 1
    return result

# generates a set of keys for the RSA encryption algorithm
def gen_rsa_key():
    n = -1
    while n < 0:
        k1 = int(r.uniform(0, 1000)) #the components of the key have to be greater than 75
        k2 = int(r.uniform(0, 1000))
        k3 = int(r.uniform(0, 1000))
        p = (primes(k1))[k1-1]
        q = (primes(k2))[k2-1]
        e = (primes(k3))[k3-1]
        n = p*q
    k = 1
    while (k*(p-1)*(q-1)+1) % e != 0:
        k += 1
    d = (k*(p-1)*(q-1)+1)/e
    print('N = %d,     E = %d,     D = %d'%(n, e, d))
    return (n, e, d)

# encrypts or decrypts code using the RSA algorithm with provided keys
def rsa(key, code):
    n = int(key[0])
    e_d = int(key[1])
    code = np.array(code).astype(int)
    new_code_array = np.array([])
############################################
# this is the same as:
#     new_code = (code**e_d) % n --> overflows
############################################
    for i in range(len(code)):
        S = e_d
        k = 0                        # this helps keep track on how many steps it has taken
        B = code[i]
        array_A = []
        array_B = [B]
        while S > 10:   # everything below is used to prevent the numbers from getting too big
            R = S % 10
            S = (S-R)/10              # code^e_d = code^R*code^10S
            if B > 75:
                M1 = B**2 % n         #B^2
                M2 = M1**2 % n        #B^4
                M3 = M2**2 % n        #B^8
                M4 = (M1*M2) % n      #B^6
                casesR = {
                    0: 1, 
                    1: B % n, 
                    2: M1 % n, 
                    3: (B*M1) % n, 
                    4: M2 % n, 
                    5: (B*M2) % n, 
                    6: (M1*M2) % n, 
                    7: (B*M4) % n, 
                    8: M3 % n, 
                    9: (B*M3) % n
                }
                A = casesR.get(R)
            else:
                A = B**R % n          # or A = (array_B[k])^R mod n
            if B > 75:   # B^10 may be > 1.8E19
                M1 = B**2 % n
                M2 = M1**2 % n
                M3 = M2**2 % n
                B = (M1*M3) % n
            else:
                B = B**10 % n         # or B = (array_B[k])^10 mod n. this is at most 74
            array_A.append(A)
            array_B.append(B)
            k+=1    # pmax/qmax/emax=541,nmax=30537,dmax=291061-->max steps taken=5
        # below is equivalent to C = int(product(array_A))
        C = array_A[0]               # based on calculation, x^e_d MOD n=(A1*A2*...*Ak*Bk^Sk) MOD n
        for j in range(len(array_A)-1):
            C = (C*(array_A[j+1])) % n
        if array_B[k] > 75:
            M1 = (array_B[k])**2 % n # array_B[k]^2
            M2 = M1**2 % n           # array_B[k]^4
            M3 = M2**2 % n           # array_B[k]^8
            M4 = (M1*M2) % n         # array_B[k]^6
            casesS = {
                0: 1, 
                1: array_B[k] % n, 
                2: M1 % n, 
                3: (B*M1) % n, 
                4: M2 % n, 
                5: ((array_B[k])*M2) % n, 
                6: (M1*M2) % n, 
                7: ((array_B[k])*M4) % n, 
                8: M3 % n, 
                9: ((array_B[k])*M3) % n
            }
            D = casesS.get(S)
        else:
            D = (array_B[k])**S
        new_code = ((C % n)*(D % n)) % n
        new_code_array = np.append(new_code_array, new_code)
    return new_code_array.astype(int)

# saves the result into another .txt file
def save_file(message, filename):
    f = open(filename, 'w')
    f.writelines(message)
    f.close()

# in case of negative dividend
def neg_mod(dividend, divisor):
    if dividend < 0:
        result = dividend
        while result < 0:
            result += divisor
    return result

if __name__ == '__main__':
    while True:
        print("NOTE: This program supports 76 characters (not including '?').")
        task = input('To encrypt, enter 1; to decrypt, enter 2; to get a key, enter 3:\n>> ')
        if task == '1': # encryption
            hasKey = input('Do you have a key? Y/N:\n>> ')
            if hasKey == 'n':
                gen_rsa_key()
            path = input('Please enter the path of the file:\n>> ')
            N = input('Please enter N (N>75):\n>> ') # this is to ensure the transformation from characters to codes is bijective
            E = input('Please enter E:\n>> ')
            keys = [int(N), int(E)]
            encrypt(path, keys)
        if task == '2':   # Calls the decryption procedure
            path = input('Please enter the path of the file:\n>> ')
            N = input('Please enter N (N>75):\n>> ')
            D = input('Please enter D:\n>> ')
            keys = [int(N), int(D)]
            decrypt(path, keys)
        if task == '3':
            gen_rsa_key()
