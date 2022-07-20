import secrets
import os
from os.path import exists
import json
from Crypto.Util.number import isPrime

ELL_GAMMA = 128
ELL_N = 256 #2048
ELL_DELTA = 128
ELL_LAMBDA = 128
ELL_K = 128
EPSILON = 2

PK_IDP_PATH = "pk_idp.json"
PK_DA_PATH = "pk_da.json"

#returns a random number in (-2^ELL_X, 2^ELL_X)
def rand_in_range(ELL_X):
    x = secrets.randbits(ELL_X)
    if secrets.randbits(1):
        x *= -1
    return x


def concat(*argv):
    string = ""

    for arg in argv:
        string += str(arg)

    return string

def clear_keys():
    if exists(PK_IDP_PATH):
        os.remove(PK_IDP_PATH)
    if exists(PK_DA_PATH):
        os.remove(PK_DA_PATH)


def rand_safe_prime(length):
    p = secrets.randbits(length)

    #bitshift instead of divide by 2 to maintain int typing
    while not (isPrime(p) and isPrime((p - 1) >> 1)):
        p = secrets.randbits(length)

    return p

def init_idp_key():
    #bitshift instead of divide by 2 to maintain int typing
    p = rand_safe_prime(ELL_N >> 1) 
    q = rand_safe_prime(ELL_N >> 1)

    n = p * q

    a_prime = secrets.randbelow(n)
    b_prime = secrets.randbelow(n)
    c_prime = secrets.randbelow(n)
    d_prime = secrets.randbelow(n)
    g_prime = secrets.randbelow(n)
    h_prime = secrets.randbelow(n)
    v_prime = secrets.randbelow(n)


    sk_idp = {
        'p': p,
        'q': q
    }

    #do we need to check that none of these are the same?
    #probably not, statistically impossible?
    pk_idp = {
        'a':pow(a_prime, 2, n),
        'b':pow(b_prime, 2, n),
        'c':pow(c_prime, 2, n),
        'd':pow(d_prime, 2, n),
        'g':pow(g_prime, 2, n),
        'h':pow(h_prime, 2, n),
        'v':pow(v_prime, 2, n),
        'n':n
    }

    return (pk_idp, sk_idp)


def publish_pk_idp(pk_idp):
    with open(PK_IDP_PATH, 'w') as file:
        json.dump(pk_idp, file)
        file.close()

def import_pk_idp():
    while(not exists(PK_IDP_PATH)):
        continue
    with open(PK_IDP_PATH, 'r') as file:
        pk_idp = json.load(file)
        file.close()
        return pk_idp

    return {}

def init_da_key():
    #https://crypto.stackexchange.com/questions/22716/generation-of-a-cyclic-group-of-prime-order
    #on generating group of order q_d (use z^*_{p_d}) where q_d | p_d - 1

    #q_d > 2^ELL_DELTA
    q_d = secrets.randbits(ELL_DELTA + 1)
    p_d = 1
    fac = 0
    while(not isPrime(p_d)):
        while ((not isPrime(q_d)) and (q_d < (2 << ELL_DELTA))):
            q_d = secrets.randbits(ELL_DELTA + 1)
        for i in range(2, 1001, 2):
            p_d = i * q_d + 1
            if isPrime(p_d):
                fac = i
                break


    g = 1
    while (g == 1):
        temp = secrets.randbelow(p_d)
        g = pow(temp, fac, p_d)

    h = 1
    while (h == 1):
        temp = secrets.randbelow(p_d)
        h = pow(temp, fac, p_d)

    x_1 = secrets.randbelow(q_d)
    x_2 = secrets.randbelow(q_d)
    x_3 = secrets.randbelow(q_d)
    x_4 = secrets.randbelow(q_d)
    x_5 = secrets.randbelow(q_d)

    y_1 = (pow(g, x_1, p_d) * pow(h, x_2, p_d)) % p_d
    y_2 = (pow(g, x_3, p_d) * pow(h, x_4, p_d)) % p_d
    y_3 = pow(g, x_5, p_d)

    sk_da = {
        'x_1':x_1,
        'x_2':x_2,
        'x_3':x_3,
        'x_4':x_4,
        'x_5':x_5
    }

    pk_da = {
        'y_1': y_1,
        'y_2': y_2,
        'y_3': y_3,
        'g_d': g,
        'h_d': h,
        'p_d': p_d
    }
    return (pk_da, sk_da)

def publish_pk_da(pk_da):
    #pk_da_json = json.dumps(pk_da, indent = 4)
    #f = open(PK_DA_PATH, "w")
    #f.write(pk_da_json)
    #f.close()
    
    with open(PK_DA_PATH, 'w') as file:
        json.dump(pk_da, file)
        file.close()

def import_pk_da():
    while(not exists(PK_DA_PATH)):
        continue
    with open(PK_DA_PATH, 'r') as file:
        pk_da = json.load(file)
        file.close()
        return pk_da

    return {}

def init_user_key():
    #return secrets.randbits(ELL_GAMMA + 1) #x_u in GAMMA = (-2^ELL_GAMMA, 2^ELL_GAMMA)
    x_u = secrets.randbits(ELL_GAMMA)
    if secrets.randbits(1):
        x_u *= -1
    return x_u