import secrets
import os
from os.path import exists
import json
from Crypto.Util.number import isPrime

ELL_GAMMA = 10
ELL_N = 256 #2048
ELL_DELTA = 10
ELL_LAMBDA = 10
ELL_K = 10
EPSILON = 2

PK_IDP_PATH = "pk_idp.json"
PK_DA_PATH = "pk_da.json"

def concat(*argv):
    string = ""

    for arg in argv:
        string += str(arg)

    return string

def clear_keys():
    os.remove(PK_IDP_PATH)
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
    sk_da = {
        'x_1':7,
        'x_2':8,
        'x_3':9,
        'x_4':10,
        'x_5':11
    }
    pk_da = {
        'y_1': 1,
        'y_2': 2,
        'y_3': 3,
        'g_d': 4,
        'h_d': 5,
        'p_d': 6
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
    return secrets.randbits(ELL_GAMMA + 1) #x_u in GAMMA = (-2^ELL_GAMMA, 2^ELL_GAMMA)
