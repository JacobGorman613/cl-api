import hashlib
import constants

def deanon_1(w, m, pk_da, sk_da):
    x_1 = sk_da['x_1']
    x_2 = sk_da['x_2']
    x_3 = sk_da['x_3']
    x_4 = sk_da['x_4']

    p_d = pk_da['p_d']

    w_1 = w['w_1']
    w_2 = w['w_2']
    w_3 = w['w_3']
    w_4 = w['w_4']

    h = hashlib.sha256()
    h.update(concat(w_1, w_2, w_3, m))
    H = h.digest()

    rhs = (w_1 ** (x_1 + x_3 * H)) * (w_2 ** (x_2 + x_4 * H)) % p_d

    return (w_4 == rhs)

def deanon_2(w_1, w_3, pk_da, sk_da):
    x_5 = sk_da['x_5']

    p_d = pk_da['p_d']
    
    y_hat = w_3 * pow(w_1, -1 * x_5, p_d)

    return y_hat