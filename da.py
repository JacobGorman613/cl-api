import constants

def deanon(deanon_str, pk_da, sk_da):
    m = deanon_str['m']
    w = deanon_str['w']
    w_1 = w['w_1']
    w_2 = w['w_2']
    w_3 = w['w_3']
    w_4 = w['w_4']

    x_1 = sk_da['x_1']
    x_2 = sk_da['x_2']
    x_3 = sk_da['x_3']
    x_4 = sk_da['x_4']
    x_5 = sk_da['x_5']

    p_d = pk_da['p_d']

    hash_str = constants.hash_str(w_1, w_2, w_3, m)

    rhs = pow(w_1, (x_1 + x_3 * hash_str), p_d) * pow(w_2, (x_2 + x_4 * hash_str), p_d) % p_d

    y_hat = -1

    if w_4 == rhs:
        y_hat = w_3 * pow(w_1, -x_5, p_d) % p_d


    return y_hat