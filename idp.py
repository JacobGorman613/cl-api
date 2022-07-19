import constants
import secrets
import hashlib

#nym_gen

def nym_gen_2():
    r = secrets.randbits(ELL_DELTA + 1)
    N_2 = secrets.randbits(ELL_K)

    ng2_dict = {
        'r': r,
        'N_2': N_2
    }
    return ng2_dict

def reparam_verify_zkp_nym_gen_1(y_1, y_2, g_1, g_2, n, zkp_ng1):
    c = zkp_ng1['c']
    
    t = zkp_ng1['t']
    t_1 = t['t_1']
    t_2 = t['t_2']

    s = zkp_ng1['s']
    s_1 = s['s_1']
    s_2 = s['s_2']
    s_3 = s['s_3']
    s_4 = s['s_4']


    string = constants.concat(g_1, g_2, y_1, y_2, t_1, t_2)
    h = hashlib.sha256()
    h.update(string.encode())
    H = h.digest()

    #do cheapest check first, hash < big exponentiations (I think)

    c2 = 0
    for byte in H:
        c2 *= 256
        c2 += int(byte)
    
    if (c2 != c):
        return False

    T_1 = (pow(g_1, s_1, n) * pow(g_2, s_2, n) * pow(y_1, c, n)) % n
    if (T_1 != t_1):
        return False

    T_2 = (pow(g_1, s_3, n) * pow(g_2, s_4, n) * pow(y_2, c, n)) % n
    if (T_2 != t_2):
        return False

    return True

def verify_zkp_nym_gen_1(C_1, C_2, pk_idp, zkp_ng1):
    n = pk_idp['n']
    
    g = pk_idp['g']
    h = pk_idp['h']
    
    y_1 = pow(C_1, 2, n)
    y_2 = pow(C_2, 2, n)
    
    g_1 = pow(g, 2, n)
    g_2 = pow(h, 2, n)

    return reparam_verify_zkp_nym_gen_1(y_1, y_2, g_1, g_2, n, zkp_ng1)


def reparam_verify_zkp_nym_gen_2(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, n, zkp_ng2):
    c = zkp_ng2['c']
    
    t = zkp_ng2['t']
    t_1 = t['t_1']
    t_2 = t['t_2']
    t_3 = t['t_3']
    t_4 = t['t_4']
    t_5 = t['t_5']

    s = zkp_ng2['s']
    s_1 = s['s_1']
    s_2 = s['s_2']
    s_3 = s['s_3']
    s_4 = s['s_4']
    s_5 = s['s_5']
    s_6 = s['s_6']

    #do cheapest check first, hash < big exponentiations (I think)
    
    h = hashlib.sha256()
    h.update(concat(g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, y_1, y_2, y_3, y_4, y_5, t_1, t_2, t_3, t_4, t_5))
    H = h.digest()

    if (H != c):
        return False

    T_1 = ((g_1 ** s_1) * (g_2 ** s_2) * (y_1 ** c)) % n
    if (T_1 != t_1):
        return False

    T_2 = ((g_1 ** s_3) * (g_2 ** s_4) * (y_2 ** c)) % n
    if (T_2 != t_2):
        return False

    T_3 = ((g_1 ** s_5) * (g_2 ** s_6) * (y_3 ** c)) % n
    if (T_3 != t_3):
        return False

    T_4 = ((g_1 ** s_7) * (g_2 ** s_8) * (y_4 ** c)) % n
    if (T_4 != t_4):
        return False

    T_5 = ((g_3 ** s_3) * (g_4 ** s_7) * (g_5 ** s_9) * (y_5 ** c)) % n
    if (T_5 != t_5):
        return False

    return True

def verify_zkp_nym_gen_2(C_1, C_2, C_3, r, P_u, pk_idp, zkp_ng2):
    n = pk_idp['n']
    
    h = pk_idp['h']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']

    g_1 = (g ** 2) % n
    g_2 = (h ** 2) % n
    g_3 = (a ** 2) & n
    g_4 = (b ** 2) & n
    g_5 = (v ** 2) & n

    y_1 = (C_1 ** 2) % n
    y_2 = (C_2 ** 2) % n
    y_3 = (C_3 ** 2) % n
    y_4 = (y_1 * (g_1 ** (r - (2 << ELL_DELTA) + 1))) / (y_3 ** ((2 << (ELL_DELTA + 1)) - 1))
    y_5 = (P_u ** 2) % n

    return reparam_verify_zkp_nym_gen_2(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, n, zkp_ng2)

def reparam_verify_zkp_nym_gen_3(y_1, y_2, g_1, g_2, g_3, h, n, p_d, zkp_ng3):

    c = zkp_ng3['c']
    
    t = zkp_ng3['t']
    t_1 = t['t_1']
    t_2 = t['t_2']

    s = zkp_ng3['s']
    s_1 = s['s_1']
    s_2 = s['s_2']
    s_3 = s['s_3']

    h = hashlib.sha256()
    h.update(concat(g_1, g_2, g_3, h, y_1, y_2, t_1, t_2))
    H = h.digest()
    if (H != c):
        return False

    T_1 = ((g_1 ** s_1) * (g_2 ** s_2) * (g_3 ** s_3) * (y_1 ** c)) % n
    if (T_1 != t_1):
        return False

    T_2 = ((h_1 ** s_1) * (y_2 ** c)) % p_d
    if (T_2 != t_2):
        return False

    return True

def verify_zkp_nym_gen_3(P_u, Y_u, pk_idp, pk_da, zkp_ng3):
    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']
    
    p_d = pk_da['p_d']
    g_d = pk_da['g_d']

    y_1 = (P_u ** 2) % n
    y_2 = Y_u
    
    g_1 = (a ** 2) % n
    g_2 = (b ** 2) % n
    g_2 = (v ** 2) % n

    h = g_d

    return reparam_verify_zkp_nym_gen_3(y_1, y_2, g_1, g_2, g_3, h, n, p_d, zkp_ng3)

#cred_gen

def reparam_verify_zkp_cred_gen_1(y_1, g_1, g_2, g_3, n):
    c = zkp_cg1['c']
    
    t = zkp_cg1['t']
    t_1 = t['t_1']

    s = zkp_cg1['s']
    s_1 = s['s_1']
    s_2 = s['s_2']
    s_3 = s['s_3']

    h = hashlib.sha256()
    h.update(concat(g_1, g_2, g_3, y_1, t_1))
    H = h.digest()
    if (H != c):
        return False

    T_1 = ((g_1 ** s_1) * (g_2 ** s_2) * (g_3 ** s_3) * (y_1 ** c)) % n
    if (T_1 != t_1):
        return False

    return True

def verify_zkp_cred_gen_1(P_u, pk_idp, zkp_cg1):
    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']

    y_1 = (P_u ** 2) % n
    
    g_1 = (a ** 2) % n
    g_2 = (b ** 2) % n
    g_3 = (v ** 2) % n

    return reparam_verify_zkp_cred_gen_1(y_1, g_1, g_2, g_3, n, zkp_cg1)

def cred_gen_1(P_u, pk_idp):
    d = pk_idp['d']
    n = pk_idp['n']

    e_u = secrets.randbits(ELL_LAMBDA + 1)
    exp = pow(e_u, -1, n) #exp = 1 / e_u mod n

    c_u = ((p_u * d) ** exp) % n
    
    cg1_dict = {
        'e_u': e_u,
        'c_u': c_u
    }

    return cg1_dict