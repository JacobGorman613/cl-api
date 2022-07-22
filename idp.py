import constants
import secrets
import user
#nym_gen

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

    hash_str = constants.hash_str(g_1, g_2, y_1, y_2, t_1, t_2)

    if (hash_str != c):
        return False

    T_1 = pow(g_1, s_1, n) * pow(g_2, s_2, n) * pow(y_1, c, n) % n
    if T_1 != t_1:
        return False

    T_2 = pow(g_1, s_3, n) * pow(g_2, s_4, n) * pow(y_2, c, n) % n
    if T_2 != t_2:
        return False

    return True

def verify_zkp_nym_gen_1(nym_gen_msg_1, pk_idp):
    zkp_ng1 = nym_gen_msg_1['zkp_ng1']
    
    C_1 = nym_gen_msg_1['pub']['C_1']
    C_2 = nym_gen_msg_1['pub']['C_2']

    n = pk_idp['n']
    g = pk_idp['g']
    h = pk_idp['h']
    
    y_1 = pow(C_1, 2, n)
    y_2 = pow(C_2, 2, n)
    
    g_1 = pow(g, 2, n)
    g_2 = pow(h, 2, n)

    return reparam_verify_zkp_nym_gen_1(y_1, y_2, g_1, g_2, n, zkp_ng1)

# returns next message to send or empty dict if zkp fails
def nym_gen_2(nym_gen_msg_1, pk_idp):
    if not verify_zkp_nym_gen_1(nym_gen_msg_1, pk_idp):
        return {}
    r = constants.rand_in_range(constants.ELL_DELTA)
    N_2 = secrets.randbits(constants.ELL_K)

    ng2_out = {
        'r': r,
        'N_2': N_2
    }
    return ng2_out

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
    s_7 = s['s_7']
    s_8 = s['s_8']
    s_9 = s['s_9']

    #do cheapest check first, hash < big exponentiations (I think)
    hash_str = constants.hash_str(g_1, g_2, g_3, g_4, g_5, y_1, y_2, y_3, y_4, y_5, t_1, t_2, t_3, t_4, t_5)

    if hash_str != c:
        return False

    T_1 = pow(g_1, s_1, n) * pow(g_2, s_2, n) * pow(y_1, c, n) % n
    if T_1 != t_1:
        return False

    T_2 = pow(g_1, s_3, n) * pow(g_2, s_4, n) * pow(y_2, c, n) % n
    if T_2 != t_2:
        return False

    T_3 = pow(g_1, s_5, n) * pow(g_2, s_6, n) * pow(y_3, c, n) % n
    if T_3 != t_3:
        return False
#T_4 check fails
    T_4 = pow(g_1, s_7, n) * pow(g_2, s_8, n) * pow(y_4, c, n) % n
    if T_4 != t_4:
        return False

    T_5 = pow(g_3, s_3, n) * pow(g_4, s_7, n) * pow(g_5, s_9, n) * pow(y_5, c, n) % n
    if T_5 != t_5:
        return False

    return True

def verify_zkp_nym_gen_2(primary_cred_pub, C_1, C_2, C_3, r, pk_idp, zkp_ng2):
    P_u = primary_cred_pub['P_u']

    n = pk_idp['n']
    
    g = pk_idp['g']
    h = pk_idp['h']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']

    g_1 = pow(g, 2, n)
    g_2 = pow(h, 2, n)
    g_3 = pow(a, 2, n)
    g_4 = pow(b, 2, n)
    g_5 = pow(v, 2, n)

    y_1 = pow(C_1, 2, n)
    y_2 = pow(C_2, 2, n)
    y_3 = pow(C_3, 2, n)
    #nested pow can probably be one with a negative exponent but idk if negative powers work in general or just for modular inverse
    y_4 = (y_1 * pow(g_1, (r - (1 << constants.ELL_DELTA) + 1), n)) * pow(pow(y_3, (1 << (constants.ELL_DELTA + 1)) - 1, n), -1, n) % n
    y_5 = pow(P_u, 2, n)

    return reparam_verify_zkp_nym_gen_2(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, n, zkp_ng2)

def reparam_verify_zkp_nym_gen_3(y_1, y_2, g_1, g_2, g_3, h_1, n, p_d, zkp_ng3):
    c = zkp_ng3['c']
    
    t = zkp_ng3['t']
    t_1 = t['t_1']
    t_2 = t['t_2']

    s = zkp_ng3['s']
    s_1 = s['s_1']
    s_2 = s['s_2']
    s_3 = s['s_3']

    hash_str = constants.hash_str(g_1, g_2, g_3, h_1, y_1, y_2, t_1, t_2)

    if hash_str != c:
        return False

    T_1 = pow(g_1, s_1, n) * pow(g_2, s_2, n) * pow(g_3, s_3, n) * pow(y_1, c, n) % n
    if T_1 != t_1:
        return False

    T_2 = pow(h_1, s_1, p_d) * pow(y_2, c, p_d) % p_d
    if T_2 != t_2:
        return False

    return True

def verify_zkp_nym_gen_3(primary_cred_pub, pk_idp, pk_da, zkp_ng3):
    P_u = primary_cred_pub['P_u']
    Y_u = primary_cred_pub['Y_u']

    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']
    
    p_d = pk_da['p_d']
    g_d = pk_da['g_d']

    y_1 = pow(P_u, 2, n)
    y_2 = Y_u
    
    g_1 = pow(a, 2, n)
    g_2 = pow(b, 2, n)
    g_3 = pow(v, 2, n)

    h_1 = g_d

    return reparam_verify_zkp_nym_gen_3(y_1, y_2, g_1, g_2, g_3, h_1, n, p_d, zkp_ng3)

def nym_gen_4(nym_gen_msg_1, nym_gen_msg_2, nym_gen_msg_3, pk_idp, pk_da):
    primary_cred_pub = nym_gen_msg_3['pub']

    N_1 = nym_gen_msg_1['pub']['N_1']
    N_2 = nym_gen_msg_2['N_2']
    nym = constants.concat(N_1, N_2)

    if (nym != primary_cred_pub['nym']):
        print("nym misformed")
        return False

    r = nym_gen_msg_2['r']

    C_1 = nym_gen_msg_1['pub']['C_1']
    C_2 = nym_gen_msg_1['pub']['C_2']
    C_3 = nym_gen_msg_3['C']['C_3']

    zkp_ng2 = nym_gen_msg_3['zkp_ng2']
    zkp_ng3 = nym_gen_msg_3['zkp_ng3']

    vf_ng2 = verify_zkp_nym_gen_2(primary_cred_pub, C_1, C_2, C_3 , r, pk_idp, zkp_ng2)
    vf_ng3 = verify_zkp_nym_gen_3(primary_cred_pub, pk_idp, pk_da, zkp_ng3)
    return vf_ng2 and vf_ng3
#cred_gen

def reparam_verify_zkp_cred_gen_1(y_1, g_1, g_2, g_3, n, zkp_cg1):
    c = zkp_cg1['c']
    
    t = zkp_cg1['t']
    t_1 = t['t_1']

    s = zkp_cg1['s']
    s_1 = s['s_1']
    s_2 = s['s_2']
    s_3 = s['s_3']

    #do cheapest check first, hash < big exponentiations (I think)
    hash_str = constants.hash_str(g_1, g_2, g_3, y_1, t_1)

    if (hash_str != c):
        return False

    T_1 = pow(g_1, s_1, n) * pow(g_2, s_2, n) * pow(g_3, s_3, n) * pow(y_1, c, n) % n
    if T_1 != t_1:
        return False

    return True

def verify_zkp_cred_gen_1(cred_gen_msg_1, pk_idp):
    P_u = cred_gen_msg_1['pub']['P_u']
    zkp_cg1 = cred_gen_msg_1['zkp_cg1']

    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']

    y_1 = pow(P_u, 2, n)
    
    g_1 = pow(a, 2, n)
    g_2 = pow(b, 2, n)
    g_3 = pow(v, 2, n)

    return reparam_verify_zkp_cred_gen_1(y_1, g_1, g_2, g_3, n, zkp_cg1)

def cred_gen_2(cred_gen_msg_1, pk_idp, sk_idp):
    if not verify_zkp_cred_gen_1(cred_gen_msg_1, pk_idp):
        return {}

    P_u = cred_gen_msg_1['pub']['P_u']

    d = pk_idp['d']
    n = pk_idp['n']

    p = sk_idp['p']
    q = sk_idp['q']

    p_prime = (p - 1) >> 1
    q_prime = (q - 1) >> 1

    e_u = constants.rand_in_range(constants.ELL_LAMBDA)
    #exp = 1 / e_u mod ord(QR_n) 
    exp = pow(e_u, -1, p_prime * q_prime) 

    c_u = pow(P_u * d, exp, n)
    
    sub_cred = {
        'e_u': e_u,
        'c_u': c_u
    }

    return sub_cred