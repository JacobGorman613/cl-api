import hashlib
import constants

reparam_verify_zkp_vf_cred_1(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, n, p_d, zkp_vc1):
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
    
    h = hashlib.sha256()
    h.update(concat(g_1, g_2, g_3, g_4, g_5, y_1, y_2, y_3, y_4, y_5, t_1, t_2, t_3, t_4, t_5))
    H = h.digest()
    if (H != c):
        return False

    T_1 = ((g_1 ** s_1) * (g_2 ** s_2) * (g_3 ** s_3) * (g_4 ** s_4) * (g_5 ** s_5) * (y_1 ** c)) % n
    if (T_1 != t_1):
        return False

    T_2 = ((h_1 ** s_6) * (y_2 ** c)) % p_d
    if (T_2 != t_2):
        return False

    T_3 = ((h_2 ** s_6) * (y_3 ** c)) % p_d
    if (T_3 != t_3):
        return False

    T_4 = ((h_1 ** s_2) * (h_2 ** s_6) * (y_4 ** c)) % p_d
    if (T_4 != t_4):
        return False

    T_5 = ((h_3 ** s_6) * (y_5 ** c)) % p_d
    if (T_5 != t_5):
        return False

    return True

verify_zkp_vf_cred_1(w, A, m, zkp_vc1, pk_idp, pk_da):
    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']
    h = pk_idp['h']
    d = pk_idp['d']

    y_1 = pk_da['y_1']
    y_2 = pk_da['y_2']
    y_3 = pk_da['y_3']
    p_d = pk_da['p_d']
    g_d = pk_da['g_d']
    h_d = pk_da['h_d']

    w_1 = w['w_1']
    w_2 = w['w_2']
    w_3 = w['w_3']
    w_4 = w['w_4']

    y_1 = (d ** 2) % n
    y_2 = w_1
    y_3 = w_2
    y_4 = w_3
    y_5 = w_4
    
    #TODO DEFINE MOD_INV
    g_1 = (A ** 2) % n
    g_2 = (pow(a, -1, n) ** 2) % n #can just do pow -2. might also be faster to do pow for all the others
    g_2 = (pow(b, -1, n) ** 2) % n #can just do pow -2. might also be faster to do pow for all the others
    g_4 = (pow(v, -1, n) ** 2) % n #can just do pow -2. might also be faster to do pow for all the others
    g_5 = (pow(h, -1, n) ** 2) % n #can just do pow -2. might also be faster to do pow for all the others


    #here don't use normal h name because we use h earlier
    h256 = hashlib.sha256()
    h256.update(concat(w_1, w_2, w_3, m))
    H = h256.digest()

    h_1 = g_d
    h_2 = h_d
    h_3 = (y_1 * (y_2 ** H))

	return reparam_verify_zkp_vf_cred_1(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, n, p_d, zkp_vc1)