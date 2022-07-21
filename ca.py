import constants

def reparam_verify_zkp_vf_cred_1(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, h_4, n, p_d, zkp_vc1):
    c = zkp_vc1['c']
    
    t = zkp_vc1['t']
    t_1 = t['t_1']
    t_2 = t['t_2']
    t_3 = t['t_3']
    t_4 = t['t_4']
    t_5 = t['t_5']

    s = zkp_vc1['s']
    s_1 = s['s_1']
    s_2 = s['s_2']
    s_3 = s['s_3']
    s_4 = s['s_4']
    s_5 = s['s_5']
    s_6 = s['s_6']

    #do cheapest check first, hash < big exponentiations (I think)
    hash_str = constants.hash_str(g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, h_4, y_1, y_2, y_3, y_4, y_5, t_1, t_2, t_3, t_4, t_5)

    if hash_str != c:
        return False

    T_1 = pow(g_1, s_1, n) * pow(g_2, s_2, n) * pow(g_3, s_3, n) * pow(g_4, s_4, n) * pow(g_5, s_5, n) * pow(y_1, c, n) % n
    if T_1 != t_1:
        return False

    T_2 = pow(h_1, s_6, p_d) * pow(y_2, c, p_d) % p_d
    if T_2 != t_2:
        return False

    T_3 = pow(h_2, s_6, p_d) * pow(y_3, c, p_d) % p_d
    if T_3 != t_3:
        return False

    T_4 = pow(h_1, s_2, p_d) * pow(h_3, s_6, p_d) * pow(y_4, c, p_d) % p_d
    if T_4 != t_4:
        return False

    T_5 = pow(h_4, s_6, p_d) * pow(y_5, c, p_d) % p_d
    if T_5 != t_5:
        return False

    return True

def verify_zkp_vf_cred_1(w, A, m, zkp_vc1, pk_idp, pk_da):
    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']
    h = pk_idp['h']
    d = pk_idp['d']

    z_1 = pk_da['z_1']
    z_2 = pk_da['z_2']
    z_3 = pk_da['z_3']
    p_d = pk_da['p_d']
    g_d = pk_da['g_d']
    h_d = pk_da['h_d']

    w_1 = w['w_1']
    w_2 = w['w_2']
    w_3 = w['w_3']
    w_4 = w['w_4']

    #use z instead of y this time because y is part of DA public key. probably change that to z later instead
    y_1 = pow(d, 2, n)
    y_2 = w_1
    y_3 = w_2
    y_4 = w_3
    y_5 = w_4
    
    g_1 = pow(A, 2, n)
    g_2 = pow(a, -2, n)
    g_3 = pow(b, -2, n)
    g_4 = pow(v, -2, n)
    g_5 = pow(h, -2, n)

    hash_str = constants.hash_str(w_1, w_2, w_3, m)

    h_1 = g_d
    h_2 = h_d
    h_3 = z_3
    h_4 = z_1 * pow(z_2, hash_str, p_d) % p_d

    return reparam_verify_zkp_vf_cred_1(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, h_4, n, p_d, zkp_vc1)