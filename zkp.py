try:
    from . import constants
except:
    import constants
import secrets

#idp - nym gen

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
    p_u = primary_cred_pub['p_u']

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
    # nested pow can probably be one with a negative exponent but idk if negative powers work in general or just for modular inverse
    y_4 = (y_1 * pow(g_1, (r - (1 << constants.ELL_DELTA) + 1), n)) * pow(pow(y_3, (1 << (constants.ELL_DELTA + 1)) - 1, n), -1, n) % n
    y_5 = pow(p_u, 2, n)

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
    p_u = primary_cred_pub['p_u']
    y_u = primary_cred_pub['y_u']

    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']
    
    p_d = pk_da['p_d']
    g_d = pk_da['g_d']

    y_1 = pow(p_u, 2, n)
    y_2 = y_u
    
    g_1 = pow(a, 2, n)
    g_2 = pow(b, 2, n)
    g_3 = pow(v, 2, n)

    h_1 = g_d

    return reparam_verify_zkp_nym_gen_3(y_1, y_2, g_1, g_2, g_3, h_1, n, p_d, zkp_ng3)


#idp - cred gen

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

def verify_zkp_cred_gen_1(cred_gen_msg_1, primary_cred, pk_idp):
    p_u = primary_cred['p_u']
    zkp_cg1 = cred_gen_msg_1['zkp_cg1']

    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']

    y_1 = pow(p_u, 2, n)
    
    g_1 = pow(a, 2, n)
    g_2 = pow(b, 2, n)
    g_3 = pow(v, 2, n)

    return reparam_verify_zkp_cred_gen_1(y_1, g_1, g_2, g_3, n, zkp_cg1)

#ca - verify cred

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

def verify_zkp_vf_cred_1(vc1_out, pk_idp, pk_da):
    w = vc1_out['deanon_str']['w']
    m = vc1_out['deanon_str']['m']
    A = vc1_out['A']
    zkp_vc1 = vc1_out['zkp_vc1']

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

# user - gen nym


# $$ PK\{(a_1, a_2, a_3, a_4): y_1 = g_1^{a_1}g_2^{a_2} \land g_2=g_1^{a_3}g_2^{a_4}\} $$
def reparam_zkp_nym_gen_1(y_1, y_2, g_1, g_2, a_1, a_2, a_3, a_4, n):
    r_1 = secrets.randbelow(n)
    r_2 = secrets.randbelow(n)
    r_3 = secrets.randbelow(n)
    r_4 = secrets.randbelow(n)

    t_1 = pow(g_1, r_1, n) * pow(g_2, r_2, n) % n
    t_2 = pow(g_1, r_3, n) * pow(g_2, r_4, n) % n

    c = constants.hash_str(g_1, g_2, y_1, y_2, t_1, t_2)

    s_1 = r_1 - c * a_1
    s_2 = r_2 - c * a_2
    s_3 = r_3 - c * a_3
    s_4 = r_4 - c * a_4
    
    s = {
        's_1': s_1, 
        's_2': s_2, 
        's_3': s_3, 
        's_4': s_4
    }
    t = {
        't_1': t_1,
        't_2': t_2
    }

    zkp = {
        'c': c,
        's': s,
        't': t
    }

    return zkp

def zkp_nym_gen_1(x_u, pub, priv , pk_idp):
    C_1 = pub['C_1']
    C_2 = pub['C_2']

    r_1 = priv['r_1']
    r_2 = priv['r_2']
    r_3 = priv['r_3']

    n = pk_idp['n']
    g = pk_idp['g']
    h = pk_idp['h']
    
    y_1 = pow(C_1, 2, n)
    y_2 = pow(C_2, 2, n)
    
    g_1 = pow(g, 2, n)
    g_2 = pow(h, 2, n)
    
    a_1 = r_1
    a_2 = r_2
    a_3 = x_u
    a_4 = r_3
    
    return reparam_zkp_nym_gen_1(y_1, y_2, g_1, g_2, a_1, a_2, a_3, a_4, n)


# $$ PK\{ TODO \} $$
def reparam_zkp_nym_gen_2(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, a_1, a_2, a_3, a_4, a_5, a_6, a_7, a_8, a_9, n):
    r_1 = secrets.randbelow(n)
    r_2 = secrets.randbelow(n)
    r_3 = secrets.randbelow(n)
    r_4 = secrets.randbelow(n)
    r_5 = secrets.randbelow(n)
    r_6 = secrets.randbelow(n)
    r_7 = secrets.randbelow(n)
    r_8 = secrets.randbelow(n)
    r_9 = secrets.randbelow(n)

    t_1 = pow(g_1, r_1, n) * pow(g_2, r_2, n) % n
    t_2 = pow(g_1, r_3, n) * pow(g_2, r_4, n) % n
    t_3 = pow(g_1, r_5, n) * pow(g_2, r_6, n) % n
    t_4 = pow(g_1, r_7, n) * pow(g_2, r_8, n) % n
    t_5 = pow(g_3, r_3, n) * pow(g_4, r_7, n) * pow(g_5, r_9, n) % n

    c = constants.hash_str(g_1, g_2, g_3, g_4, g_5, y_1, y_2, y_3, y_4, y_5, t_1, t_2, t_3, t_4, t_5)

    s_1 = r_1 - c * a_1
    s_2 = r_2 - c * a_2
    s_3 = r_3 - c * a_3
    s_4 = r_4 - c * a_4
    s_5 = r_5 - c * a_5
    s_6 = r_6 - c * a_6
    s_7 = r_7 - c * a_7
    s_8 = r_8 - c * a_8
    s_9 = r_9 - c * a_9
    
    s = {
        's_1': s_1, 
        's_2': s_2, 
        's_3': s_3, 
        's_4': s_4,
        's_5': s_5, 
        's_6': s_6, 
        's_7': s_7, 
        's_8': s_8, 
        's_9': s_9
    }
    t = {
        't_1': t_1,
        't_2': t_2,
        't_3': t_3,
        't_4': t_4,
        't_5': t_5
    }

    zkp = {
        'c': c,
        's': s,
        't': t
    }

    return zkp

def zkp_nym_gen_2(x_u, primary_cred, C, R, s_tilde, pk_idp):
    p_u = primary_cred['pub']['p_u']
    s_u = primary_cred['priv']['s_u']
    x_u_o = primary_cred['priv']['x_u_o']

    C_1 = C['C_1']
    C_2 = C['C_2']
    C_3 = C['C_3']

    r = R['r']
    r_1 = R['r_1']
    r_2 = R['r_2']
    r_3 = R['r_3']
    r_4 = R['r_4']

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
    y_4 = y_1 * pow(g_1, r - (1 << constants.ELL_DELTA) + 1, n) * pow(y_3, -((1 << (constants.ELL_DELTA + 1)) - 1), n) % n
    y_5 = pow(p_u, 2, n)
        
    a_1 = r_1
    a_2 = r_2
    a_3 = x_u
    a_4 = r_3
    a_5 = s_tilde
    a_6 = r_4
    a_7 = s_u
    a_8 = r_2 - r_4 * ((1 << (constants.ELL_DELTA + 1)) - 1)
    a_9 = x_u_o

    return reparam_zkp_nym_gen_2(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, a_1, a_2, a_3, a_4, a_5, a_6, a_7, a_8, a_9, n)



# $$ PK\{ (a_1, a_2, a_3) : y_1 = g_1^{a_1}g_2^{a_2}g_3^{a_3} \land y_2 = h ^ a_1 \land -2^{constants.ELL\_DELTA} < a_3 < -2^{constants.ELL\_DELTA} \} $$
def reparam_zkp_nym_gen_3(y_1, y_2, g_1, g_2, g_3, h_1, a_1, a_2, a_3, n, p_d):
    r_1 = secrets.randbelow(n)
    r_2 = secrets.randbelow(n)
    r_3 = secrets.randbelow(n)
    
    t_1 = pow(g_1, r_1, n) * pow(g_2, r_2, n) * pow(g_3, r_3, n) % n
    t_2 = pow(h_1, r_1, p_d)

    c = constants.hash_str(g_1, g_2, g_3, h_1, y_1, y_2, t_1, t_2)

    s_1 = r_1 - c * a_1
    s_2 = r_2 - c * a_2
    s_3 = r_3 - c * a_3

    s = {
        's_1': s_1, 
        's_2': s_2, 
        's_3': s_3
    }
    t = {
        't_1': t_1,
        't_2': t_2
    }

    zkp = {
        'c': c,
        's': s,
        't': t
    }

    return zkp

def zkp_nym_gen_3(x_u, primary_cred, pk_idp, pk_da):
    p_u = primary_cred['pub']['p_u']
    y_u = primary_cred['pub']['y_u']
    s_u = primary_cred['priv']['s_u']
    x_u_o = primary_cred['priv']['x_u_o']
    
    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']
    
    p_d = pk_da['p_d']
    g_d = pk_da['g_d']

    y_1 = pow(p_u, 2, n)
    y_2 = y_u
    
    g_1 = pow(a, 2, n)
    g_2 = pow(b, 2, n)
    g_3 = pow(v, 2, n)

    h_1 = g_d
    
    a_1 = x_u
    a_2 = s_u
    a_3 = x_u_o

    return reparam_zkp_nym_gen_3(y_1, y_2, g_1, g_2, g_3, h_1, a_1, a_2, a_3, n, p_d)


#user - cred gen

# $$ PK\{ (a_1, a_2, a_3) : y_1 = g_1^{a_1}g_2^{a_2}g_3^{a_3} \land -2^{constants.ELL\_DELTA} < a_3 < -2^{constants.ELL\_DELTA} \} $$
def reparam_zkp_cred_gen_1(y_1, g_1, g_2, g_3, a_1, a_2, a_3, n):
    r_1 = secrets.randbelow(n)
    r_2 = secrets.randbelow(n)
    r_3 = secrets.randbelow(n)


    t_1 = pow(g_1, r_1, n) * pow(g_2, r_2, n) * pow(g_3, r_3, n) % n

    c = constants.hash_str(g_1, g_2, g_3, y_1, t_1)

    s_1 = r_1 - c * a_1
    s_2 = r_2 - c * a_2
    s_3 = r_3 - c * a_3

    s = {
        's_1': s_1, 
        's_2': s_2, 
        's_3': s_3
    }
    t = {
        't_1': t_1
    }

    zkp = {
        'c': c,
        's': s,
        't': t
    }
    return zkp

def zkp_cred_gen_1(x_u, primary_cred, pk_idp):
    p_u = primary_cred['pub']['p_u']
    y_u = primary_cred['pub']['y_u']
    s_u = primary_cred['priv']['s_u']
    x_u_o = primary_cred['priv']['x_u_o']    

    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']

    y_1 = pow(p_u, 2, n)
    
    g_1 = pow(a, 2, n)
    g_2 = pow(b, 2, n)
    g_3 = pow(v, 2, n)

    a_1 = x_u
    a_2 = s_u
    a_3 = x_u_o

    return reparam_zkp_cred_gen_1(y_1, g_1, g_2, g_3, a_1, a_2, a_3, n)


#user - verify cred


# $$ PK\{ (a_1, a_2, a_3, a_4, a_5, a_6) : y_1 = g_1^{a_1}g_2^{a_2}g_3^{a_3}g_4^{a_4}g_5^{a_5} 
#       \land y_2 = h_1^{a_6} \land y_3 = h_2^{a_6} \land y_4 = h_1^{a_2}h_2^{a_6} \land y_5=h_3^{a_6}\} $$
def reparam_zkp_vf_cred_1(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, h_4, a_1, a_2, a_3, a_4, a_5, a_6, n, p_d):
    r_1 = secrets.randbelow(n)
    r_2 = secrets.randbelow(n)
    r_3 = secrets.randbelow(n)
    r_4 = secrets.randbelow(n)
    r_5 = secrets.randbelow(n)
    r_6 = secrets.randbelow(n)

    t_1 = pow(g_1, r_1, n) * pow(g_2, r_2, n) * pow(g_3, r_3, n) * pow(g_4, r_4, n) * pow(g_5, r_5, n) % n
    t_2 = pow(h_1, r_6, p_d)
    t_3 = pow(h_2, r_6, p_d)
    t_4 = pow(h_1, r_2, p_d) * pow(h_3, r_6, p_d) % p_d
    t_5 = pow(h_4, r_6, p_d)

    c = constants.hash_str(g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, h_4, y_1, y_2, y_3, y_4, y_5, t_1, t_2, t_3, t_4, t_5)

    s_1 = r_1 - c * a_1
    s_2 = r_2 - c * a_2
    s_3 = r_3 - c * a_3
    s_4 = r_4 - c * a_4
    s_5 = r_5 - c * a_5
    s_6 = r_6 - c * a_6

    s = {
        's_1': s_1, 
        's_2': s_2, 
        's_3': s_3,
        's_4': s_4, 
        's_5': s_5, 
        's_6': s_6
    }
    t = {
        't_1': t_1,
        't_2': t_2,
        't_3': t_3,
        't_4': t_4,
        't_5': t_5
    }

    zkp = {
        'c': c,
        's': s,
        't': t
    }

    return zkp

def zkp_vf_cred_1(x_u, primary_cred, sub_cred, w, A, m, r_1, r_2, pk_idp, pk_da):
    s_u = primary_cred['priv']['s_u']
    x_u_o = primary_cred['priv']['x_u_o']  

    e_u = sub_cred['e_u']

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

    c = constants.hash_str(w_1, w_2, w_3, m)
    
    h_1 = g_d
    h_2 = h_d
    h_3 = z_3
    h_4 = z_1 * pow(z_2, c, p_d) % p_d
    
    a_1 = e_u
    a_2 = x_u
    a_3 = s_u
    a_4 = x_u_o
    a_5 = r_1 * e_u
    a_6 = r_1

    return reparam_zkp_vf_cred_1(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, h_4, a_1, a_2, a_3, a_4, a_5, a_6, n, p_d)