import math
import secrets
import constants

#nym_gen

def nym_gen_1(x_u, pk_idp):    
    g = pk_idp['g']
    h = pk_idp['h']
    n = pk_idp['n']

    N_1 = secrets.randbits(constants.ELL_K)
    r_1 = constants.rand_in_range(constants.ELL_DELTA)
    r_2 = secrets.randbits(2 * constants.ELL_N)
    r_3 = secrets.randbits(2 * constants.ELL_N)

    C_1 = pow(g, r_1, n) * pow(h, r_2, n) % n
    C_2 = pow(g, x_u, n) * pow(h, r_3, n) % n

    out_dict = {
        'N_1':N_1,
        'r_1':r_1,
        'r_2':r_2,
        'r_3':r_3,
        'C_1':C_1,
        'C_2':C_2
    }

    return out_dict

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

def zkp_nym_gen_1(C_1, C_2, r_1, r_2, r_3, x_u, pk_idp):
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
    
def nym_gen_3(r_1, r, x_u, pk_idp):
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']
    g = pk_idp['g']
    h = pk_idp['h']
    n = pk_idp['n']

    x_u_o = constants.rand_in_range(constants.ELL_GAMMA)
    r_4 = secrets.randbits(constants.ELL_N)
    
    s_u = (((r_1 + r) % (1 << (constants.ELL_DELTA + 1)) - 1)) - (1 << constants.ELL_DELTA) + 1
    s_tilde = math.floor((r_1 + r) / ((1 << (constants.ELL_DELTA + 1)) - 1))

    # not sure why this happens but it shouldn't be possible for this check to fail. 
    # I think we are somehow miscalculating s_u because changing any other value even a little throws the equality waaay off
    check = (r_1 + r - (1 << constants.ELL_DELTA) + 1) - s_tilde * ((1 << (constants.ELL_DELTA + 1)) - 1)
    if not check == s_u:
        s_u += 1
    
    P_u = pow(a, x_u, n) * pow(b, s_u, n) * pow(v, x_u_o, n) % n
    C_3 = pow(g, s_tilde, n) * pow(h, r_4, n) % n

    out_dict = {
        's_u':s_u,
        'P_u':P_u,
        'x_u':x_u,
        'x_u_o':x_u_o,
        'r_4':r_4,
        'C_3':C_3,
        's_tilde':s_tilde
    }

    return out_dict

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

def zkp_nym_gen_2(C_1, C_2, C_3, R, P_u, x_u, x_u_o, s_u, s_tilde, pk_idp):
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
    #nested pow can probably be one with a negative exponent but idk if negative powers work in general or just for modular inverse
    y_4 = y_1 * pow(g_1, r - (1 << constants.ELL_DELTA) + 1, n) * pow(y_3, -((1 << (constants.ELL_DELTA + 1)) - 1), n) % n
    y_5 = pow(P_u, 2, n)
        
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

def nym_gen_4(x_u, pk_da):
    g_d = pk_da['g_d']
    p_d = pk_da['p_d']

    Y_u = pow(g_d, x_u, p_d)

    out_dict = {'Y_u':Y_u}

    return out_dict

# $$ PK\{ (a_1, a_2, a_3) : y_1 = g_1^{a_1}g_2^{a_2}g_3^{a_3} \land y_2 = h ^ a_1 \land -2^{constants.ELL\_DELTA} < a_3 < -2^{constants.ELL\_DELTA} \} $$
def reparam_zkp_nym_gen_3(y_1, y_2, g_1, g_2, g_3, h_1, a_1, a_2, a_3, n, p_d):
    r_1 = secrets.randbelow(n)
    r_2 = secrets.randbelow(n)
    r_3 = secrets.randbelow(n)

    #Ord(QRn) == p'q', so order of each element guaranteed to be big
    
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

def zkp_nym_gen_3(P_u, Y_u, x_u, x_u_o, s_u, pk_idp, pk_da):
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
    
    a_1 = x_u
    a_2 = s_u
    a_3 = x_u_o

    return reparam_zkp_nym_gen_3(y_1, y_2, g_1, g_2, g_3, h_1, a_1, a_2, a_3, n, p_d)

#cred_gen

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

def zkp_cred_gen_1(P_u, x_u, x_u_o, s_u, pk_idp):
    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']

    y_1 = pow(P_u, 2, n)
    
    g_1 = pow(a, 2, n)
    g_2 = pow(b, 2, n)
    g_3 = pow(v, 2, n)

    a_1 = x_u
    a_2 = s_u
    a_3 = x_u_o

    return reparam_zkp_cred_gen_1(y_1, g_1, g_2, g_3, a_1, a_2, a_3, n)

def cred_gen_2(e_u, c_u, P_u, pk_idp):
    d = pk_idp['d']
    n = pk_idp['n']

    lhs = pow(c_u, e_u, n)
    rhs = (P_u * d) % n

    return lhs == rhs

#verify_cred

def verify_cred_1(c_u, Y_u, m, pk_idp, pk_da):
    h = pk_idp['h']
    n = pk_idp['n']

    g_d = pk_da['g_d']
    h_d = pk_da['h_d']
    p_d = pk_da['p_d']
    z_1 = pk_da['z_1']
    z_2 = pk_da['z_2']
    z_3 = pk_da['z_3']

    r_1 = secrets.randbits(2 * constants.ELL_N)
    r_2 = secrets.randbelow(n)

    w_1 = pow(g_d, r_1, p_d)
    w_2 = pow(h_d, r_1, p_d)
    w_3 = pow(z_3, r_1, p_d) * Y_u % p_d

    c = constants.hash_str(w_1, w_2, w_3, m)

    w_4 = pow(z_1, r_1, p_d) * pow(z_2, r_1 * c, p_d) % p_d

    A = c_u * pow(h, r_1, n) % n

    out_dict = {
        'r_1':r_1,
        'r_2':r_2,
        'w_1':w_1,
        'w_2':w_2,
        'w_3':w_3,
        'w_4':w_4,
        'A': A
    }

    return out_dict

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

def zkp_vf_cred_1(w, A, m, r_1, r_2, e_u, x_u, x_u_o, s_u, pk_idp, pk_da):
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