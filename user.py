import math
import secrets
import hashlib

#nym_gen

nym_gen_1(x_u, pk_idp):    
    g = pk_idp['g']
    h = pk_idp['h']
    n = pk_idp['n']

    N_1 = secrets.randbits(ELL_K)
    r_1 = secrets.randbits(ELL_DELTA + 1)
    r_2 = secrets.randbits(2 * ELL_N)
    r_3 = secrets.randbits(2 * ELL_N)

    C_1 = ((g ** r_1) * (h ** r_2)) % n
    C_2 = ((g ** x_u) * (h ** r_3)) % n

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
reparam_zkp_cred_gen_1(y_1, y_2, g_1, g_2, a_1, a_2, a_3, a_4, n):
    r_1 = secrets.randbelow(n)
    r_2 = secrets.randbelow(n)
    r_3 = secrets.randbelow(n)
    r_4 = secrets.randbelow(n)

    #Ord(QRn) == p'q', so order of each element guaranteed to be big

    t_1 = ((g_1 ** r_1) * (g_2 ** r_2)) % n
    t_2 = ((g_1 ** r_3) * (g_2 ** r_4)) % n

    h = hashlib.sha256()
    h.update(concat(g_1, g_2, y_1, y_2, t_1, t_2))
    c = h.digest()

    s_1 = r_1 - c * a_1 # might need a modulus but idts
    s_2 = r_2 - c * a_2 # might need a modulus but idts
    s_3 = r_3 - c * a_3 # might need a modulus but idts
    s_4 = r_4 - c * a_4 # might need a modulus but idts
    
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

zkp_nym_gen_1(C_1, C_2, r_1, r_2, r_3, x_u, pk_idp):
    n = pk_idp['n']
    g = pk_idp['g']
    h = pk_idp['h']
    
    y_1 = (C_1 ** 2) % n
    y_2 = (C_1 ** 2) & n
    
    g_1 = (g ** 2) % n
    g_2 = (h ** 2) % n
    
    a_1 = r_1
    a_2 = r_2
    a_3 = x_u
    a_4 = r_3
    
    return reparam_zkp_cred_gen_1(y_1, y_2, g_1, g_2, a_1, a_2, a_3, a_4, n)
    
nym_gen_3(r_1, r, x_u, pk_idp):
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']
    n = pk_idp['n']

    x_u_o = secrets.randbits(ELL_GAMMA + 1)
    r_4 = secrets.randbits(ELL_N)
    
    s_u = (((r_1 + r) % (2 << (ELL_DELTA + 1)) - 1)) - (2 << ELL_DELTA) + 1
    P_u = (a ** x_u) * (b ** s_u) #mod n
    s_tilde = math.floor((r_1 + r) / ((2 << (ELL_DELTA + 1)) - 1))
    C_3 = ((g ** s_tilde) * (h ** r_4)) % n

    out_dict = {
        's_u':s_u,
        'P_u':P_u,
        'x_u':x_u,
        'r_4':r_4,
        'C_3':C_3,
        's_tilde':s_tilde
    }

    return out_dict

# $$ PK\{ TODO \} $$
reparam_zkp_cred_gen_2(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, a_1, a_2, a_3, a_4, a_5, a_6, a_7, a_8, a_9, n):
    r_1 = secrets.randbelow(n)
    r_2 = secrets.randbelow(n)
    r_3 = secrets.randbelow(n)
    r_4 = secrets.randbelow(n)
    r_5 = secrets.randbelow(n)
    r_6 = secrets.randbelow(n)
    r_7 = secrets.randbelow(n)
    r_8 = secrets.randbelow(n)
    r_9 = secrets.randbelow(n)

    #Ord(QRn) == p'q', so order of each element guaranteed to be big

    t_1 = ((g_1 ** r_1) * (g_2 ** r_2)) % n
    t_2 = ((g_1 ** r_3) * (g_2 ** r_4)) % n
    t_3 = ((g_1 ** r_5) * (g_2 ** r_6)) % n
    t_4 = ((g_1 ** r_7) * (g_2 ** r_8)) % n
    t_5 = ((g_3 ** r_3) * (g_4 ** r_7) * (g_5 ** r_9)) % n

    h = hashlib.sha256()
    h.update(concat(g_1, g_2, g_3, g_4, g_5, y_1, y_2, y_3, y_4, y_5, t_1, t_2, t_3, t_4, t_5))
    c = h.digest()

    s_1 = r_1 - c * a_1 # might need a modulus but idts
    s_2 = r_2 - c * a_2 # might need a modulus but idts
    s_3 = r_3 - c * a_3 # might need a modulus but idts
    s_4 = r_4 - c * a_4 # might need a modulus but idts
    s_5 = r_5 - c * a_5 # might need a modulus but idts
    s_6 = r_6 - c * a_6 # might need a modulus but idts
    s_7 = r_7 - c * a_7 # might need a modulus but idts
    s_8 = r_8 - c * a_8 # might need a modulus but idts
    s_9 = r_9 - c * a_9 # might need a modulus but idts
    
    s = {
        's_1': s_1, 
        's_2': s_2, 
        's_3': s_3, 
        's_4': s_4
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

zkp_nym_gen_2(C_1, C_2, C_3, R, P_u, x_u, x_u_o, s_u, s_tilde, pk_idp):
    r = R['r']
    r_1 = R['r_1']
    r_2 = R['r_2']
    r_3 = R['r_3']
    r_4 = R['r_4']

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
        
    a_1 = r_1
    a_2 = r_2
    a_3 = x_u
    a_4 = r_3
    a_5 = s_tilde
    a_6 = r_4
    a_7 = s_u
    a_8 = r_2 - r_4 * ((2 << (ELL_DELTA + 1)) - 1)
    a_9 = x_u_o

    return reparam_zkp_cred_gen_2(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, a_1, a_2, a_3, a_4, a_5, a_6, a_7, a_8, a_9, n):

nym_gen_4(x_u, pk_da):
    #ng4_dict = json.loads(json_string)
    #x_u = ng4_dict['x_u']
    #pk_da = ng4_dict['pk_da']
    g_d = pk_da['g_d']
    p_d = pk_da['p_d']

    Y_u = (g_d ** x_u) % p_d

    return Y_u

# $$ PK\{ (a_1, a_2, a_3) : y_1 = g_1^{a_1}g_2^{a_2}g_3^{a_3} \land y_2 = h ^ a_1 \land -2^{ELL\_DELTA} < a_3 < -2^{ELL\_DELTA} \} $$
reparam_zkp_nym_gen_3(y_1, y_2, g_1, g_2, g_3, h, a_1, a_2, a_3, n, p_d):
    r_1 = secrets.randbelow(n)
    r_2 = secrets.randbelow(n)
    r_3 = secrets.randbelow(n)

    #Ord(QRn) == p'q', so order of each element guaranteed to be big
    #NEED TO INCORPORATE P AND/OR Q

    t_1 = ((g_1 ** r_1) * (g_2 ** r_2) * (g_3 ** r_3)) % n
    t_2 = (h ** r_1) % p_d

    h = hashlib.sha256()
    h.update(concat(g_1, g_2, g_3, h, y_1, y_2, t_1, t_2))
    c = h.digest()

    s_1 = r_1 - c * a_1 # might need a modulus but idts
    s_2 = r_2 - c * a_2 # might need a modulus but idts
    s_3 = r_3 - c * a_3 # might need a modulus but idts

    s = {
        's_1': s_1, 
        's_2': s_2, 
        's_3': s_3, 
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

zkp_nym_gen_3(P_u, Y_u, x_u, x_u_o, s_u, pk_idp, pk_da):
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
    
    a_1 = x_u
    a_2 = s_u
    a_3 = x_u_o

    return reparam_zkp_nym_gen_3(y_1, y_2, g_1, g_2, g_3, h, a_1, a_2, a_3, n, p_d):

#cred_gen

# $$ PK\{ (a_1, a_2, a_3) : y_1 = g_1^{a_1}g_2^{a_2}g_3^{a_3} \land -2^{ELL\_DELTA} < a_3 < -2^{ELL\_DELTA} \} $$
reparam_zkp_cred_gen_1(y_1, y_2, g_1, g_2, g_3, a_1, a_2, a_3, n):
    r_1 = secrets.randbelow(n)
    r_2 = secrets.randbelow(n)
    r_3 = secrets.randbelow(n)

    #Ord(QRn) == p'q', so order of each element guaranteed to be big

    t_1 = ((g_1 ** r_1) * (g_2 ** r_2) * (g_3 ** r_3)) % n

    h = hashlib.sha256()
    h.update(concat(g_1, g_2, g_3, y_1, t_1))
    c = h.digest()

    s_1 = r_1 - c * a_1 # might need a modulus but idts
    s_2 = r_2 - c * a_2 # might need a modulus but idts
    s_3 = r_3 - c * a_3 # might need a modulus but idts

    s = {
        's_1': s_1, 
        's_2': s_2, 
        's_3': s_3
    }
    t = {
        't_1': t_1
    }

    zkp = {
        'c': c
        's': s
        't': t
    }

    return zkp

zkp_cred_gen_1(P_u, x_u, x_u_o, s_u, pk_idp):
    n = pk_idp['n']
    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']

    y_1 = (P_u ** 2) % n
    
    g_1 = (a ** 2) % n
    g_2 = (b ** 2) % n
    g_3 = (v ** 2) % n

    a_1 = x_u
    a_2 = s_u
    a_3 = x_u_o

    return reparam_zkp_cred_gen_1(y_1, y_2, g_1, g_2, g_3, a_1, a_2, a_3, n),

cred_gen_2(e_u, c_u, P_u, pk_idp):
    d = pk_idp['d']
    n = pk_idp['n']

    lhs = (c_u ** e_u) % n
    rhs = (P_u * d) % n

    return (lhs == rhs)

#verify_cred

verify_cred_1(c_u, Y_u, m, pk_idp, pk_da):
    h = pk_idp['h']
    n = pk_idp['n']

    g_d = pk_da['g_d']
    h_d = pk_da['h_d']
    p_d = pk_da['p_d']
    y_1 = pk_da['y_1']
    y_2 = pk_da['y_2']
    y_3 = pk_da['y_3']

    r_1 = secrets.randbits(2 * ELL_N)
    r_2 = secrets.randbelow(n)



    w_1 = (g_d ** r_2) % p_d
    w_2 = (h_d ** r_2) % p_d
    w_3 = ((y_3 ** r_2) * Y_u) % p_d


    h = hashlib.sha256()
    #should be concat
    h.update(w_1 * w_2 * w_3 * m)
    w_4 = ((y_1 ** r_2) * (y_2 ** (r_2 * h.digest()))) % p_d

    A = c_u * (h ** r_1) #mod n?

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
reparam_zkp_vf_cred_1(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, a_1, a_2, a_3, a_4, a_5, a_6, n, p_d):
    r_1 = secrets.randbelow(n)
    r_2 = secrets.randbelow(n)
    r_3 = secrets.randbelow(n)
    r_4 = secrets.randbelow(n)
    r_5 = secrets.randbelow(n)
    r_6 = secrets.randbelow(n)

    #Ord(QRn) == p'q', so order of each element guaranteed to be big

    t_1 = ((g_1 ** r_1) * (g_2 ** r_2) * (g_3 ** r_3) * (g_4 ** r_4) * (g_5 ** r_5)) % n
    t_2 = (h_1 ** a_6) % p_d
    t_3 = (h_2 ** a_6) % p_d
    t_4 = ((h_1 ** a_2) * (h_2 ** a_6)) % p_d
    t_5 = (h_3 ** a_6) % p_d

    h = hashlib.sha256()
    h.update(concat(g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, y_1, y_2, y_3, y_4, y_5, t_1, t_2, t_3, t_4, t_5))
    c = h.digest()

    s_1 = r_1 - c * a_1 # might need a modulus but idts
    s_2 = r_2 - c * a_2 # might need a modulus but idts
    s_3 = r_3 - c * a_3 # might need a modulus but idts
    s_4 = r_4 - c * a_4 # might need a modulus but idts
    s_5 = r_5 - c * a_5 # might need a modulus but idts
    s_6 = r_6 - c * a_6 # might need a modulus but idts

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

zkp_vf_cred_1(w, A, m, r_1, r_2, e_u, x_u, x_u_o, s_u, pk_idp, pk_da):
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

    #here we don't use normal h name because h is taken
    h256 = hashlib.sha256()
    h256.update(concat(w_1, w_2, w_3, m))
    H = h256.digest()

    h_1 = g_d
    h_2 = h_d
    h_3 = (y_1 * (y_2 ** H))
    
    a_1 = e_u
    a_2 = x_u
    a_3 = s_u
    a_4 = r_1
    a_5 = r_2
    a_6 = x_u_o

    return reparam_zkp_vf_cred_1(y_1, y_2, y_3, y_4, y_5, g_1, g_2, g_3, g_4, g_5, h_1, h_2, h_3, a_1, a_2, a_3, a_4, a_5, a_6, n, p_d)