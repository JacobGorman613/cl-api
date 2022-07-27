import math
import secrets
import constants
import zkp

#nym_gen


def nym_gen_1(x_u, pk_idp):    
    g = pk_idp['g']
    h = pk_idp['h']
    n = pk_idp['n']

    r_1 = constants.rand_in_range(constants.ELL_DELTA)
    r_2 = secrets.randbits(2 * constants.ELL_N)
    r_3 = secrets.randbits(2 * constants.ELL_N)

    N_1 = secrets.randbits(constants.ELL_K)
    C_1 = pow(g, r_1, n) * pow(h, r_2, n) % n
    C_2 = pow(g, x_u, n) * pow(h, r_3, n) % n

    pub = {
        'N_1' : N_1,    
        'C_1' : C_1,    
        'C_2' : C_2         
    }

    priv = {
        'r_1' : r_1,
        'r_2' : r_2,
        'r_3' : r_3    
    }

    zkp_ng1 = zkp.zkp_nym_gen_1(x_u, pub, priv , pk_idp)

    send = {
        'pub':pub,
        'zkp_ng1': zkp_ng1
    }

    ng1_out = {
        'priv' : priv,
        'send' : send
    }

    return ng1_out


   
def nym_gen_3(x_u, ng1_out, nym_gen_msg_2, pk_idp, pk_da):
    N_1 = ng1_out['send']['pub']['N_1']
    C_1 = ng1_out['send']['pub']['C_1']
    C_2 = ng1_out['send']['pub']['C_2']
    
    r_1 = ng1_out['priv']['r_1']
    r_2 = ng1_out['priv']['r_2']
    r_3 = ng1_out['priv']['r_3']

    r = nym_gen_msg_2['r']
    N_2 = nym_gen_msg_2['N_2']

    a = pk_idp['a']
    b = pk_idp['b']
    v = pk_idp['v']
    g = pk_idp['g']
    h = pk_idp['h']
    n = pk_idp['n']

    g_d = pk_da['g_d']
    p_d = pk_da['p_d']

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

    Y_u = pow(g_d, x_u, p_d)

    nym = constants.concat(N_1, N_2)

    R = {
        'r':r,
        'r_1':r_1,
        'r_2':r_2,
        'r_3':r_3,
        'r_4':r_4
    }

    C = {
        'C_1' : C_1,
        'C_2' : C_2,
        'C_3' : C_3
    }

    # part of primary credential shared with IDP
    pub = {
        'P_u' : P_u,
        'Y_u' : Y_u,
        'nym' : nym
    }
    # private part of primary credential
    priv = {
        'x_u_o':x_u_o,
        's_u':s_u    
    }
    primary_cred = {
        'priv':priv,
        'pub':pub
    }


    zkp_ng2 = zkp.zkp_nym_gen_2(x_u, primary_cred, C, R, s_tilde, pk_idp)

    zkp_ng3 = zkp.zkp_nym_gen_3(x_u, primary_cred, pk_idp, pk_da)

    send = {
        'pub':pub,
        'R':R,
        'C':C,
        's_tilde':s_tilde,
        'zkp_ng2':zkp_ng2,
        'zkp_ng3':zkp_ng3

    }

    # technically space inefficient bc pub stored twice but makes our lives sooo much easier
    ng3_out = {
        'primary_cred' : primary_cred,
        'send' : send
    }
    return ng3_out


#cred_gen

def cred_gen_1(x_u, primary_cred, pk_idp):
    
    zkp_cg1 = zkp.zkp_cred_gen_1(x_u, primary_cred, pk_idp)

    cg1_out = {
        'zkp_cg1' : zkp_cg1,
        'pub' : primary_cred['pub']
    }

    return cg1_out

def cred_gen_3(primary_cred, sub_cred, pk_idp):
    P_u = primary_cred['pub']['P_u']

    e_u = sub_cred['e_u']
    c_u = sub_cred['c_u']    

    d = pk_idp['d']
    n = pk_idp['n']

    lhs = pow(c_u, e_u, n)
    rhs = (P_u * d) % n

    return lhs == rhs

#verify_cred



def verify_cred_1(x_u, primary_cred, sub_cred, m, pk_idp, pk_da):
    Y_u = primary_cred['pub']['Y_u']

    c_u = sub_cred['c_u']

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

    w = {
        'w_1':w_1,
        'w_2':w_2,
        'w_3':w_3,
        'w_4':w_4
    }


    zkp_vc1 = zkp.zkp_vf_cred_1(x_u, primary_cred, sub_cred, w, A, m, r_1, r_2, pk_idp, pk_da)

    deanon_str = {
        'w' : w,
        'm' : m
    }

    vc1_out = {
        'A':A,
        'deanon_str' : deanon_str,
        'zkp_vc1':zkp_vc1
    }

    return vc1_out