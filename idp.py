import constants
import secrets
import zkp

#nym_gen



# returns next message to send or empty dict if zkp fails
def nym_gen_2(nym_gen_msg_1, pk_idp):
    if not zkp.verify_zkp_nym_gen_1(nym_gen_msg_1, pk_idp):
        return {}
    r = constants.rand_in_range(constants.ELL_DELTA)
    N_2 = secrets.randbits(constants.ELL_K)

    ng2_out = {
        'r': r,
        'N_2': N_2
    }
    return ng2_out

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

    vf_ng2 = zkp.verify_zkp_nym_gen_2(primary_cred_pub, C_1, C_2, C_3 , r, pk_idp, zkp_ng2)
    vf_ng3 = zkp.verify_zkp_nym_gen_3(primary_cred_pub, pk_idp, pk_da, zkp_ng3)
    return vf_ng2 and vf_ng3
#cred_gen


def cred_gen_2(cred_gen_msg_1, pk_idp, sk_idp):
    if not zkp.verify_zkp_cred_gen_1(cred_gen_msg_1, pk_idp):
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