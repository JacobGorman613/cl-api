import zkp
import time

def verify_cred_2(vc1_out, keys):
    pk_idp = keys['pk_idp']
    pk_da = keys['pk_da']
    return zkp.verify_zkp_vf_cred_1(vc1_out, pk_idp, pk_da)


def init_keys_dict(pk_idp, pk_da):
    return {
        'pk_idp': pk_idp,
        'pk_da' : pk_da 
    }