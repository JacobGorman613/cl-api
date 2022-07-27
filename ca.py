import zkp

def verify_cred_2(vc1_out, pk_idp, pk_da):
    return zkp.verify_zkp_vf_cred_1(vc1_out, pk_idp, pk_da)