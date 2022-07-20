import da
import ca
import user
import idp
import constants

from threading import Thread
from multiprocessing import Queue

import time
import json

def user_demo(queue_user_idp, queue_idp_user, queue_user_ca, queue_ca_user):
    x_u = constants.init_user_key()
    pk_idp = constants.import_pk_idp()
    pk_da = constants.import_pk_da()

#NYM GEN
    ng1_out = user.nym_gen_1(x_u, pk_idp)

    C_1 = ng1_out['C_1']
    C_2 = ng1_out['C_2']
    N_1 = ng1_out['N_1']
    r_1 = ng1_out['r_1']
    r_2 = ng1_out['r_2']
    r_3 = ng1_out['r_3']

    zkp_ng1 = user.zkp_nym_gen_1(C_1, C_2, r_1, r_2, r_3, x_u, pk_idp)

    nym_gen_msg_1 = {
        'N_1' : N_1,
        'C_1' : C_1,
        'C_2' : C_2,
        'zkp_ng1' : zkp_ng1
    }

    queue_user_idp.put(json.dumps(nym_gen_msg_1))

    while(queue_idp_user.empty()):
        continue
    nym_gen_msg_2 = json.loads(queue_idp_user.get())

    r = nym_gen_msg_2['r']
    N_2 = nym_gen_msg_2['N_2']

    nym = constants.concat(N_1, N_2)

    ng3_out = user.nym_gen_3(r_1, r, x_u, pk_idp)

    s_u = ng3_out['s_u']
    P_u = ng3_out['P_u']
    x_u_o = ng3_out['x_u_o']
    r_4 = ng3_out['r_4']
    C_3 = ng3_out['C_3']
    s_tilde = ng3_out['s_tilde']

    #redefining as R is inconvenient and probably a bad idea, just made the diagram more bearable
    R = {
        'r': r,
        'r_1': r_1,
        'r_2': r_2,
        'r_3': r_3,
        'r_4': r_4
    }

    zkp_ng2 = user.zkp_nym_gen_2(C_1, C_2, C_3, R, P_u, x_u, x_u_o, s_u, s_tilde, pk_idp)

    ng4_out = user.nym_gen_4(x_u, pk_da)

    Y_u = ng4_out['Y_u']

    zkp_ng3 = user.zkp_nym_gen_3(P_u, Y_u, x_u, x_u_o, s_u, pk_idp, pk_da)

    nym_gen_msg_3 = {
        'P_u':P_u,
        'Y_u':Y_u,
        'C_3':C_3,
        's_tilde':s_tilde,
        'zkp_ng2':zkp_ng2,
        'zkp_ng3':zkp_ng3
    }

    queue_user_idp.put(json.dumps(nym_gen_msg_3))

    #STORE x_u_o, s_u, nym, Y_u, P_u

    #TODO: WHY DOES THIS RETURN AS A LIST?
    #[0] is a fix because for some reason cred_gen_msg_1 returns a tuple with the dict we want instead of just the dict
    zkp_cg1 = user.zkp_cred_gen_1(P_u, x_u, x_u_o, s_u, pk_idp)

    cred_gen_msg_1 = {
        'nym': nym,
        'P_u': P_u,
        'zkp_cg1': zkp_cg1
    }

    queue_user_idp.put(json.dumps(cred_gen_msg_1))

    while queue_idp_user.empty():
        continue
    cred_gen_msg_2 = json.loads(queue_idp_user.get())

    e_u = cred_gen_msg_2['e_u']
    c_u = cred_gen_msg_2['c_u']

    cred_record_correct = user.cred_gen_2(e_u, c_u, P_u, pk_idp)

    print("cred_record_correct =", cred_record_correct)
    
    #store e_u and c_u

    #VERIFY CRED

    m = "i agree not to post ncp or you can deanonymize me"

    vc1_out = user.verify_cred_1(c_u, Y_u, m, pk_idp, pk_da)

    r_1 = vc1_out['r_1']
    r_2 = vc1_out['r_2']
    w_1 = vc1_out['w_1']
    w_2 = vc1_out['w_2']
    w_3 = vc1_out['w_3']
    w_4 = vc1_out['w_4']
    A = vc1_out['A']

    w = {
        'w_1':w_1,
        'w_2':w_2,
        'w_3':w_3,
        'w_4':w_4
    }

    zkp_vc1 = user.zkp_vf_cred_1(w, A, m, r_1, r_2, e_u, x_u, x_u_o, s_u, pk_idp, pk_da)

    verify_cred_msg_1 = {
        'w':w,
        'A':A,
        'm':m,
        'zkp_vc1':zkp_vc1
    }

    queue_user_ca.put(json.dumps(verify_cred_msg_1))

    #get certificate or false

def idp_demo(queue_user_idp, queue_idp_user):
    #initialize and sk/pk, publish pk
    (pk_idp, sk_idp) = constants.init_idp_key()
    constants.publish_pk_idp(pk_idp)
    pk_da = constants.import_pk_da()

    while (queue_user_idp.empty()):
        continue

    nym_gen_msg_1 = json.loads(queue_user_idp.get())

    N_1 = nym_gen_msg_1['N_1']
    C_1 = nym_gen_msg_1['C_1']
    C_2 = nym_gen_msg_1['C_2']
    zkp_ng1 = nym_gen_msg_1['zkp_ng1']
    
    vf_ng1 = idp.verify_zkp_nym_gen_1(C_1, C_2, pk_idp, zkp_ng1)

    print("vf_ng1 =", vf_ng1)

    #BAD NAMING CONVENTION: should be ng2_out but also happens to be the same message we send
    nym_gen_msg_2 = idp.nym_gen_2()

    queue_idp_user.put(json.dumps(nym_gen_msg_2))

    N_2 = nym_gen_msg_2['N_2']
    r = nym_gen_msg_2['r']

    nym = constants.concat(N_1, N_2)

    while(queue_user_idp.empty()):
        continue
    nym_gen_msg_3 = json.loads(queue_user_idp.get())

    P_u = nym_gen_msg_3['P_u']
    Y_u = nym_gen_msg_3['Y_u']
    s_tilde = nym_gen_msg_3['s_tilde']
    C_3 = nym_gen_msg_3['C_3']
    zkp_ng2 = nym_gen_msg_3['zkp_ng2']
    zkp_ng3 = nym_gen_msg_3['zkp_ng3']

    vf_ng2 = idp.verify_zkp_nym_gen_2(C_1, C_2, C_3, r, P_u, pk_idp, zkp_ng2)
    vf_ng3 = idp.verify_zkp_nym_gen_3(P_u, Y_u, pk_idp, pk_da, zkp_ng3)

    print("vf_ng2 =", vf_ng2)
    print("vf_ng3 =", vf_ng3)

    #Store Y_u, P_u, nym


    #CRED GEN

    #in theory this is a new session, lose all non-stored variables
    while queue_user_idp.empty():
        continue
    cred_gen_msg_1 = json.loads(queue_user_idp.get())

    nym = cred_gen_msg_1['nym']
    P_u = cred_gen_msg_1['P_u']
    zkp_cg1 = cred_gen_msg_1['zkp_cg1']

    #VERIFY nym and P_u are in the database
    vf_cg1 = idp.verify_zkp_cred_gen_1(P_u, pk_idp, zkp_cg1)

    print("vf_cg1 =", vf_cg1)

    #BAD NAMING CONVENTION: should be cg1_out but also happens to be the same message we send
    cred_gen_msg_2 = idp.cred_gen_1(P_u, pk_idp, sk_idp)
    queue_idp_user.put(json.dumps(cred_gen_msg_2))

    #store e_u and c_u with P_u and nym_u

def ca_demo(queue_user_ca, queue_ca_user):
    pk_idp = constants.import_pk_idp()
    pk_da = constants.import_pk_da()

    while queue_user_ca.empty():
        continue
    verify_cred_msg_1 = json.loads(queue_user_ca.get())
    
    #realistically signed m would be sent at the start
    w = verify_cred_msg_1['w']
    A = verify_cred_msg_1['A']
    m = verify_cred_msg_1['m']
    zkp_vc1 = verify_cred_msg_1['zkp_vc1']

    vf_vc1 = ca.verify_zkp_vf_cred_1(w, A, m, zkp_vc1, pk_idp, pk_da)
    print("vf_vc1 =", vf_vc1)

    #send certificate
    
def da_demo():
    #initialize and publish keys
    (pk_da, sk_da) = constants.init_da_key()
    constants.publish_pk_da(pk_da)

def main():
    #if we dont clear the keys then user/ca read old keys and everything breaks
    constants.clear_keys()

    queue_user_idp = Queue() #for user to send stuff to idp
    queue_idp_user = Queue() #for idp to send stuff to user
    queue_user_ca = Queue()  #for user to send stuff to ca
    queue_ca_user = Queue()  #for ca to send stuff to user
    #queue_da = Queue()

    user_thread = Thread(target = user_demo, args = (queue_user_idp, queue_idp_user, queue_user_ca, queue_ca_user, ))
    idp_thread = Thread(target = idp_demo, args = (queue_user_idp, queue_idp_user, ))
    ca_thread = Thread(target = ca_demo, args = (queue_user_ca, queue_ca_user, ))
    da_thread = Thread(target = da_demo, args = ())

    user_thread.start()
    idp_thread.start()
    ca_thread.start()
    da_thread.start()

if __name__ == "__main__":
    main()