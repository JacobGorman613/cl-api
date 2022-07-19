import da
import ca
import user
import idp
import constants

from threading import Thread
from multiprocessing import Queue

import time
import json

def user_demo(queue_user_idp, queue_user_ca):
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
def idp_demo(queue_user_idp):
    #initialize and sk/pk, publish pk
    (pk_idp, sk_idp) = constants.init_idp_key()
    constants.publish_pk_idp(pk_idp)

    while (queue_user_idp.empty()):
        continue

    nym_gen_msg_1 = json.loads(queue_user_idp.get())
    N_1 = nym_gen_msg_1['N_1']
    C_1 = nym_gen_msg_1['C_1']
    C_2 = nym_gen_msg_1['C_2']
    zkp_ng1 = nym_gen_msg_1['zkp_ng1']
    
    vf = idp.verify_zkp_nym_gen_1(C_1, C_2, pk_idp, zkp_ng1)

    print(vf)

def ca_demo(pid):
    return 0
    
def da_demo():
    #initialize and publish keys
    (pk_da, sk_da) = constants.init_da_key()
    constants.publish_pk_da(pk_da)

def main():
    #if we dont clear the keys then user/ca read old keys and everything breaks
    constants.clear_keys()

    queue_user_idp = Queue()
    queue_user_ca = Queue()
    #queue_da = Queue()

    user_thread = Thread(target = user_demo, args = (queue_user_idp, queue_user_ca, ))
    idp_thread = Thread(target = idp_demo, args = (queue_user_idp, ))
    ca_thread = Thread(target = ca_demo, args = (queue_user_ca, ))
    da_thread = Thread(target = da_demo, args = ())

    user_thread.start()
    idp_thread.start()
    ca_thread.start()
    da_thread.start()

if __name__ == "__main__":
    main()