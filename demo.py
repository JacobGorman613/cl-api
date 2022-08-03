import da
import ca
import user
import idp
import constants

from threading import Thread
from multiprocessing import Queue

import json

def user_demo(user_queue, idp_queue, ca_queue):
    x_u = constants.init_user_key()
    pk_idp = constants.import_pk_idp()
    pk_da = constants.import_pk_da()

#NYM GEN
    ng1_out = user.nym_gen_1(x_u, pk_idp)

    idp_queue.put(json.dumps(ng1_out['send']))

    while user_queue.empty():
        continue
    nym_gen_msg_2 = json.loads(user_queue.get())

    ng3_out = user.nym_gen_3(x_u, ng1_out, nym_gen_msg_2, pk_idp, pk_da)

    primary_cred = ng3_out['primary_cred']

    nym_gen_msg_3 = ng3_out['send']

    idp_queue.put(json.dumps(nym_gen_msg_3))

    #STORE primary_cred

#CRED GEN
    cg1_out = user.cred_gen_1(x_u, primary_cred, pk_idp)

    idp_queue.put(json.dumps(cg1_out))

    while user_queue.empty():
        continue

    #sub_cred = cred_gen_msg_2
    sub_cred = json.loads(user_queue.get())

    cred_record_correct = user.cred_gen_3(primary_cred, sub_cred, pk_idp)

    print("cred_record_correct =", cred_record_correct)
    
    #store sub_cred

#VERIFY CRED
    m = "i agree not to post ncp or you can deanonymize me"

    vc1_out = user.verify_cred_1(x_u, primary_cred, sub_cred, m, pk_idp, pk_da)

    ca_queue.put(json.dumps(vc1_out))

    #get certificate or false

def idp_demo(idp_queue, user_queue, le_queue):
    #initialize and sk/pk, publish pk
    (pk_idp, sk_idp) = constants.init_idp_key()
    constants.publish_pk_idp(pk_idp)
    pk_da = constants.import_pk_da()
#NYM GEN (wait for user to initiate)
    while (idp_queue.empty()):
        continue

    nym_gen_msg_1 = json.loads(idp_queue.get())
    
    ng2_out = idp.nym_gen_2(nym_gen_msg_1, pk_idp)

    if len(ng2_out) == 0:
        print ("zkp_ng1 failed")

    user_queue.put(json.dumps(ng2_out))

    while(idp_queue.empty()):
        continue
    nym_gen_msg_3 = json.loads(idp_queue.get())

    primary_cred_pub = nym_gen_msg_3['pub']

    #have to add extra checks to make sure we got valid parameters from other person
    #checks second and third proofs of knowledge
    vf_ng2 = idp.nym_gen_4(nym_gen_msg_1, ng2_out, nym_gen_msg_3, pk_idp, pk_da)

    print("vf_ng2 =", vf_ng2)

    #Store primary_cred_pub

#CRED GEN (wait for user to initiate)

    #in theory this is a new session, lose all non-stored variables
    while idp_queue.empty():
        continue
    cg1_out = json.loads(idp_queue.get())

    #TASK: primary_cred_pub is in the database

    #sub_cred = cg2_out
    sub_cred = idp.cred_gen_2(cg1_out, pk_idp, sk_idp)
    if len(sub_cred) == 0:
        print("VFCG failed")
    else:
        user_queue.put(json.dumps(sub_cred))

    #store sub_cred with primary_cred_pub

#DEANON
    #wait until law enforcement comes to us
    while idp_queue.empty():
        continue

    deanon_msg_2 = json.loads(idp_queue.get())
    y_hat = deanon_msg_2['y_hat']

    if y_hat == primary_cred_pub['Y_u']:
        print("MATCH, FOUND USER")
    else:
        print("NO MATCH, SOMETHINGS WRONG")

def ca_demo(ca_queue, user_queue, le_queue):
    pk_idp = constants.import_pk_idp()
    pk_da = constants.import_pk_da()
#VERIFY CRED
    while ca_queue.empty():
        continue
    vc1_out = json.loads(ca_queue.get())
    
    #TASK verify m is valid signed string

    #vc2_out = vf_vc1
    vf_vc1 = ca.verify_cred_2(vc1_out, pk_idp, pk_da)
    print("vf_vc1 =", vf_vc1)

    deanon_str = vc1_out['deanon_str']
    #send certificate
    #deanon_str with serial number of certificate

    #here we would wait for law enforcement to send a certificate then check our database for corresponding deanon_str
    
    le_queue.put(json.dumps(deanon_str))
    
def da_demo(da_queue, le_queue):
    #initialize and publish keys
    (pk_da, sk_da) = constants.init_da_key()
    constants.publish_pk_da(pk_da)

    while(da_queue.empty()):
        continue

    deanon_msg_1 = json.loads(da_queue.get())

    y_hat = da.deanon(deanon_msg_1, pk_da, sk_da)

    if (y_hat < 0):
        print ("deanon check failed")

    deanon_msg_2 = {
        'y_hat': y_hat
    }

    le_queue.put(json.dumps(deanon_msg_2))

def le_demo(le_queue, idp_queue, ca_queue, da_queue):
    while le_queue.empty():
        continue
    
    deanon_msg_1 = json.loads(le_queue.get())
    #i guess there's no real reason to un-json/re-json the string    
    da_queue.put(json.dumps(deanon_msg_1))

    while le_queue.empty():
        continue

    deanon_msg_2 = json.loads(le_queue.get())
    #i guess there's no real reason to un-json/re-json the string
    idp_queue.put(json.dumps(deanon_msg_2))

def main():
    #if we dont clear the keys then user/ca read old keys and everything breaks
    constants.clear_keys()

    # queues for each process to receive messages
    # note queues are threadsafe
    user_queue = Queue()
    idp_queue = Queue()
    ca_queue = Queue()
    da_queue = Queue()
    le_queue = Queue()

    user_thread = Thread(target = user_demo, args = (user_queue, idp_queue, ca_queue, ))
    idp_thread = Thread(target = idp_demo, args = (idp_queue, user_queue, le_queue, ))
    ca_thread = Thread(target = ca_demo, args = (ca_queue, user_queue, le_queue, ))
    da_thread = Thread(target = da_demo, args = (da_queue, le_queue, ))
    le_thread = Thread(target = le_demo, args = (le_queue, idp_queue, ca_queue, da_queue, ))

    user_thread.start()
    idp_thread.start()
    ca_thread.start()
    da_thread.start()
    le_thread.start()

if __name__ == "__main__":
    main()