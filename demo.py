import da
import ca
import user
import idp
import constants

from threading import Thread
from multiprocessing import Queue

import json

def user_demo(queue_user_idp, queue_idp_user, queue_user_ca, queue_ca_user):
    x_u = constants.init_user_key()
    pk_idp = constants.import_pk_idp()
    pk_da = constants.import_pk_da()

#NYM GEN
    ng1_out = user.nym_gen_1(x_u, pk_idp)

    queue_user_idp.put(json.dumps(ng1_out['send']))

    while queue_idp_user.empty():
        continue
    nym_gen_msg_2 = json.loads(queue_idp_user.get())

    ng3_out = user.nym_gen_3(x_u, ng1_out, nym_gen_msg_2, pk_idp, pk_da)

    primary_cred = ng3_out['primary_cred']

    nym_gen_msg_3 = ng3_out['send']

    queue_user_idp.put(json.dumps(nym_gen_msg_3))

    #STORE primary_cred

#CRED GEN
    cg1_out = user.cred_gen_1(x_u, primary_cred, pk_idp)

    queue_user_idp.put(json.dumps(cg1_out))

    while queue_idp_user.empty():
        continue

    #sub_cred = cred_gen_msg_2
    sub_cred = json.loads(queue_idp_user.get())

    cred_record_correct = user.cred_gen_3(primary_cred, sub_cred, pk_idp)

    print("cred_record_correct =", cred_record_correct)
    
    #store sub_cred

#VERIFY CRED
    m = "i agree not to post ncp or you can deanonymize me"

    vc1_out = user.verify_cred_1(x_u, primary_cred, sub_cred, m, pk_idp, pk_da)

    queue_user_ca.put(json.dumps(vc1_out))

    #get certificate or false

def idp_demo(queue_user_idp, queue_idp_user, queue_le_idp, queue_idp_le):
    #initialize and sk/pk, publish pk
    (pk_idp, sk_idp) = constants.init_idp_key()
    constants.publish_pk_idp(pk_idp)
    pk_da = constants.import_pk_da()
#NYM GEN (wait for user to initiate)
    while (queue_user_idp.empty()):
        continue

    nym_gen_msg_1 = json.loads(queue_user_idp.get())
    
    ng2_out = idp.nym_gen_2(nym_gen_msg_1, pk_idp)

    if len(ng2_out) == 0:
        print ("zkp_ng1 failed")

    queue_idp_user.put(json.dumps(ng2_out))

    while(queue_user_idp.empty()):
        continue
    nym_gen_msg_3 = json.loads(queue_user_idp.get())

    primary_cred_pub = nym_gen_msg_3['pub']

    #have to add extra checks to make sure we got valid parameters from other person
    #checks second and third proofs of knowledge
    vf_ng2 = idp.nym_gen_4(nym_gen_msg_1, ng2_out, nym_gen_msg_3, pk_idp, pk_da)

    print("vf_ng2 =", vf_ng2)

    #Store primary_cred_pub

#CRED GEN (wait for user to initiate)

    #in theory this is a new session, lose all non-stored variables
    while queue_user_idp.empty():
        continue
    cg1_out = json.loads(queue_user_idp.get())

    #TASK: primary_cred_pub is in the database

    #sub_cred = cg2_out
    sub_cred = idp.cred_gen_2(cg1_out, pk_idp, sk_idp)
    if len(sub_cred) == 0:
        print("VFCG failed")
    else:
        queue_idp_user.put(json.dumps(sub_cred))

    #store sub_cred with primary_cred_pub

#DEANON
    #wait until law enforcement comes to us
    while queue_le_idp.empty():
        continue

    deanon_msg_2 = json.loads(queue_le_idp.get())
    y_hat = deanon_msg_2['y_hat']

    if y_hat == primary_cred_pub['Y_u']:
        print("MATCH, FOUND USER")
    else:
        print("NO MATCH, SOMETHINGS WRONG")

def ca_demo(queue_user_ca, queue_ca_user, queue_ca_le):
    pk_idp = constants.import_pk_idp()
    pk_da = constants.import_pk_da()
#VERIFY CRED
    while queue_user_ca.empty():
        continue
    vc1_out = json.loads(queue_user_ca.get())
    
    #TASK verify m is valid signed string

    #vc2_out = vf_vc1
    vf_vc1 = ca.verify_cred_2(vc1_out, pk_idp, pk_da)
    print("vf_vc1 =", vf_vc1)

    deanon_str = vc1_out['deanon_str']
    #send certificate
    #deanon_str with serial number of certificate

    #here we would wait for law enforcement to send a certificate then check our database for corresponding deanon_str
    
    queue_ca_le.put(json.dumps(deanon_str))

def le_demo(queue_ca_le, queue_le_idp, queue_idp_le, queue_le_da, queue_da_le):
    while queue_ca_le.empty():
        continue
    
    deanon_msg_1 = json.loads(queue_ca_le.get())
    #i guess there's no real reason to un-json/re-json the string    
    queue_le_da.put(json.dumps(deanon_msg_1))

    while queue_da_le.empty():
        continue

    deanon_msg_2 = json.loads(queue_da_le.get())
    #i guess there's no real reason to un-json/re-json the string
    queue_le_idp.put(json.dumps(deanon_msg_2))
    
def da_demo(queue_le_da, queue_da_le):
    #initialize and publish keys
    (pk_da, sk_da) = constants.init_da_key()
    constants.publish_pk_da(pk_da)

    while(queue_le_da.empty()):
        continue

    deanon_msg_1 = json.loads(queue_le_da.get())

    y_hat = da.deanon(deanon_msg_1, pk_da, sk_da)

    if (y_hat < 0):
        print ("deanon check failed")

    deanon_msg_2 = {
        'y_hat': y_hat
    }

    queue_da_le.put(json.dumps(deanon_msg_2))

def main():
    #if we dont clear the keys then user/ca read old keys and everything breaks
    constants.clear_keys()

    queue_user_idp = Queue() #for user to send stuff to idp
    queue_idp_user = Queue() #for idp to send stuff to user
    
    queue_user_ca = Queue()  #for user to send stuff to ca
    queue_ca_user = Queue()  #for ca to send stuff to user
    
    queue_ca_le = Queue()

    queue_le_idp = Queue()
    queue_idp_le = Queue()

    queue_le_da = Queue()
    queue_da_le = Queue()

    user_thread = Thread(target = user_demo, args = (queue_user_idp, queue_idp_user, queue_user_ca, queue_ca_user, ))
    idp_thread = Thread(target = idp_demo, args = (queue_user_idp, queue_idp_user, queue_le_idp, queue_idp_le, ))
    ca_thread = Thread(target = ca_demo, args = (queue_user_ca, queue_ca_user, queue_ca_le, ))
    da_thread = Thread(target = da_demo, args = (queue_le_da, queue_da_le, ))
    le_thread = Thread(target = le_demo, args = (queue_ca_le, queue_le_idp, queue_idp_le, queue_le_da, queue_da_le, ))

    user_thread.start()
    idp_thread.start()
    ca_thread.start()
    da_thread.start()
    le_thread.start()

if __name__ == "__main__":
    main()