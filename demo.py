NUM_USERS = 10

import da
import ca
import user
import idp
import constants

import secrets
import time
import json
from threading import Thread
from multiprocessing import Queue

def user_demo(user_queue, idp_queue, ca_queue, le_queue, threadno):
    #initialize/import all necessary keys
    x_u = constants.init_user_key()
    pk_idp = constants.import_pk_idp()
    pk_da = constants.import_pk_da()
    
    #this may not be a great assumption to make but assuming for now proof of identity can be encoded as a json
    id_u = "this string contains definitive proof that I am thread " + str(threadno)


    #PROTOCOL: NYM_GEN

    #DIFF use random 256 bit session_id instead. 
    #   here we do it deterministically because we can assume no cheating 
    #   and no collision and it makes keeping track of user_queues easier

    session_id_nym_gen = threadno

    msg_init = {
        'type':'vf_id',
        'id_u':id_u,
        'id':session_id_nym_gen
    }

    idp_queue.put(json.dumps(msg_init))

    init_response = json.loads(user_queue.get())

    if init_response != 'success':
        print("failed to verify identity")

    ng1_out = user.nym_gen_1(x_u, session_id_nym_gen, pk_idp)

    idp_queue.put(json.dumps(ng1_out['send']))

    while user_queue.empty():
        time.sleep(1)
    nym_gen_msg_2 = json.loads(user_queue.get())

    ng3_out = user.nym_gen_3(x_u, ng1_out, nym_gen_msg_2, pk_idp, pk_da)

    primary_cred = ng3_out['primary_cred']

    nym_gen_msg_3 = ng3_out['send']

    idp_queue.put(json.dumps(nym_gen_msg_3))

    while user_queue.empty():
        time.sleep(1)

    nym_response = json.loads(user_queue.get())

    if nym_response != 'success':
        print("failed to obtain primary credential")
    
    #STORE primary_cred
    
    #PROTOCOL: CRED_GEN

    #new unique id for cred gen (should use random)
    session_id_cred_gen = NUM_USERS + threadno

    cg1_out = user.cred_gen_1(x_u, primary_cred, pk_idp, session_id_cred_gen)

    idp_queue.put(json.dumps(cg1_out))

    while user_queue.empty():
        time.sleep(1)

    sub_cred = json.loads(user_queue.get())

    cred_record_correct = user.cred_gen_3(primary_cred, sub_cred, pk_idp)

    if not cred_record_correct:
        print("failure creating subcredential")
    
    #TASK store sub_cred

    idp_queue.put(json.dumps('done'))
    
    #PROTOCOL: VERIFY_CRED
    session_id_verify_cred = 2 * NUM_USERS + threadno

    m = "i agree not to post ncp or you can deanonymize me"

    vc1_out = user.verify_cred_1(x_u, primary_cred, sub_cred, m, pk_idp, pk_da, session_id_verify_cred)

    ca_queue.put(json.dumps(vc1_out))

    #get certificate or false
    #for now we don't get rejection message so if we get anything then its a certificate
    #TODO fix so that there's an error message
    certificate = json.loads(user_queue.get())
    le_queue.put(certificate['cert_id'])

    ca_queue.put(json.dumps('done'))

def idp_demo(idp_queue, user_queues, le_queue):
    #initialize/import all necessary keys
    (pk_idp, sk_idp) = constants.init_idp_key()
    constants.publish_pk_idp(pk_idp)
    pk_da = constants.import_pk_da()

    #store keys as one element. Is this realistic? Could we import all the keys as one thing through PKI?
    #otherwise make separate args for each which makes users life harder
    keys = {
        'pk_idp': pk_idp,
        'sk_idp': sk_idp,
        'pk_da': pk_da
    }

    #represents persistent data
    database = {
        'primary_cred' : {},
        'sub_cred' : {}

    }

    #represents a cache
    buffer = {
        'primary_creds' : {},
        'ng1_datas' : {},
        'ng2_datas' : {},
        'ng3_datas' : {},
        'sub_creds' : {},
        'user_ids' : {}
    }

    done = False

    #loop until all users and DA have sent 'done' messages
    num_finished = 0

    while not done:
        #wait until we receive a message
        while (idp_queue.empty()):
            time.sleep(1)
        msg = json.loads(idp_queue.get())

        if msg == 'done':
            num_finished += 1
            #wait for le to finish too
            if num_finished == NUM_USERS + 1:
                done = True
                print("idp done")
        elif msg['type'] == 'deanon':
            #DEANON HANDLED SEPARATELY SINCE INFREQUENT AND HIGHLY IMPORTANT
            #TASK verify all legal stuff

            y_hat = msg['data']
            perp_id = -1

            for user in database['primary_cred'].values():
                if user['Y_u'] == y_hat:
                    perp_id = user['id']
                    break

            le_queue.put(json.dumps(perp_id))
        else:
            out = idp.schedule_idp(msg, buffer, keys)
            if 'load' in out:
                key = out['load']
                load_type = out['load_type']
                if key in database[load_type]:
                    out = idp.schedule_idp(msg, buffer, keys, database[load_type][key])
                else:
                    #TODO real error handling
                    print ("failed to find {} in database".format(key))
            if 'send' in out:
                #send result to user with correct id
                user_queues[msg['id'] % NUM_USERS].put(json.dumps(out['send']))

            if 'store' in out:
                key = out['store']['key']
                cred_type = out['store']['cred_type']
                value = out['store']['value']
                database[cred_type][key] = value


def ca_demo(ca_queue, user_queues, le_queue):
    pk_idp = constants.import_pk_idp()
    pk_da = constants.import_pk_da()

    keys = {
        'pk_idp': pk_idp,
        'pk_da' : pk_da 
    }

    database = {}

    num_finished = 0

    done = False

    #loop until all users and le have sent 'done' messages
    while not done:

        while ca_queue.empty():
            time.sleep(1)
        
        msg = json.loads(ca_queue.get())

        if msg == 'done':
            num_finished += 1
            #wait for le to finish too
            if num_finished == NUM_USERS + 1:
                print("ca done")
                done = True
        elif msg['type'] == 'deanon':
            #DEANON HANDLED SEPARATELY FROM MAIN CASE FOR CONTROL FLOW REASONS AND BECAUSE ACTUAL PROCESS OUTSIDE API
            certificate_id = msg['data']
            deanon_str = database[certificate_id]['deanon_str']
            #print("deanon = ", json.dumps(deanon_str, indent = 4))
            le_queue.put(json.dumps(deanon_str))
        else:
            out = ca.schedule_ca(msg, keys)

            if 'cert' in out:
                #TASK get a certificate and cert_id

                certificate = {
                    'cert' : secrets.randbits(64),
                    'cert_id' : secrets.randbits(64),
                    'proof_of_validity' : out['cert']
                }
                out = ca.schedule_ca(msg, keys, certificate)

            if 'send' in out:
                #TODO pick right queue based on out['send_id']
                user_queues[msg['id'] % NUM_USERS].put(json.dumps(out['send']))

            if 'store' in out:
                key = out['store']['key']
                value = out['store']['value']
                database[key] = value
            
    
def da_demo(da_queue, le_queue):
    #initialize and publish keys
    (pk_da, sk_da) = constants.init_da_key()
    constants.publish_pk_da(pk_da)

    done = False

    #loop until LE sends done
    while not done:
        while(da_queue.empty()):
            time.sleep(1)

        msg = json.loads(da_queue.get())

        #templating is dumb here but works
        if msg == 'done':
            print("da done")
            done = True
        elif msg['type'] == 'deanon':

            #TASK VERIFY ALL PAPERWORK

            deanon_msg_1 = msg['data']

            y_hat = da.deanon(deanon_msg_1, pk_da, sk_da)
            le_queue.put(json.dumps(y_hat))
        else:
            print("invalid message type")

def le_demo(le_queue, idp_queue, ca_queue, da_queue):   
    while le_queue.qsize() < NUM_USERS:
        time.sleep(1)

    perp_index = secrets.randbelow(NUM_USERS)

    certificate_id = le_queue.get()

    for i in range(perp_index):
        certificate_id = le_queue.get()
    
    while not le_queue.empty():
        le_queue.get()

    ca_msg = {
        'type' : 'deanon',
        'data' : certificate_id
    }
    ca_queue.put(json.dumps(ca_msg))

    while le_queue.empty():
        time.sleep(1)
    deanon_str = json.loads(le_queue.get())

    #kill CA
    ca_queue.put(json.dumps('done'))

    da_msg = {
        'type' : 'deanon',
        'data' : deanon_str
    }

    da_queue.put(json.dumps(da_msg))

    while le_queue.empty():
        time.sleep(1)
    y_hat = json.loads(le_queue.get())

    #kill da
    da_queue.put(json.dumps('done'))
    
    if y_hat < 1:
        print("deanon failed, invalid deanon string")
    else:
        idp_msg = {
            'type' : 'deanon',
            'data' : y_hat
        }
        idp_queue.put(json.dumps(idp_msg))

        while le_queue.empty():
            time.sleep(1)
        user_id = json.loads(le_queue.get())

        print("perp_id: ", user_id)

    #KILL idp
    idp_queue.put(json.dumps('done'))

def main():
    #if we dont clear the keys then user/ca read old keys and everything breaks
    constants.clear_keys()

    # queues for each process to receive messages
    # note queues are threadsafe
    idp_queue = Queue()
    ca_queue = Queue()
    da_queue = Queue()
    le_queue = Queue()

    user_threads = []
    user_queues = []
    for i in range(NUM_USERS):
        user_queues.append(Queue())
        user_threads.append(Thread(target = user_demo, args = (user_queues[i], idp_queue, ca_queue, le_queue, i, )))

    idp_thread = Thread(target = idp_demo, args = (idp_queue, user_queues, le_queue, ))
    ca_thread = Thread(target = ca_demo, args = (ca_queue, user_queues, le_queue, ))
    da_thread = Thread(target = da_demo, args = (da_queue, le_queue, ))
    le_thread = Thread(target = le_demo, args = (le_queue, idp_queue, ca_queue, da_queue, ))

    for i in range(NUM_USERS):
        user_threads[i].start()
    #user_thread.start()
    idp_thread.start()
    ca_thread.start()
    da_thread.start()
    le_thread.start()

if __name__ == "__main__":
    main()