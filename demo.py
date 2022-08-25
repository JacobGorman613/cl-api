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


    # initialize/import all necessary keys
    x_u = constants.init_user_key()
    pk_idp = constants.import_pk_idp()
    pk_da = constants.import_pk_da()

    keys = user.init_keys_dict(x_u, pk_idp, pk_da)
    
    # this may not be a great assumption to make but assuming for now proof of identity can be encoded as a string
    id_u = "this string contains definitive proof that I am thread " + str(threadno)


    # PROTOCOL: NYM_GEN

    
    # send initial message w/ proof of identity and randomly generated session id
    # NOTE we really will use a random 256 bit string but using threadno + NUM_USERS*i for the ith call lets us makes debugging far easier 
    # also allows for indexing into an array of queues based on session_id % NUM_USERS without worrying about collision

    # session_id_nym_gen = secrets.randbits(constants.ID_LENGTH)

    #note each protocol (nym gen, cred gen, cred vf) have their own session id
    session_id_nym_gen = threadno

    msg_init = user.get_init_msg(id_u, session_id_nym_gen)

    idp_queue.put(json.dumps(msg_init))

    init_response = json.loads(user_queue.get())

    if init_response != 'success':
        print("failed to verify identity")

    ng1_out = user.nym_gen_1(session_id_nym_gen, keys)

    idp_queue.put(json.dumps(ng1_out['send']))

    nym_gen_msg_2 = json.loads(user_queue.get())

    ng3_out = user.nym_gen_3(ng1_out, nym_gen_msg_2, keys)

    primary_cred = ng3_out['primary_cred']

    nym_gen_msg_3 = ng3_out['send']

    idp_queue.put(json.dumps(nym_gen_msg_3))

    nym_response = json.loads(user_queue.get())

    if nym_response != 'success':
        print("failed to obtain primary credential")
    
    # STORE primary_cred
    
    # PROTOCOL: CRED_GEN

    # new unique id for cred gen (should use random)
    session_id_cred_gen = NUM_USERS + threadno

    cg1_out = user.cred_gen_1(primary_cred, session_id_cred_gen, keys)

    idp_queue.put(json.dumps(cg1_out))

    sub_cred = json.loads(user_queue.get())

    cred_record_correct = user.cred_gen_3(primary_cred, sub_cred, keys)

    if not cred_record_correct:
        print("failure creating subcredential")
    
    # TASK store sub_cred

    idp_queue.put(json.dumps('done'))
    
    # PROTOCOL: VERIFY_CRED
    session_id_verify_cred = 2 * NUM_USERS + threadno

    m = "i agree not to post ncp or you can deanonymize me"

    vc1_out = user.verify_cred_1(primary_cred, sub_cred, m, session_id_verify_cred, keys)

    ca_queue.put(json.dumps(vc1_out))

    # get certificate or error message
    certificate = json.loads(user_queue.get())

    if certificate == 'failure':
        print("user thread {} failed to verify subcredential".format(threadno))
    ca_queue.put(json.dumps('done'))

    #send LE our certificate ID for when they choose a random user to flag
    le_queue.put(json.dumps(certificate))


def idp_demo(idp_queue, user_queues, le_queue):
    # initialize/import all necessary keys
    (pk_idp, sk_idp) = constants.init_idp_key()
    constants.publish_pk_idp(pk_idp)
    pk_da = constants.import_pk_da()

    # store keys as a single dict since certain calls need different keys
    keys = idp.init_keys_dict(pk_idp, sk_idp, pk_da)

    # represents a cache, dict of dicts
    idp_cache = idp.init_idp_cache()


    # represents persistent data
    # store one table with primary creds,
    # keep a databse w/ primary_cred table and sub_cred table
    # both are indexed to by nym
    idp_db = {
        'primary_cred' : {},
        'sub_cred' : {}
    }

    done = False

    # loop until all users and DA have sent 'done' messages
    num_finished = 0

    while not done:
        # wait until we receive a message
        msg = json.loads(idp_queue.get())

        if msg == 'done':
            num_finished += 1
            # wait for all users and LE to finish
            if num_finished == NUM_USERS + 1:
                done = True
        elif msg['type'] == 'deanon':
            # DEANON HANDLED SEPARATELY SINCE INFREQUENT AND HIGHLY IMPORTANT
            # TASK verify all legal stuff (msg['data']['legal'])

            y_hat = msg['data']['y_hat']
            perp_id = -1

            #search through primary cred database table for user w/ user['y_u'] == y_hat
            for user in idp_db['primary_cred'].values():
                if user['y_u'] == y_hat:
                    perp_id = user['id']
                    break

            le_queue.put(json.dumps(perp_id))
        else:
            out = idp.schedule_idp(msg, idp_cache, keys)
            if 'verify' in out:
                #TASK verify id is good can get id_u as out['id_u'] or msg['id_u']
                id_verified = True

                if not id_verified:
                    print("failed to verify identity")
                    out['send'] = 'failure'
                else:
                    idp.store_uid(msg, idp_cache)
                    out['send'] = 'success'
            if 'load' in out:
                key = out['load']
                load_type = out['load_type']
                if key in idp_db[load_type]:
                    out = idp.schedule_idp(msg, idp_cache, keys, idp_db[load_type][key])
                else:
                    # TODO real error handling
                    print ("failed to find {} in database".format(key))
            if 'send' in out:
                # user_queues should actually be a map of session_id -> ip address but
                # array of queues is how demo keeps track of which user we are responding to

                # send result to user with correct id
                user_queues[out['send_id'] % NUM_USERS].put(json.dumps(out['send']))

            if 'store' in out:
                key = out['store']['key']
                cred_type = out['store']['cred_type']
                value = out['store']['value']
                #TASK replace with replace database storage
                idp_db[cred_type][key] = value

    print("idp done")


def ca_demo(ca_queue, user_queues, le_queue):
    pk_idp = constants.import_pk_idp()
    pk_da = constants.import_pk_da()

    keys = ca.init_keys_dict(pk_idp, pk_da)

    ca_db = {}

    num_finished = 0

    done = False

    # loop until all users and le have sent 'done' messages
    while not done:
        msg = json.loads(ca_queue.get())

        if msg == 'done':
            num_finished += 1
            # wait for all users and LE to finish
            if num_finished == NUM_USERS + 1:
                done = True
        elif msg['type'] == 'deanon':
            # DEANON HANDLED SEPARATELY FROM MAIN CASE FOR CONTROL FLOW REASONS AND BECAUSE ACTUAL PROCESS OUTSIDE API
            # TASK: verify all legal paperwork (msg['data']['legal'])
            certificate_id = msg['data']['cert']['cert_id']
            deanon_str = ""
            try:
                deanon_str = ca_db[certificate_id]['deanon_str']
            except KeyError:
                continue    
            le_queue.put(json.dumps(deanon_str))
        else:
            # if not a deanon message or done message, call the scheduler
            out = ca.schedule_ca(msg, keys)

            # use the output of the scheduler to decide what to do

            # if 'cert' in out then we have verified users subcredential and need to send them a certificate
            if 'cert' in out:
                # TASK get a certificate and cert_id

                certificate = {
                    #should be replaced with real certificate and real cert_id but for now use session_id as cert_id
                    #we really don't even need a session id for CA, maybe removed in later version (all done one back/forth transaction)
                    #(include hash of msg id so that it is unique)
                    'cert' : "this is a certificate that I verified my subcredential with the CA" + str(constants.hash_str(msg['id'])),
                    'cert_id' : msg['id'],
                    'proof_of_validity' : out['cert']
                }

                #additional call to schedule_ca to configure out to be good for 'send' and 'store'
                #note the addition of the optional data parameter
                out = ca.schedule_ca(msg, keys, certificate)

            # if out has a send parameter send out['send'] to out['send_id']
            if 'send' in out:
                # TASK choose correct connection based on out['send_id']
                user_queues[out['send_id'] % NUM_USERS].put(json.dumps(out['send']))

            # if out has a 'store' parameter, store in our database
            if 'store' in out:
                key = out['store']['key']
                value = out['store']['value']
                #TASK replace this with real database access
                ca_db[key] = value
    
    print("ca done")
            
    
def da_demo(da_queue, le_queue):
    # initialize and publish keys
    (pk_da, sk_da) = constants.init_da_key()
    constants.publish_pk_da(pk_da)

    done = False

    # loop until LE sends done
    while not done:
        msg = json.loads(da_queue.get())

        # templating is dumb here but works
        #in a real demo deanon is the only kind of message da should be getting
        if msg == 'done':
            done = True
        elif msg['type'] == 'deanon':

            # TASK VERIFY ALL legal (msg['data']['legal'])

            deanon_msg_1 = msg['data']['deanon_str']

            #decrypt the deanon string
            y_hat = da.deanon(deanon_msg_1, pk_da, sk_da)
            
            #send decrypted deanon string to law enfocement
            le_queue.put(json.dumps(y_hat))
        else:
            print("invalid message type")
    

    print("da done")

def le_demo(le_queue, idp_queue, ca_queue, da_queue):   
    # wait for all users to send their certificate_id
    # note users don't necessarily finish in order so le_queue is not sorted (perp_index != threadno)
    while le_queue.qsize() < NUM_USERS:
        time.sleep(1)
    print("users done")

    # choose a random element of the list of certificates to be flagged as NCP
    perp_index = secrets.randbelow(NUM_USERS)

    #set certificate_id = le_queue[perp_index] then clear le_queue
    certificate = json.loads(le_queue.get())

    for i in range(perp_index):
        certificate = json.loads(le_queue.get())
    
    while not le_queue.empty():
        le_queue.get()
    
    print("LE found NCP posted, certificate had id {}".format(certificate['cert_id']))

    #send legal evidence and certificate ID to CA
    legal = "this string contains evidence of NCP posted by user w/ certificate_id = {}".format(certificate['cert_id'])

    ca_msg = {
        'type' : 'deanon',
        'data' : {
            'cert' : certificate,
            'legal': legal
        }
    }

    ca_queue.put(json.dumps(ca_msg))

    # wait for CA to send deanon_string
    deanon_str = json.loads(le_queue.get())

    if deanon_str == "":
        print("CA failed to find certificate with certificate_id")
        #kill all processes
        idp_queue.put(json.dumps('done'))
        ca_queue.put(json.dumps('done'))
        da_queue.put(json.dumps('done'))
        return -1

    #send DA deanon_str from CA
    da_msg = {
        'type' : 'deanon',
        'data' : {
            'deanon_str':deanon_str,
            'legal':legal
        }
    }

    da_queue.put(json.dumps(da_msg))

    #wait for DA to return decrypted deanonymization string
    y_hat = json.loads(le_queue.get())

    if y_hat < 1:
        print("DA failed to decrypt deanon string (invalid deanon_str)")
        #kill all processes
        idp_queue.put(json.dumps('done'))
        ca_queue.put(json.dumps('done'))
        da_queue.put(json.dumps('done'))
        return -1


    #send idp decrypted deanon string and evidence
    idp_msg = {
        'type' : 'deanon',
        'data' : { 
            'y_hat' : y_hat,
            'legal' : legal
        }
    }

    idp_queue.put(json.dumps(idp_msg))

    #wait for IDP to return identifying information
    user_id = json.loads(le_queue.get())

    if user_id == -1:
        print("idp unable to find user with y_u = {} in its database".format(y_hat))
    else:
        print("user identified: ", user_id)

    #kill other processes
    idp_queue.put(json.dumps('done'))
    ca_queue.put(json.dumps('done'))
    da_queue.put(json.dumps('done'))


    print("le done")

def main():
    # if we dont clear the keys then user/ca read old keys and everything breaks
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
    idp_thread.start()
    ca_thread.start()
    da_thread.start()
    le_thread.start()

if __name__ == "__main__":
    main()