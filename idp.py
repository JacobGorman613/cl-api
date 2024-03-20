import secrets
try:
    import constants
    import zkp
    import idpcache
except:
    from . import constants
    from . import zkp
    from . import idpcache

#nym_gen
import json
import time

# returns next message to send or empty dict if zkp fails
def nym_gen_2(nym_gen_msg_1, cache, pk_idp):
    ng1_datas = cache['ng1_datas']
    ng2_datas = cache['ng2_datas']
    if not zkp.verify_zkp_nym_gen_1(nym_gen_msg_1, pk_idp):
        return {}
    r = constants.rand_in_range(constants.ELL_DELTA)
    N_2 = secrets.randbits(constants.ELL_K)

    ng2_out = {
        'r': r,
        'N_2': N_2
    }

    session_id = nym_gen_msg_1['id']
    ng1_datas[session_id] = (nym_gen_msg_1, time.time())
    ng2_datas[session_id] = (ng2_out, time.time())
    idpcache.write_to_cache(cache)
    return ng2_out

def nym_gen_4(nym_gen_msg_3, cache, pk_idp, pk_da):
    session_id = nym_gen_msg_3['id']

    nym_gen_msg_1 = cache['ng1_datas'][session_id][0]
    nym_gen_msg_2 = cache['ng2_datas'][session_id][0]

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
    C_3 = nym_gen_msg_3['C_3']

    zkp_ng2 = nym_gen_msg_3['zkp_ng2']
    zkp_ng3 = nym_gen_msg_3['zkp_ng3']

    vf_ng2 = zkp.verify_zkp_nym_gen_2(primary_cred_pub, C_1, C_2, C_3, r, pk_idp, zkp_ng2)
    vf_ng3 = zkp.verify_zkp_nym_gen_3(primary_cred_pub, pk_idp, pk_da, zkp_ng3)
    

    #if ZKPs succeed store primary_cred
    if vf_ng2 and vf_ng3:
        primary_cred_pub['id'] = cache['user_ids'][session_id][0]
        out = {
            'send' : 'success',
            'send_id' : session_id,
            'store': {
                'key'   : nym,
                'cred_type' : 'primary_cred',
                'value' : primary_cred_pub
            }
        }
        #primary_creds[session_id] = primary_cred_pub
        return out
    else:
        #TODO error code for failure to identify
        return {
            'send' : 'failure',
            'send_id' : session_id
        }

#cred_gen


def cred_gen_2(msg, primary_cred, pk_idp, sk_idp): #cred_gen_msg_1, sub_creds, pk_idp, sk_idp):
    if not zkp.verify_zkp_cred_gen_1(msg['data'], primary_cred, pk_idp):
        return {}

    p_u = primary_cred['p_u']

    d = pk_idp['d']
    n = pk_idp['n']

    p = sk_idp['p']
    q = sk_idp['q']

    p_prime = (p - 1) >> 1
    q_prime = (q - 1) >> 1

    e_u = constants.rand_in_range(constants.ELL_LAMBDA)
    #exp = 1 / e_u mod ord(QR_n) 
    exp = pow(e_u, -1, p_prime * q_prime) 

    c_u = pow(p_u * d, exp, n)
    
    sub_cred = {
        'e_u': e_u,
        'c_u': c_u
    }

    return sub_cred


def schedule_idp(msg, cache, keys, data = None):
    msg_type = msg['type']

    pk_idp = keys['pk_idp']
    sk_idp = keys['sk_idp']
    pk_da = keys['pk_da']

    if msg_type == 'vf_id':
        return {
            'verify' : msg['id_u'],
            'send' : '',
            'send_id' : msg['id']
        }
    elif msg_type == 'ng1':

        ng2_out = nym_gen_2(msg['data'], cache, pk_idp)

        #TODO add appropriate behavior
        if len(ng2_out) == 0:
            print ("zkp_ng1 failed")
            #TODO should return error code
            return {}
        else:
            out = {
                'send' : ng2_out,
                'send_id' : msg['id']
            }
            return out
    elif msg_type == 'ng3':

        #ng3_data should contain id to obscure
        ng3_data = msg['data']

        #have to add extra checks to make sure we got valid parameters from other person
        #checks second and third proofs of knowledge
        #ng4 checks if 2 PoKs from msg and updates cache (sometimes instructions to store)
        return nym_gen_4(msg['data'], cache, pk_idp, pk_da)

        #CRED GEN (wait for user to initiate)
    elif msg_type == 'cg1':
        if data == None:
            #load the primary cred associated with nym
            out = {
                'load' : msg['data']['pub']['nym'],
                'load_type' : 'primary_cred'
            }
            return out
        else:
            #cg2_out = sub_cred
            cg2_out = cred_gen_2(msg, data, pk_idp, sk_idp)
            
            if len(cg2_out) == 0:
                print ("zkp_cg1 failed")
                return {}

            out = {
                'send_id':msg['id'],
                'send' : cg2_out,
                'store' : {
                    'key' : msg['data']['pub']['nym'],
                    'cred_type' : 'sub_cred',
                    'value': cg2_out
                }
            }
            return out
    else:
        #TODO put real error handling here
        print("Invalid message type")

def init_idp_cache():
    return {
        'ng1_datas' : {},
        'ng2_datas' : {},
        'user_ids' : {}
    }

#deletes all entrys in idp_cache that were put there more than 'age' seconds ago
def clean_idp_cache(idp_cache, age):
    curr_time = time.time()
    print()
    print(curr_time)
    print()
    deleted_items = {}
    for sub_dict_key in list(idp_cache.keys()):
        deleted_items[sub_dict_key] = {}
        for key in list(idp_cache[sub_dict_key].keys()):
            if curr_time - idp_cache[sub_dict_key][key][1] > age:
                #del idp_cache[sub_dict_key][key]
                deleted_items[sub_dict_key][key] = idp_cache[sub_dict_key].pop(key)

    return deleted_items

def init_keys_dict(pk_idp, sk_idp, pk_da):
    return {
        'pk_idp': pk_idp,
        'sk_idp': sk_idp,
        'pk_da': pk_da
    }