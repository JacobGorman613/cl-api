import zkp
import time

def verify_cred_2(vc1_out, pk_idp, pk_da):
    return zkp.verify_zkp_vf_cred_1(vc1_out, pk_idp, pk_da)



def schedule_ca(msg, keys, data = None):
    msg_type = msg['type']

    pk_idp = keys['pk_idp']
    pk_da = keys['pk_da']

    if msg_type == 'vc1':
        if data == None:
            #verify_cred_2 verifies the PoK in the message
            if verify_cred_2(msg['data'], pk_idp, pk_da):
                #saving our inputs shows that we verified PoK so somehow credentials faked or leaked
                proof_of_validity = [msg['data'], pk_idp, pk_da]

                out = {
                    'cert': proof_of_validity,
                    'id':msg['id']
                }
                return out
            else:
                return {
                    'send' : 'failure',
                    'send_id' : msg['id']
                }
        else:
            #Potential here if API is misused to skip a PoK. maybe we want to run it again?

            out = {
                #send certificate and cert_id to user (prob not cert_id but necessary for the demo)
                'send' : data,
                'store' : {
                    'key' : data['cert_id'],
                    'value' : {
                        'deanon_str':msg['data']['deanon_str'],
                        'proof_of_validity':data['proof_of_validity']
                    }
                },
                'send_id' : msg['id']
            }

            return out
    else:
        #TODO put real error handling here
        print("Invalid message type")

def init_keys_dict(pk_idp, pk_da):
    return {
        'pk_idp': pk_idp,
        'pk_da' : pk_da 
    }