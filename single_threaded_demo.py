NEW_KEYS = False

import da
import ca
import user
import idp
import constants
import key_storage

import secrets
import time
import json

def main():
    # initialize and publish keys
    if NEW_KEYS:
        (pk_da, sk_da) = constants.init_da_key()
        key_storage.publish_pk_da(pk_da)
        key_storage.publish_sk_da(sk_da)

        (pk_idp, sk_idp) = constants.init_idp_key()
        key_storage.publish_pk_idp(pk_idp)
        key_storage.publish_sk_idp(sk_idp)
    else:
        pk_da = key_storage.import_pk_da()
        sk_da = key_storage.import_sk_da()


        pk_idp = key_storage.import_pk_idp()
        sk_idp = key_storage.import_sk_idp()

    x_u = constants.init_user_key()

    user_keys = user.init_keys_dict(x_u, pk_idp, pk_da)
    ca_keys = ca.init_keys_dict(pk_idp, pk_da)
    idp_keys = idp.init_keys_dict(pk_idp, sk_idp, pk_da)

    idp_cache = idp.init_idp_cache()
    idp_db = {
        'primary_cred' : {},
        'subcred' : {}
    }

    nym = "pseudonym"
    id = "user_identification_string (e.g. license no)"

    session_id_nym_gen = 0
    idp_cache['user_ids'][session_id_nym_gen] = ("user identification string", time.time())

    ng1_out = user.nym_gen_1(session_id_nym_gen, user_keys)
    ng1_msg = ng1_out['send']

    ng2_out = idp.nym_gen_2(ng1_msg['data'], idp_cache, pk_idp)
    ng2_msg = ng2_out

    ng3_out = user.nym_gen_3(ng1_out, ng2_msg, user_keys)
    ng3_msg = ng3_out['send']

    primary_cred_user = ng3_out['primary_cred']
    primary_cred_idp = ng3_msg['data']['pub']

    if not idp.nym_gen_4(ng3_msg['data'], idp_cache, pk_idp, pk_da):
        print("failure")

    idp_db['primary_cred'][nym] = primary_cred_idp

    # Subcredential Generation
    sid = 2


    t_start = time.process_time()
    cg1_out = user.cred_gen_1(primary_cred_user, sid, user_keys)
    t_end = time.process_time()
    print("time for user to generate proof that primary credential is valid: " + str(t_end - t_start))


    t_start = time.process_time()
    # TODO check cg1_out['pub'] in idp_db
    subcred = idp.cred_gen_2(cg1_out, primary_cred_idp, pk_idp, sk_idp)
    subcred_check_idp = len(subcred) != 0
    t_end = time.process_time()
    print("time for IDP to validate proof that primary credential is valid AND issue subcredential: " + str(t_end - t_start))


    t_start = time.process_time()
    subcred_check_user = user.cred_gen_3(primary_cred_user, subcred, user_keys)
    t_end = time.process_time()
    print("time for user to validate proof that subcredential is valid: " + str(t_end - t_start))

    if not subcred_check_idp or not subcred_check_user:
        print("failure")

    idp_db['subcred'][cg1_out['data']['pub']['nym']] = subcred

    # subcred verification

    t_start = time.process_time()
    vc1_out = user.verify_cred_1(primary_cred_user, subcred, "hello world", sid, user_keys)
    t_end = time.process_time()
    print("time for user to generate proof that subcredential is valid: " + str(t_end - t_start))


    t_start = time.process_time()
    # add time for validating vc1_out['m']
    if not ca.verify_cred_2(vc1_out['data'], ca_keys):
        print("failure")
    t_end = time.process_time()
    print("time for CA to validate proof that subcredential is valid: " + str(t_end - t_start))

    deanon_str = vc1_out['data']['deanon_str']

    # CA saves deanon string with certificate id

    # Deanonymization: after LE sends problematic image, CA finds deanon_str assocaited with certificate id

    y_hat = da.deanon(deanon_str, pk_da, sk_da)

    if y_hat == -1:
        print("failure")

    #search through primary cred database table for user w/ user['y_u'] == y_hat
    for u in idp_db['primary_cred'].values():
        if u['y_u'] == y_hat:
            print("found id")


if __name__ == "__main__":
    main()