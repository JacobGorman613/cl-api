import constants

import os
from os.path import exists
import json

PK_IDP_PATH = "pk_idp.json"
SK_IDP_PATH = "sk_idp.json"
PK_DA_PATH = "pk_da.json"
SK_DA_PATH = "sk_da.json"

def clear_keys():
    if exists(PK_IDP_PATH):
        os.remove(PK_IDP_PATH)
    if exists(PK_DA_PATH):
        os.remove(PK_DA_PATH)
    if exists(SK_IDP_PATH):
        os.remove(SK_IDP_PATH)
    if exists(SK_DA_PATH):
        os.remove(SK_DA_PATH)
    while exists(PK_IDP_PATH):
        continue
    while exists(PK_DA_PATH):
        continue
    while exists(SK_IDP_PATH):
        continue
    while exists(SK_DA_PATH):
        continue


def publish_pk_idp(pk_idp):
    with open(PK_IDP_PATH, 'w') as file:
        json.dump(pk_idp, file)
        file.close()

def publish_sk_idp(sk_idp):
    with open(SK_IDP_PATH, 'w') as file:
        json.dump(sk_idp, file)
        file.close()

def import_pk_idp():
    while not exists(PK_IDP_PATH):
        continue
    with open(PK_IDP_PATH, 'r') as file:
        pk_idp = json.load(file)
        file.close()
        return pk_idp

    return {}
def import_sk_idp():
    while not exists(SK_IDP_PATH):
        continue
    with open(SK_IDP_PATH, 'r') as file:
        sk_idp = json.load(file)
        file.close()
        return sk_idp

    return {}

def publish_pk_da(pk_da):    
    with open(PK_DA_PATH, 'w') as file:
        json.dump(pk_da, file)
        file.close()


def publish_sk_da(sk_da):    
    with open(SK_DA_PATH, 'w') as file:
        json.dump(sk_da, file)
        file.close()

def import_pk_da():
    while not exists(PK_DA_PATH):
        continue
    with open(PK_DA_PATH, 'r') as file:
        pk_da = json.load(file)
        file.close()
        return pk_da

    return {}

def import_sk_da():
    while not exists(SK_DA_PATH):
        continue
    with open(SK_DA_PATH, 'r') as file:
        sk_da = json.load(file)
        file.close()
        return sk_da

    return {}