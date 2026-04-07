import json
import os


def _cache_file():
    return os.path.join(os.environ["IDP_CACHE_DIR"], "idp_cache.json")


def _db_file():
    return os.path.join(os.environ["IDP_CACHE_DIR"], "idp_db.json")


def set_up_cache():
    if os.path.isfile(_cache_file()):
        return False
    cache = {
        'ng1_datas': {},
        'ng2_datas': {},
        'user_ids': {}
    }
    with open(_cache_file(), 'w') as f:
        json.dump(cache, f)
    return True


def write_to_cache(cache):
    if not os.path.isfile(_cache_file()):
        return False
    with open(_cache_file(), 'w') as f:
        json.dump(cache, f)
    return True


def get_cache():
    if not os.path.isfile(_cache_file()):
        return False
    with open(_cache_file()) as f:
        return json.load(f)


def set_up_idp_db():
    if os.path.isfile(_db_file()):
        return False
    idp_db = {
        'primary_cred': {},
        'sub_cred': {}
    }
    with open(_db_file(), 'w') as f:
        json.dump(idp_db, f)
    return True


def write_to_idp_db(idp_db):
    if not os.path.isfile(_db_file()):
        return False
    with open(_db_file(), 'w') as f:
        json.dump(idp_db, f)
    return True


def get_idp_db():
    if not os.path.isfile(_db_file()):
        return False
    with open(_db_file()) as f:
        return json.load(f)
