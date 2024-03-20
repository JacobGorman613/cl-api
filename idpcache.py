import json
import os.path
# set up cache for idp
def set_up_cache():
	if os.path.isfile("idp_cache.json"):
		return False
	else:
		cache = {
        'ng1_datas' : {},
        'ng2_datas' : {},
        'user_ids' : {}
    	}
		with open("idp_cache.json", 'w') as cache_file:
			json.dump(cache, cache_file)
		return True
		
#write to the cache
def write_to_cache(cache):
	if os.path.isfile("idp_cache.json"):
		with open("idp_cache.json", 'w') as cache_file:
			json.dump(cache, cache_file)
		return True
	else:
		return False
	
#access cache
def get_cache():
	if os.path.isfile("idp_cache.json"):
		with open("idp_cache.json") as cache_file:
			cache = json.load(cache_file)
		return cache
	return False

# set up db for idp
def set_up_idp_db():
	if os.path.isfile("idp_db.json"):
		return False
	else:
		idp_db = {
        'primary_cred' : {},
        'sub_cred' : {}
    	}
		with open("idp_db.json", 'w') as db_file:
			json.dump(idp_db, db_file)
		return True
		
#write to the idp db
def write_to_idp_db(idp_db):
	if os.path.isfile("idp_db.json"):
		with open("idp_db.json", 'w') as db_file:
			json.dump(idp_db, db_file)
		return True
	else:
		return False
	
#access idp db
def get_idp_db():
	if os.path.isfile("idp_db.json"):
		with open("idp_db.json") as db_file:
			db = json.load(db_file)
		return db
	return False
