import json
import os.path
# install pyyaml
import yaml

def env_constructor(loader, node):
    value = loader.construct_scalar(node)
    return os.getenv(value, f"DEFAULT_{value}") # Optional default value

# TODO: Make this run when the file gets imported
if __name__ == "__main__":
	yaml.SafeLoader.add_constructor('!env', env_constructor)
	with open('env.yaml', 'r') as f:
		config = yaml.safe_load(f)
		idp_cache_file = os.path.join(config["IDP_CACHE_DIR"], "idp_cache.json")
		print(idp_cache_file)

# set up cache for idp
def set_up_cache():
	if os.path.isfile(idp_cache_file):
		return False
	else:
		cache = {
        'ng1_datas' : {},
        'ng2_datas' : {},
        'user_ids' : {}
    	}
		with open(idp_cache_file, 'w') as cache_file:
			json.dump(cache, cache_file)
		return True
		
#write to the cache
def write_to_cache(cache):
	if os.path.isfile(idp_cache_file):
		with open(idp_cache_file, 'w') as cache_file:
			json.dump(cache, cache_file)
		return True
	else:
		return False
	
#access cache
def get_cache():
	if os.path.isfile(idp_cache_file):
		with open(idp_cache_file) as cache_file:
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
