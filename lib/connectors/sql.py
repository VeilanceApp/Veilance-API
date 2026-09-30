import re
import datetime

import pymongo
from mongo_secure.sanitizer import sanitize

import lib.settings as settings


def get_client():
    conf = settings.load_conf()
    database_conf = conf['database']
    connection_string = (
        f"mongodb://{database_conf['username']}:{database_conf['password']}@"
        f"{database_conf['host']}:{database_conf['port']}/{database_conf['name']}"
        f"?authSource=admin"
    )
    client = pymongo.MongoClient(connection_string)
    try:
        _ = client[database_conf['name']]
        return client
    except:
        return None

@sanitize("user_id", "wallet_address", "eligible", "balance_raw", "decimals", "checked_at", "slot")
def update_user_holder_access(user_id, wallet_address, eligible, balance_raw, decimals, checked_at, slot):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['holder_access']]
    try:
        collection.insert_one({
            "added_on": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            "user_id": user_id,
            "wallet_address": wallet_address,
            "is_eligible": eligible,
            "raw_balance": balance_raw,
            "decimals": decimals,
            "checked_at": checked_at,
            "slot": slot
        })
        return True
    except:
        return False


@sanitize("id_")
def insert_stripe_id(id_):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['stripe']]
    try:
        collection.insert_one({
            "stripe_id": id_,
            "inserted_at": datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
        })
    except:
        pass


@sanitize("id_")
def find_stripe_id(id_):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['stripe']]
    try:
        results = collection.find_one({"stripe_id": id_})
        return results
    except:
        return None


@sanitize("email", "password_hash", "salt", "password_rounds", "user_id", "verification_code", "expiration_time")
def register_user(email, password_hash, salt, password_rounds, user_id, verification_code, expiration_time):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['users']]
    try:
        collection.insert_one({
            "user_id": user_id,
            "email": email,
            "password_hash": password_hash,
            "password_salt": salt,
            "password_rounds": password_rounds,
            "registration_time": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            "enabled_account": True,
            "verified_account": False,
            "verification_code": {
                "code": verification_code,
                "expiration_time": expiration_time
            },
            "plan": "free",
            "api_key": None
        })
        return True
    except:
        return False


@sanitize("user_id", "wallet_address")
def save_wallet_address_verification(user_id, wallet_address):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['users']]
    try:
        results = collection.update_one(
            {"user_id": user_id},
            {"$set": {"holder_wallet_address": wallet_address}}
        )
        return results.modified_count == 1
    except:
        return False


@sanitize("user_id", "api_key")
def update_user_api_key(user_id, api_key):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['users']]
    try:
        results = collection.update_one(
            {"user_id": user_id},
            {"$set": {"api_key": api_key}}
        )
        return results.modified_count == 1
    except:
        return False


@sanitize("email", "plan_name")
def update_user_plan_by_email(email, plan_name):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['users']]
    try:
        results = collection.update_one(
            {"email": email},
            {"$set": {"plan": plan_name.lower()}}
        )
        return results.modified_count == 1
    except:
        return False


@sanitize("stripe_id", "user_id")
def update_user_stripe_id(stripe_id, user_id):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['users']]
    try:
        results = collection.update_one(
            {"user_id": user_id},
            {"$set": {"stripe_id": stripe_id}}
        )
        return results.modified_count == 1
    except:
        return False


@sanitize("user_id")
def find_stripe_id_by_user_id(user_id):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['users']]
    try:
        results = collection.find_one({"user_id": user_id})
        return results['stripe_id']
    except:
        return None


@sanitize("user_id")
def verify_user(user_id):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['users']]
    try:
        results = collection.update_one(
            {"user_id": user_id},
            {"$set": {"verified_account": True, "verification_code": {"code": None, "expiration_time": None}}}
        )
        return results.modified_count == 1
    except:
        return False



@sanitize("user_id")
def find_user_by_user_id(user_id):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['users']]
    try:
        return collection.find_one({"user_id": user_id})
    except:
        return None


@sanitize("email")
def find_user_by_email(email):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['users']]
    try:
        results = collection.find_one({"email": email})
        return results
    except:
        return None


@sanitize("payload", "domain_url", "privacy_policy_link")
def insert_privacy_policy_analysis(payload, domain_url, privacy_policy_link):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['privacy_policies']]
    try:
        collection.insert_one({
            "policy_id": settings.build_id(is_privacy_policy_analysis=True),
            "inserted_at": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            "policy_raw_results": payload,
            "associated_domain": domain_url,
            "associated_policy_link": privacy_policy_link,
        })
    except:
        pass


@sanitize("domain")
def find_newest_telemetry_by_domain(domain, **kwargs):
    remove_args = kwargs.get("remove_args", False)
    search_limit = kwargs.get("search_limit", 5)

    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['telemetry']]
    try:
        domain = domain.strip().lower().rstrip(".")
        escaped_domain = re.escape(domain)
        results = collection.find({
            "raw_json_string.observations.site.hostname": {
                "$regex": rf"^(?:.+\.)?{escaped_domain}$",
                "$options": "i"
            }
        }).sort("_id", -1).limit(search_limit)
        if remove_args:
            retval = []
            for item in results:
                ip_address = item['uploaded_from']
                uploaded_on = item['uploaded_on']
                ip_location = settings.find_ip_location(ip_address)
                data = item['raw_json_string']
                del data['contributorId']
                data['uploaded_from'] = ip_location
                data['uploaded_on'] = uploaded_on
                retval.append(data)
            results = retval
        return results
    except:
        import traceback
        traceback.print_exc()
        return None


@sanitize("dedupe_key")
def find_telemetry_by_deduplication_key(dedupe_key):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['telemetry']]
    try:
        results = collection.find_one({
            "deduplication_key": dedupe_key
        })
        return results
    except:
        return None


@sanitize("ip_address", "raw_json", "client_id", "wallet_address", "deduplication_key")
def upload_telemetry(ip_address, raw_json, client_id, wallet_address, deduplication_key):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['telemetry']]
    try:
        collection.insert_one({
            "telemetry_id": settings.build_id(is_telemetry_id=True),
            "raw_json_string": raw_json,
            "uploaded_from": ip_address,
            "uploaded_on": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            "is_accepted": False,
            "accepted_on": None,
            "payout_amount": None,
            "rejected_reason": None,
            "rejected_on": None,
            "is_rejected": False,
            "client_id": client_id,
            "wallet_address": wallet_address,
            "deduplication_key": deduplication_key
        })
        return True
    except:
        return False


@sanitize("telemetry_id", "payout_amount")
def accept_telemetry(telemetry_id, payout_amount):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['telemetry']]
    try:
        _filter = {"telemetry_id": telemetry_id}
        update = {
            "$set": {
                "is_accepted": True,
                "accepted_on": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
                "payout_amount": payout_amount,
            }
        }
        result = collection.update_one(_filter, update)
        return result.modified_count == 1
    except:
        return False


@sanitize("telemetry_id", "rejected_reasoning")
def deny_telemetry(telemetry_id, rejected_reasoning):
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['telemetry']]
    try:
        _filter = {"telemetry_id": telemetry_id}
        update = {
            "$set": {
                "rejected_on": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
                "rejected_reason": rejected_reasoning,
                "is_rejected": True
            }
        }
        result = collection.update_one(_filter, update)
        return result.modified_count == 1
    except:
        return False


def get_all_active_telemetry():
    conf = settings.load_conf()
    client = get_client()
    db = client[conf["database"]["name"]]
    collection = db[conf["database"]["collections"]["telemetry"]]
    try:
        return list(
            collection.find(
                {
                    "is_accepted": False,
                    "is_rejected": False
                },
                {
                    "_id": 0,
                    "uploaded_from": 0,
                    "deduplication_key": 0
                }
            ).sort("uploaded_on", 1)
        )
    except Exception:
        return []


def get_leaderboard():
    conf = settings.load_conf()
    client = get_client()
    db = client[conf["database"]["name"]]
    collection = db[conf["database"]["collections"]["telemetry"]]
    try:
        pipeline = [
            {
                "$match": {
                    "client_id": {"$ne": None}
                }
            },
            {
                "$group": {
                    "_id": "$client_id",
                    "telemetry_count": {"$sum": 1},
                    "payout_amount": {
                        "$sum": {
                            "$convert": {
                                "input": "$payout_amount",
                                "to": "double",
                                "onError": 0,
                                "onNull": 0
                            }
                        }
                    }
                }
            },
            {
                "$sort": {
                    "telemetry_count": -1
                }
            },
            {"$limit": 25},
            {
                "$project": {
                    "_id": 0,
                    "client_id": "$_id",
                    "telemetry_count": 1,
                    "payout_amount": 1
                }
            }
        ]
        results = list(collection.aggregate(pipeline))
        for rank, item in enumerate(results, start=1):
            item["rank"] = rank
        return results
    except:
        return []