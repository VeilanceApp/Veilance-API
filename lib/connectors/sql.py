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
            {"$limit": 50},
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