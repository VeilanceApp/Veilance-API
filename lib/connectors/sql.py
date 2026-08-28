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


def get_leaderboard():
    conf = settings.load_conf()
    client = get_client()
    db = client[conf['database']['name']]
    collection = db[conf['database']['collections']['telemetry']]
    try:
        pipeline = [
            {
                "$match": {
                    "client_id": {
                        "$ne": None
                    }
                }
            },
            {
                "$group": {
                    "_id": "$client_id",
                    "telemetry_count": {
                        "$sum": 1
                    },
                    "payout_amount": {
                        "$sum": {
                            "$ifNull": ["$payout_amount", 0]
                        }
                    }
                }
            },
            {
                "$sort": {
                    "telemetry_count": -1
                }
            },
            {
                "$limit": 50
            },
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
        return None