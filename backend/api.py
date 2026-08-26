import gzip
import json

from flask import Flask, request, Blueprint
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter

import lib.connectors.sql as sql
import lib.settings as settings


app = Flask(__name__)
veilance_v1 = Blueprint("veilance_v1", __name__, url_prefix="/api/v1")


def parse_telemetry_json(data):
    expected_keys = ('schemaVersion', 'batchId', 'contributorId', 'observations')
    if any(s not in data.keys() for s in list(expected_keys)):
        return False, "Invalid telemetry JSON"
    if len(data.keys()) == 0:
        return False, "Invalid telemetry JSON"
    return True, None


@veilance_v1.route("/telemetry/ip", methods=["GET"])
def get_client_ip_address():
    try:
        ip_address = settings.get_client_ip(request, get_remote_address)
    except:
        ip_address = "127.0.0.1"
    return settings.build_json_report({
        "ok": True,
        "ip_address": ip_address
    })


@veilance_v1.route("/telemetry/upload", methods=["POST"])
def upload_telemetry():
    ip_address = request.form.get("ip_address")
    telemetry_file = request.files.get("telemetry")
    client_id = request.form.get("client_id")
    wallet_address = request.form.get("wallet_address", None)
    domain_name = request.form.get("domain_name", None)

    if telemetry_file is None:
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="Invalid telemetry data provided"
        )
    compressed_data = telemetry_file.read()
    if not compressed_data:
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="Invalid telemetry data provided"
        )
    try:
        data = gzip.decompress(compressed_data)
    except (gzip.BadGzipFile, EOFError, OSError):
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="Telemetry data should be gzip compatible during upload"
        )
    try:
        raw_telemetry_data = json.loads(data)
    except:
        return settings.build_json_report(None, is_error=True, error_string="Telemetry data should safely convert to JSON")
    good_json, error = parse_telemetry_json(raw_telemetry_data)
    if not good_json:
        return settings.build_json_report(None, is_error=True, error_string=error)
    if wallet_address is None:
        return settings.build_json_report(None, is_error=True, error_string="Wallet address cannot be empty")
    if domain_name is None:
        return settings.build_json_report(None, is_error=True, error_string="Domain name cannot be empty")
    dedupe_key = settings.get_hash(domain_name)
    exists = sql.find_telemetry_by_deduplication_key(dedupe_key)
    if exists is not None:
        return settings.build_json_report(None, is_error=True, error_string="This telemetry data has already been uploaded")
    is_inserted = sql.upload_telemetry(ip_address, raw_telemetry_data, client_id, wallet_address, dedupe_key)
    if is_inserted:
        return settings.build_json_report({
            "ok": True
        })
    else:
        return settings.build_json_report(None, is_error=True, error_string="Unable to upload telemetry data")
