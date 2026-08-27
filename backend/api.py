import gzip
import json

from flask import Flask, request, Blueprint
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter

import lib.connectors.sql as sql
import lib.settings as settings


app = Flask(__name__)
veilance_public_v1 = Blueprint("veilance_public_v1", __name__, url_prefix="/api/v1")
veilance_users_v1 = Blueprint("veilance_users_v1", __name__, url_prefix="/api/users/v1")
veilance_admin_v1 = Blueprint("veilance_admin_v1", __name__, url_prefix="/api/admin/v1")


def default_request_limits():
    try:
        if request.is_json:
             data = request.get_json(force=True, silent=True) or {}
             client_id = data.get("client_id", None)
        else:
            client_id = request.form.get("client_id", None)
    except:
        client_id = None
    use_ip = False
    if client_id is None:
        use_ip = True
    if use_ip:
        return f"ip:{settings.get_client_ip(request, get_remote_address)}"
    else:
        token_hash = settings.get_hash(client_id)
        return f"tok:{token_hash}"


def telemetry_upload_request_limit():
    try:
        _id = request.form.get("client_id", None)
    except:
        _id = None
    use_ip = False
    if _id is None:
        use_ip = True
    if use_ip:
        return f"ip:{settings.get_client_ip(request, get_remote_address)}"
    else:
        return f"client:{_id}"


def parse_telemetry_json(data):
    expected_keys = ('schemaVersion', 'batchId', 'contributorId', 'observations')
    if any(s not in data.keys() for s in list(expected_keys)):
        return False, "Invalid telemetry JSON"
    if len(data.keys()) == 0:
        return False, "Invalid telemetry JSON"
    return True, None


conf = settings.load_conf()
limiter = Limiter(
    app=app,
    key_func=default_request_limits,
    default_limits=["50 per second"],
    storage_uri=f"redis://{conf['redis']['host']}:{conf['redis']['port']}/{conf['redis']['database']}",
    key_prefix="veilance-limiter"
)


@app.errorhandler(429)
def handler_429(_):
    return settings.build_json_report(None, is_error=True, error_string="Hit request rate limit"), 429


@app.errorhandler(Exception)
def handler_exception(error):
    return settings.build_json_report(None, is_error=True, error_string="Internal server error"), 500


@app.route("/", methods=["GET", "POST"])
def public_home():
    return settings.build_json_report({
        "version": settings.VERSION,
        "title": "Veilance Intelligence Network API",
        "documentation_link": "https://github.com/VeilanceApp/Veilance-API",
        "description": "Shared opt-in intelligence network from the Veilance browser extension",
        "install_links": {
            "firefox": None,
            "chromium": "https://chromewebstore.google.com/detail/veilance/jnpdghabfaeceighkogelpmaeplcmddb?hl=en&authuser=2",
            "edge": None
        },
        "status": "online"
    })


@veilance_public_v1.route("/token/check", methods=["POST"])
@veilance_users_v1.route("/token/check", methods=["POST"])
@veilance_admin_v1.route("/token/check", methods=["POST"])
def check_login_token():
    return settings.build_json_report(None, is_error=True, error_string="Endpoint not implemented yet")


@veilance_public_v1.route("/telemetry/ip", methods=["GET"])
def get_client_ip_address():
    try:
        ip_address = settings.get_client_ip(request, get_remote_address)
    except:
        ip_address = "127.0.0.1"
    return settings.build_json_report({
        "ok": True,
        "ip_address": ip_address
    })


@veilance_public_v1.route("/telemetry/upload", methods=["POST"])
@limiter.limit("1000 per day", key_func=telemetry_upload_request_limit)
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


@veilance_users_v1.route("/register", methods=["POST"])
def user_registration():
    return settings.build_json_report(None, is_error=True, error_string="Endpoint not implemented yet")


@veilance_users_v1.route("/login", methods=["POST"])
def user_login():
    return settings.build_json_report(None, is_error=True, error_string="Endpoint not implemented yet")


@veilance_admin_v1.route("/login", methods=["POST"])
def admin_login():
    return settings.build_json_report(None, is_error=True, error_string="Endpoint not implemented yet")


@veilance_admin_v1.route("/payout", methods=["POST"])
def admin_perform_payout():
    return settings.build_json_report(None, is_error=True, error_string="Endpoint not implemented yet")
