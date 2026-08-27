import json
import uuid
import hashlib
import ipaddress
import datetime


VERSION = "0.0.1"


def load_conf():
    return json.load(open("conf.json"))


def build_id(**kwargs):
    is_req_id = kwargs.get("is_req_id", False)
    is_error_id = kwargs.get("is_error_id", False)
    is_telemetry_id = kwargs.get("is_telemetry_id", False)

    if is_req_id:
        template = "req-"
    elif is_error_id:
        template = "err-"
    elif is_telemetry_id:
        template = "tlm-"
    else:
        template = "vln-"
    return f"{template}{uuid.uuid4()}"


def build_json_report(output, **kwargs):
    is_error = kwargs.get("is_error", False)
    error_string = kwargs.get("error_string", None)

    report = {
        "metadata": {
            "timestamp": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            "request_id": build_id(is_req_id=True)
        }
    }
    if is_error:
        if error_string is None:
            error_string = "Unexpected error occurred, no details provided to the backend"
        report["error"] = {
            "error_id": build_id(is_error_id=True),
            "error_string": error_string
        }
    else:
        report["error"] = {}
    if output is None:
        report["output"] = {}
    else:
        report["output"] = output
    return report


def get_hash(s):
    h = hashlib.sha3_256()
    h.update(s.encode("utf-8"))
    return h.hexdigest()


def is_valid_ip(value):
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except:
        return False


def normalize_ip_value(value):
    if not value:
        return None
    value = value.strip()
    if value.startswith('[') and value.endswith(']'):
        value = value[1:-1]
    if is_valid_ip(value):
        return value
    return None


def valid_from_csv(value, delim=","):
    if not value:
        return None
    for item in value.split(delim):
        ip = normalize_ip_value(item)
        if ip:
            return ip
    return None


def get_client_ip(req, fallback_func):
    cf_headers = (
        "CF-Connecting-IP",
        "True-Client-IP",
        "CF-Pseudo-IPv4"
    )
    single_ip_headers = (
        "X-Real-IP",
        "X-Client-IP",
        "X-Forwarded",
        "Forwarded-For",
        "X-Cluster-Client-IP",
        "Fastly-Client-IP",
        "Fly-Client-IP",
        "X-Appengine-User-IP",
        "X-Azure-ClientIP",
        "X-Original-Forwarded-For",
    )
    for header in cf_headers:
        ip = normalize_ip_value(req.headers.get(header))
        if ip:
            return ip
    for header in single_ip_headers:
        ip = normalize_ip_value(req.headers.get(header))
        if ip:
            return ip
    forwarded = req.headers.get("Forwarded")
    ip = valid_from_csv(forwarded, delim=";")
    if ip:
        return ip
    ip = valid_from_csv(req.headers.get("X-Forwarded-For"), delim=",")
    if ip:
       return ip
    ip = normalize_ip_value(req.remote_addr)
    if ip:
        return ip
    ip = normalize_ip_value(fallback_func())
    if ip:
        return ip
    return None
