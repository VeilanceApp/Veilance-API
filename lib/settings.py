import base64
import json
import os
import random
import uuid
import hashlib
import ipaddress
import datetime
import string

import geoip2.errors
import geoip2.database

from dns.resolver import query
from email.utils import parseaddr

from itsdangerous import URLSafeTimedSerializer


VERSION = "1.0"
PRIVACY_POLICY_PROMPT = f"{os.getcwd()}{os.path.sep}data{os.path.sep}prompts{os.path.sep}privacy_policy.prompt"
VERITY_CHAT_PROMPT = f"{os.getcwd()}{os.path.sep}data{os.path.sep}prompts{os.path.sep}verity_chat.prompt"
MAIL_TEMPLATES = {
    "welcome": f"{os.getcwd()}{os.path.sep}data{os.path.sep}templates{os.path.sep}emails{os.path.sep}welcome.template",
    "verification": f"{os.getcwd()}{os.path.sep}data{os.path.sep}templates{os.path.sep}emails{os.path.sep}verify.template",
    "upgrade": f"{os.getcwd()}{os.path.sep}data{os.path.sep}templates{os.path.sep}emails{os.path.sep}upgrade.template",
}
BAD_PASSWORDS_LIST = f"{os.getcwd()}{os.path.sep}data{os.path.sep}databases{os.path.sep}bad_passwords.lst"
TELEMETRY_BLACKLIST = f"{os.getcwd()}{os.path.sep}data{os.path.sep}databases{os.path.sep}telemetry_blacklist.json"
GEO2LITE_COUNTRY_DATABASE = f"{os.getcwd()}{os.path.sep}data{os.path.sep}databases{os.path.sep}GeoLite2-City.mmdb"


def load_conf():
    return json.load(open("conf.json"))


def build_id(**kwargs):
    is_req_id = kwargs.get("is_req_id", False)
    is_error_id = kwargs.get("is_error_id", False)
    is_telemetry_id = kwargs.get("is_telemetry_id", False)
    is_domain_sighting = kwargs.get("is_domain_sighting", False)
    is_privacy_policy_analysis = kwargs.get("is_privacy_policy_analysis", False)
    is_user_id = kwargs.get("is_user_id", False)

    if is_req_id:
        template = "req-"
    elif is_error_id:
        template = "err-"
    elif is_telemetry_id:
        template = "tlm-"
    elif is_domain_sighting:
        template = "dmn-"
    elif is_privacy_policy_analysis:
        template = "ppa-"
    elif is_user_id:
        template = "usr-"
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


def make_admin_serial():
    secret = load_conf()['user_config']['admin_secret']
    return URLSafeTimedSerializer(secret)


def make_user_serial():
    secret = load_conf()['user_config']['user_secret']
    return URLSafeTimedSerializer(secret)


def create_user_token(username, is_admin=False):
    if not is_admin:
        serializer = make_user_serial()
    else:
        serializer = make_admin_serial()
    return serializer.dumps({"token": username})


def verify_token(token, is_admin=False):
    try:
        if not is_admin:
            serial = make_user_serial()
            max_age = load_conf()['user_config']['user_max_age']
            data = serial.loads(token, max_age=max_age)
            return data['token']
        else:
            serial = make_admin_serial()
            max_age = load_conf()['user_config']['admin_max_age']
            data = serial.loads(token, max_age=max_age)
            return data['token']
    except:
        return None


def generate_password_salt():
    length = random.SystemRandom().randint(21, 43)
    return os.urandom(length)


def encrypt_password(password_str, rounds=None, salt=None):
    if salt is None:
        salt = generate_password_salt()
        salt = base64.b64encode(salt)
    if rounds is None:
        rounds = random.SystemRandom().randint(30000, 50000)
    if not isinstance(salt, bytes):
        salt = salt.encode()
    h = hashlib.pbkdf2_hmac("sha256", password_str.encode(), salt, rounds)
    return h.hex(), salt, rounds


def verify_password_complexity(sent_password):
    needed = {
        "digits": {
            "charset": string.digits,
            "found": 0
        },
        "punctuation": {
            "charset": string.punctuation,
            "found": 0
        },
        "lowercase": {
            "charset": string.ascii_lowercase,
            "found": 0
        },
        "uppercase": {
            "charset": string.ascii_uppercase,
            "found": 0
        }
    }
    if not (8 <= len(sent_password) <= 48):
        return False, "Password must be between 8 and 48 characters"
    for char in sent_password:
        for key in needed.keys():
            if char in needed[key]["charset"]:
                needed[key]["found"] += 1
    for key in needed.keys():
        if needed[key]["found"] == 0:
            return False, f"Missing at least 1 {key} character"
    data = open(BAD_PASSWORDS_LIST).readlines()
    for bad_password in data:
        bad_password = bad_password.strip()
        if bad_password == sent_password:
            return False, "Password in list of known bad passwords"
    return True, None


def verify_email_address(address):
    skip_schema = ("veilance.org", "perkinsfund.org", "securelegion.org")
    try:
        if "@" not in address:
            return False
        for item in list(skip_schema):
            if item in address.lower():
                return False
        parsed = parseaddr(address)
        if parsed == ('', ''):
            return False
        domain = address.split("@")[-1]
        return bool(query(domain, "MX"))
    except:
        return False


def build_verification_code():
    alpha = string.ascii_uppercase + string.ascii_lowercase + string.digits
    length = 10
    code = []
    for _ in range(length):
        code.append(random.SystemRandom().choice(alpha))
    expiration_time = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours=3)
    return "".join(code), expiration_time.isoformat()


def load_blacklist():
    return json.load(open(TELEMETRY_BLACKLIST))


def timestamp_to_iso(timestamp):
    if timestamp is None:
        return None
    else:
        return datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).isoformat()


def correlate_requested_item_to_real_id(requested_item):
    if requested_item is None:
        return None
    conf = load_conf()
    products = conf['stripe']['products']
    if requested_item.lower() not in [item.lower() for item in products.keys()]:
        return None
    else:
        return products[requested_item.lower()]


def find_ip_location(ip):
    try:
        with geoip2.database.Reader(GEO2LITE_COUNTRY_DATABASE) as reader:
            response = reader.city(ip)
            return response.country.name
    except Exception:
        return "Unknown"


def create_api_key():
    chars = string.printable
    length = random.SystemRandom().randint(12, 27)
    string_ = []
    for _ in range(length):
        string_.append(random.SystemRandom().choice(chars))
    key_addition = str(uuid.uuid4())
    key = f"{''.join(string_)}-{key_addition}"
    secure_key = get_hash(key)
    return secure_key
