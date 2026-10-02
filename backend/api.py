import re
import datetime
import gzip
import json
import secrets
import binascii
import base64

import base58
import requests

from redis import Redis
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from flask import Flask, request, Blueprint, Response, stream_with_context
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
from celery.result import AsyncResult
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt

import lib.connectors.emails as emails
import lib.connectors.sql as sql
import lib.settings as settings
import lib.tasks.background as background
import lib.connectors.chatgpt as chatgpt
import lib.connectors.stripe_conn as stripe_conn


stripe_connect = stripe_conn
conf = settings.load_conf()
redis_wallet_challenges = Redis(
    host=conf['redis']['host'],
    port=conf['redis']['port'],
    db=conf['redis']['wallet_db'],
    decode_responses=True
)
vlnc_mint = conf['verification']['address']
vlnc_holder_threshold = conf['verification']['threshold']
solana_rpc_url = conf['verification']['rpc_url']

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = conf['user_config']['user_secret']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=conf['user_config']['user_min_age'])
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=conf['user_config']['user_max_age'])

jwt = JWTManager(app)

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


def validate_user_token(token, is_admin=False):
    good_token = settings.verify_token(token, is_admin=is_admin)
    if good_token is None:
        return False, "Invalid token"
    else:
        return True, None


def wallet_error(message):
    return settings.build_json_report(None, is_error=True, error_string=message)


def wallet_rate_limit():
    return f"wallet-user:{get_jwt_identity()}"


def check_vlnc_holder(wallet_address):
    try:
        response = requests.post(
            solana_rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTokenAccountsByOwner",
                "params": [
                    wallet_address,
                    {"mint": vlnc_mint},
                    {
                        "encoding": "jsonParsed",
                        "commitment": "finalized",
                    },
                ],
            },
            timeout=(5, 15),
        )
        response.raise_for_status()
        payload = response.json()

        if payload.get("error"):
            raise ValueError("RPC returned an error")

        result = payload["result"]
        accounts = result["value"]
        slot = result["context"]["slot"]

        if not isinstance(accounts, list):
            raise ValueError("Invalid token accounts response")

        total_raw = 0
        decimals = None
        seen = set()

        for item in accounts:
            token_account = item["pubkey"]
            if token_account in seen:
                raise ValueError("Duplicate token account")
            seen.add(token_account)

            info = item["account"]["data"]["parsed"]["info"]

            if (
                info["mint"] != vlnc_mint
                or info["owner"] != wallet_address
            ):
                raise ValueError("Unexpected token account")

            amount = info["tokenAmount"]
            account_decimals = amount["decimals"]
            raw_amount = amount["amount"]

            if (
                type(account_decimals) is not int
                or not 0 <= account_decimals <= 255
                or not isinstance(raw_amount, str)
                or not re.fullmatch(r"[0-9]{1,20}", raw_amount)
            ):
                raise ValueError("Invalid token balance")

            if decimals is None:
                decimals = account_decimals
            elif decimals != account_decimals:
                raise ValueError("Inconsistent token decimals")

            total_raw += int(raw_amount)

        eligible = (
            decimals is not None
            and total_raw >= vlnc_holder_threshold * (10 ** decimals)
        )

        return {
            "eligible": eligible,
            "balance_raw": str(total_raw),
            "decimals": decimals,
            "slot": slot,
            "checked_at": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
        }

    except (requests.RequestException, ValueError, KeyError, TypeError):
        raise RuntimeError("Unable to check VLNC holdings") from None


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
    import traceback
    traceback.print_exc()
    return settings.build_json_report(None, is_error=True, error_string="Internal server error"), 500


@app.route("/", methods=["GET", "POST"])
def public_home():
    return settings.build_json_report({
        "version": settings.VERSION,
        "title": "Veilance Intelligence Network API",
        "documentation_link": "https://github.com/VeilanceApp/Veilance-API",
        "description": "Shared opt-in intelligence network from the Veilance browser extension",
        "install_links": {
            "firefox": "https://addons.mozilla.org/en-US/firefox/addon/veilance/",
            "chromium": "https://chromewebstore.google.com/detail/veilance/jnpdghabfaeceighkogelpmaeplcmddb?hl=en&authuser=2",
            "edge": "https://microsoftedge.microsoft.com/addons/detail/veilance/bjkaboijedghpmalbcdbodeifdlilfgg"
        },
        "status": "online"
    })


@veilance_public_v1.route("/products", methods=["GET"])
@limiter.limit("5 per second")
def get_products():
    return stripe_conn.get_product()


@veilance_public_v1.route("/token/check", methods=["POST"])
@veilance_users_v1.route("/token/check", methods=["POST"])
@veilance_admin_v1.route("/token/check", methods=["POST"])
def check_login_token():
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token")
    if "admin" in request.path:
        admin = True
    else:
        admin = False
    good_token, error = validate_user_token(token, is_admin=admin)
    if not good_token:
        return settings.build_json_report(None, is_error=True, error_string=error)
    else:
        return settings.build_json_report({"ok": True})


@veilance_public_v1.route("/status", methods=["POST"])
@veilance_users_v1.route("/status", methods=["POST"])
def check_status():
    data = request.get_json(force=True, silent=True) or {}
    uuid_ = data.get("uuid", None)
    if uuid_ is None:
        return settings.build_json_report(None, is_error=True, error_string="UUID is required")
    queue = AsyncResult(uuid_, app=background.app)
    status = queue.status
    if queue.ready():
        retval = queue.result
        queue.forget()
        if not isinstance(retval, dict):
            retval = {"output": retval}
        return settings.build_json_report(retval)
    else:
        return settings.build_json_report({"status": status, "uuid": uuid_})


@veilance_public_v1.route("/leaderboard", methods=["GET"])
@limiter.limit("3 per second")
def veilance_telemetry_leaderboard():
    results = sql.get_leaderboard()
    if results is None:
        return settings.build_json_report(None, is_error=True, error_string="No leaderboard data found")
    for item in results:
        client_id = item['client_id']
        # redact the client_id from public view
        client_id = f"{client_id[0:5]}*****{client_id[-5:-1]}"
        del item['client_id']
        item['client_id'] = client_id
    return settings.build_json_report(results)


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
    # exists = sql.find_telemetry_by_deduplication_key(dedupe_key)
    exists = None
    if exists is not None:
        return settings.build_json_report(None, is_error=True, error_string="This telemetry data has already been uploaded")
    is_inserted = sql.upload_telemetry(ip_address, raw_telemetry_data, client_id, wallet_address, dedupe_key)
    if is_inserted:
        return settings.build_json_report({
            "ok": True
        })
    else:
        return settings.build_json_report(None, is_error=True, error_string="Unable to upload telemetry data")


@veilance_public_v1.route("/intel/domain/<domain>", methods=["GET"])
def get_free_domain_intel(domain):
    return settings.build_json_report(None, is_error=True, error_string="Endpoint not implemented yet")


@veilance_users_v1.route("/wallet/verify", methods=["POST"])
@jwt_required()
@limiter.limit("10 per minute", key_func=wallet_rate_limit)
def wallet_verification():
    user_id = get_jwt_identity()
    user = sql.find_user_by_user_id(user_id)

    if user is None:
        return wallet_error("User not found", 401)

    if not user["enabled_account"]:
        return wallet_error("Account is disabled", 403)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return wallet_error("Invalid JSON body")

    challenge_id = data.get("challenge_id")
    signature_b64 = data.get("signature")

    if (
            not isinstance(challenge_id, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge_id)
            or not isinstance(signature_b64, str)
            or len(signature_b64) != 88
    ):
        return wallet_error("Invalid wallet proof")

    challenge_key = f"veilance:wallet-link:{user_id}"
    stored = redis_wallet_challenges.get(challenge_key)

    if stored is None:
        return wallet_error("Challenge expired or already used. Connect again.")

    try:
        challenge = json.loads(stored)
        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = datetime.datetime.fromisoformat(
            challenge["expires_at"]
        )

        if (
                challenge["purpose"] != "holding_verification"
                or challenge["user_id"] != user_id
                or challenge["challenge_id"] != challenge_id
                or expires_at <= now
        ):
            raise ValueError("Challenge mismatch")

        signature = base64.b64decode(signature_b64, validate=True)
        if len(signature) != 64:
            raise ValueError("Invalid signature length")

        wallet_address = challenge["wallet_address"]
        public_key = base58.b58decode(wallet_address)

        VerifyKey(public_key).verify(
            challenge["message"].encode("utf-8"),
            signature,
        )

    except (
            ValueError,
            TypeError,
            KeyError,
            binascii.Error,
            BadSignatureError,
    ):
        import traceback
        traceback.print_exc()
        return wallet_error("Wallet verification failed. Connect again.")
    consumed = redis_wallet_challenges.eval(
        """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        end
        return 0
        """,
        1,
        challenge_key,
        stored,
    )

    if consumed != 1:
        return wallet_error("Challenge expired or already used. Connect again.")

    verified_at = now.isoformat()

    saved = sql.save_wallet_address_verification(user_id, wallet_address)

    if not saved:
        return wallet_error("Unable to link this wallet. Connect again to retry.")
    try:
        holder = check_vlnc_holder(wallet_address)
    except RuntimeError:
        return settings.build_json_report({
            "ok": True,
            "wallet_address": wallet_address,
            "wallet_verified": True,
            "wallet_verified_at": verified_at,
            "holder_check": "pending",
            "message": (
                "Wallet verified, but token holdings could not be checked. "
                "Holder access has not been granted by this request."
            ),
        })

    updated = sql.update_user_holder_access(
        user_id=user_id,
        wallet_address=wallet_address,
        eligible=holder["eligible"],
        balance_raw=holder["balance_raw"],
        decimals=holder["decimals"],
        checked_at=holder["checked_at"],
        slot=holder["slot"],
    )

    if not updated:
        return wallet_error(
            "Wallet verified, but holder access could not be updated. Retry."
        )
    is_updated = sql.update_user_plan_by_email(user['email'], "holder")

    if is_updated:
        return settings.build_json_report({
            "ok": True,
            "wallet_address": wallet_address,
            "wallet_verified": True,
            "wallet_verified_at": verified_at,
            "holder_check": "complete",
            "holder_eligible": holder["eligible"],
            "required_tokens": vlnc_holder_threshold,
            "balance_raw": holder["balance_raw"],
            "decimals": holder["decimals"],
        })
    else:
        return settings.build_json_report({
            "ok": False,
            "wallet_address": wallet_address,
            "wallet_verified": False,
            "wallet_verified_at": verified_at,
            "holder_check": "complete",
            "holder_eligible": holder["eligible"],
            "required_tokens": vlnc_holder_threshold,
            "balance_raw": holder["balance_raw"],
            "decimals": holder["decimals"],
        })


@veilance_users_v1.route("/wallet/challenge", methods=["POST"])
@jwt_required()
@limiter.limit("10 per minute", key_func=wallet_rate_limit)
def wallet_challenge():
    user_id = get_jwt_identity()
    user = sql.find_user_by_user_id(user_id)
    if user is None:
        return wallet_error("User not found")
    if not user["enabled_account"]:
        return wallet_error("Account is disabled")
    if not user['verified_account']:
        return wallet_error("Account is not verified")
    data = request.get_json(silent=True, force=True)
    if not isinstance(data, dict):
        return wallet_error("Invalid JSON body")
    wallet_address = data.get("wallet_address", None)
    if wallet_address is None:
        return wallet_error("No wallet address provided")
    try:
        if not 32 <= len(wallet_address) <= 44:
            raise ValueError()
        public_key = base58.b58decode(wallet_address.encode())
        if len(public_key) != 32 or base58.b58encode(public_key).decode("ascii") != wallet_address:
            raise ValueError()
    except ValueError:
        return wallet_error("Invalid Solana wallet address")
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    expires_at = now + datetime.timedelta(seconds=4500)
    challenge_id = secrets.token_urlsafe(32)
    message = (
        "Link your Solana wallet to your Veilance account\n\n"
        "Domain: veilance.org\n"
        "URI: https://veilance.org\n"
        f"Account: {user_id}\n"
        f"Wallet: {wallet_address}\n"
        f"Purpose: Verify wallet holdings for premium Veilance access\n"
        f"This replaces any wallet currently linked to this account.\n"
        "This does not authorize a payment or transaction.\n\n"
        f"Nonce: {challenge_id}\n"
        f"Issued at: {now.isoformat()}\n"
        f"Expiration time: {expires_at.isoformat()}"
    )
    challenge = {
        "challenge_id": challenge_id,
        "purpose": "holding_verification",
        "user_id": user_id,
        "wallet_address": wallet_address,
        "message": message,
        "expires_at": expires_at.isoformat()
    }
    redis_wallet_challenges.set(
        f"veilance:wallet-link:{user_id}",
        json.dumps(challenge),
        ex=4500
    )
    return settings.build_json_report({
        "challenge_id": challenge_id,
        "wallet_address": wallet_address,
        "message": message,
        "expires_at": challenge["expires_at"],
    })


@veilance_users_v1.route("/whoami", methods=["POST"])
@jwt_required()
def get_user_info():
    user_id = get_jwt_identity()
    user_exists = sql.find_user_by_user_id(user_id)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="User not found")
    return settings.build_json_report({
        "user_id": user_exists["user_id"],
        "email_address": user_exists["email"],
        "verified": user_exists["verified_account"],
        "enabled_account": user_exists["enabled_account"],
        "plan": user_exists["plan"]
    })


@veilance_users_v1.route("/register", methods=["POST"])
def user_registration():
    data = request.get_json(silent=True, force=True) or {}
    email_address = data.get("email_address", None)
    password = data.get("password", None)

    if email_address is None or password is None:
        return settings.build_json_report(None, is_error=True, error_string="Email address and password are required")
    is_valid, error_string = settings.verify_password_complexity(password)
    if not is_valid:
        return settings.build_json_report(None, is_error=True, error_string=error_string)
    good_email = settings.verify_email_address(email_address)
    if not good_email:
        return settings.build_json_report(None, is_error=True, error_string="Invalid email address")
    user_exists = sql.find_user_by_email(email_address)
    if user_exists is not None:
        return settings.build_json_report(None, is_error=True, error_string="Unable to register user")
    password_hash, password_salt, password_rounds = settings.encrypt_password(password)
    user_id = settings.build_id(is_user_id=True)
    verification_code, expiration_time = settings.build_verification_code()
    is_inserted = sql.register_user(
        email_address, password_hash,
        password_salt, password_rounds,
        user_id, verification_code,
        expiration_time
    )
    if not is_inserted:
        return settings.build_json_report(None, is_error=True, error_string="Unable to register user")
    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token(user_id)
    emails.send_verification_code_email(verification_code, email_address, expiration_time)
    return settings.build_json_report({
        "ok": True,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "is_enabled": True,
            "is_verified": False,
            "plan": "free"
        }
    })


@veilance_users_v1.route("/verify", methods=["POST"])
def verify_user():
    data = request.get_json(silent=True, force=True) or {}
    email_address = data.get("email_address", None)
    sent_code = data.get("verification_code", None)
    if email_address is None or sent_code is None:
        return settings.build_json_report(None, is_error=True, error_string="Email address and verification code are required")
    user_exists = sql.find_user_by_email(email_address)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="Unable to verify user account")
    if user_exists['verified_account']:
        return settings.build_json_report(None, is_error=True, error_string="Unable to verify user account")
    verification_data = user_exists['verification_code']
    current_time = datetime.datetime.now(tz=datetime.timezone.utc)
    stored_time = datetime.datetime.fromisoformat(verification_data['expiration_time'].replace("Z", "+00:00"))
    if current_time > stored_time:
        return settings.build_json_report(None, is_error=True, error_string="Unable to verify user, please contact support contact@veilance.org")
    if sent_code != verification_data['code']:
        return settings.build_json_report(None, is_error=True, error_string="Invalid verification code")
    verified = sql.verify_user(user_exists['user_id'])
    if verified:
        return settings.build_json_report({"ok": True})
    else:
        return settings.build_json_report(None, is_error=True, error_string="Unable to verify user account")


@veilance_users_v1.route("/login", methods=["POST"])
def login_user():
    data = request.get_json(silent=True, force=True) or {}
    email_address = data.get("email_address", None)
    password = data.get("password", None)

    if email_address is None or password is None:
        return settings.build_json_report(None, is_error=True, error_string="Missing email address or password")
    user_data = sql.find_user_by_email(email_address)
    if user_data is None:
        return settings.build_json_report(None, is_error=True, error_string="User not found")
    sent_password_hash, _, _ = settings.encrypt_password(password, rounds=user_data['password_rounds'], salt=user_data['password_salt'])
    if sent_password_hash != user_data['password_hash']:
        return settings.build_json_report(None, is_error=True, error_string="User not found")
    access_token = create_access_token(user_data['user_id'])
    refresh_token = create_refresh_token(user_data['user_id'])
    return settings.build_json_report({
        "ok": True,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "is_enabled": user_data['enabled_account'],
            "is_verified": user_data['verified_account'],
            "plan": user_data['plan']
        }
    })


@veilance_users_v1.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh_user_token():
    user_id = get_jwt_identity()
    user_exists = sql.find_user_by_user_id(user_id)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="User not found")
    access_token = create_access_token(user_id)
    return settings.build_json_report({
        "ok": True,
        "access_token": access_token
    })


@veilance_users_v1.route("/payment/request", methods=["POST"])
@jwt_required()
def request_payment_link():
    data = request.get_json(force=True, silent=True) or {}
    user_id = get_jwt_identity()
    user_exists = sql.find_user_by_user_id(user_id)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="User not found")
    requested_product = data.get("requested_product", None)
    if requested_product is None:
        return settings.build_json_report(None, is_error=True, error_string="Product does not exist")
    product_id = settings.correlate_requested_item_to_real_id(requested_product.lower())
    if product_id is None:
        return settings.build_json_report(None, is_error=True, error_string="Product does not exist")
    stripe_id = stripe_conn.get_stripe_customer(user_exists['email'], user_exists['user_id'])
    if stripe_id is None:
        return settings.build_json_report(None, is_error=True, error_string="Unable to upgrade user at this time")
    product_data = stripe_conn.get_product_data(product_id)
    price_data = stripe_conn.get_price_data(product_data['default_price'])
    if price_data["type"] == "one_time":
        invoice = stripe_connect.stripe.Invoice.create(
            customer=stripe_id,
            collection_method="send_invoice",
            days_until_due=2,
            metadata={
                "plan": requested_product,
            },
        )
        stripe_connect.stripe.InvoiceItem.create(
            customer=stripe_id,
            pricing={
                "price": price_data["id"],
            },
            invoice=invoice["id"],
        )
        stripe_connect.stripe.Invoice.send_invoice(
            invoice["id"]
        )
        invoice = stripe_connect.stripe.Invoice.retrieve(
            invoice["id"]
        )
        return settings.build_json_report({
            "invoice_url": invoice["hosted_invoice_url"],
            "invoice_id": invoice["id"],
            "invoice_status": invoice["status"],
            "subscription_id": None,
        })
    else:

        subscription = stripe_connect.stripe.Subscription.create(
            customer=stripe_id,
            items=[
                {
                    "price": price_data["id"],
                    "quantity": 1,
                }
            ],
            collection_method="charge_automatically",
            payment_behavior="default_incomplete",
            payment_settings={
                "save_default_payment_method": "on_subscription"
            },
            metadata={
                "plan": requested_product,
            },
            expand=["latest_invoice"],
        )
        invoice = subscription["latest_invoice"]
        if isinstance(invoice, str):
            invoice = stripe_connect.stripe.Invoice.retrieve(
                invoice
            )
        return settings.build_json_report({
            "invoice_url": invoice["hosted_invoice_url"],
            "invoice_id": invoice["id"],
            "invoice_status": subscription["status"],
            "subscription_id": subscription["id"],
        })



@veilance_users_v1.route("/payment/confirm", methods=["POST"])
@jwt_required()
def confirm_payment_success():
    data = request.get_json(force=True, silent=True) or {}
    user_id = get_jwt_identity()
    user_exists = sql.find_user_by_user_id(user_id)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="User not found")
    invoice_id = data.get("invoice_id", None)
    if invoice_id is None:
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="Missing required arguments",
        )
    product = data.get("product", None)
    if product is None:
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="Missing required arguments",
        )
    if product not in ["premium"]:
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="Invalid product provided",
        )
    is_used = sql.find_stripe_id(invoice_id)
    if is_used is not None:
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="This invoice ID has already been used",
        )
    invoice = stripe_connect.stripe.Invoice.retrieve(invoice_id)
    if invoice["status"] == "paid":
        retval = {
            "invoice_status": "paid",
            "upgraded": None,
            "paid": True,
            "note": None,
        }
        sql.insert_stripe_id(invoice_id)
        is_upgraded = sql.update_user_plan_by_email(
            user_exists['email'],
            product,
        )
        if is_upgraded:
            retval["upgraded"] = True
            emails.send_upgrade_email(user_exists['email'])
        else:
            retval["upgraded"] = False
            retval["note"] = (
                "Failed to upgrade user plan. Please contact "
                "support@helpmewrk.com with your invoice ID."
            )
    else:
        retval = {
            "invoice_id": "pending",
            "invoice_status": invoice["status"],
            "upgraded": None,
            "note": None,
            "paid": False,
        }
    return settings.build_json_report(retval)



@veilance_users_v1.route("/intel/domain/<domain>", methods=["GET"])
@jwt_required()
def get_paid_domain_intel(domain):
    user_id = get_jwt_identity()
    user_exists = sql.find_user_by_user_id(user_id)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="User not found")
    if user_exists['plan'] == "free":
        return settings.build_json_report(None, is_error=True, error_string="Your plan does not support this feature")
    # provide blacklist for people who need it (tl;dr: $$$)
    if domain in settings.load_blacklist():
        return settings.build_json_report(None, is_error=True, error_string="No telemetry found for this domain")
    search = request.headers.get("x-search", "5")
    try:
        if not isinstance(search, int):
            try:
                search = int(search)
            except:
                search = 5
        if search < 1:
            search = 5
        elif search > 350:
            search = 350
    except:
        search = 350
    telemetry = sql.find_newest_telemetry_by_domain(domain, remove_args=True, search_limit=search)
    if telemetry is None:
        return settings.build_json_report(None, is_error=True, error_string="No telemetry found for this domain")
    else:
        return settings.build_json_report(telemetry)


@veilance_users_v1.route("/intel/tracker/<tracker>", methods=["GET"])
@jwt_required()
def get_paid_tracker_intel(tracker):
    return settings.build_json_report(None, is_error=True, error_string="Endpoint not implemented yet")


@veilance_users_v1.route("/intel/fingerprint/<method>", methods=["GET"])
@jwt_required()
def get_paid_fingerprint_intel(method):
    return settings.build_json_report(None, is_error=True, error_string="Endpoint not implemented yet")


@veilance_users_v1.route("/intel/policy/compare", methods=["POST"])
@jwt_required()
def compare_privacy_policy():
    user_id = get_jwt_identity()
    user_exists = sql.find_user_by_user_id(user_id)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="User does not exist")
    if user_exists['plan'] == "free":
        return settings.build_json_report(None, is_error=True, error_string="This feature is only available for paid users")
    data = request.get_json(silent=True, force=True) or {}
    telemetry_data = data.get("telemetry_data", None)
    privacy_policy_url = data.get("privacy_policy_url", None)
    current_url = data.get("current_url", None)
    if telemetry_data is None or privacy_policy_url is None or current_url is None:
        return settings.build_json_report(None, is_error=True, error_string="Telemetry data, privacy policy URL, and current URL are required")
    queue_status = background.background_llm_request.apply_async(args=[telemetry_data, privacy_policy_url, current_url])
    return settings.build_json_report({
        "status": queue_status.status,
        "uuid": queue_status.id
    })


@veilance_users_v1.route("/verity/chat", methods=["POST"])
@jwt_required()
def chat_with_verify():
    user_id = get_jwt_identity()
    user_exists = sql.find_user_by_user_id(user_id)

    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="User does not exist")
    if not user_exists['verified_account']:
        return settings.build_json_report(None, is_error=True, error_string="User account is not verified")

    if user_exists['plan'] == "free":
        return settings.build_json_report(None, is_error=True, error_string="User plan does not support this feature")

    data = request.get_json(silent=True, force=True) or {}
    message = data.get("message", None)
    response_id = data.get("response_id", None)
    if message is None:
        return settings.build_json_report(None, is_error=True, error_string="Message is required")

    @stream_with_context
    def generate():
        stream = chatgpt.chat_with_verity(message, response_id=response_id)
        for event in stream:
            if event.type == "response.reasoning_summary_text.delta":
                payload = {"type": "thinking", "text": event.delta}
            elif event.type == "response.output_text.delta":
                payload = {"type": "delta", "text": event.delta}
            elif event.type == "response.completed":
                payload = {
                    "type": "done",
                    "response_id": event.response.id,
                }
            elif event.type == "response.failed":
                payload = {
                    "type": "error",
                    "error_string": (
                        event.response.error.message
                        if event.response.error
                        else "Verity could not complete the response"
                    ),
                }
            elif event.type == "error":
                payload = {"type": "error", "error_string": event.message}
            else:
                continue

            yield f"data: {json.dumps(payload)}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Verity": "Beyond the fine print."
        }
    )


@veilance_users_v1.route("/apikey/create", methods=["POST"])
@jwt_required()
@limiter.limit("3 per day")
def create_api_key():
    user_id = get_jwt_identity()
    user_exists = sql.find_user_by_user_id(user_id)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="User does not exist")
    if not user_exists['verified_account']:
        return settings.build_json_report(None, is_error=True, error_string="User account is not verified")
    if user_exists['plan'] == "free":
        return settings.build_json_report(None, is_error=True, error_string="API is available under premium access")
    api_key = settings.create_api_key()
    user_id = user_exists['user_id']
    is_updated = sql.update_user_api_key(user_id, api_key)
    if is_updated:
        return settings.build_json_report({"api_key": api_key})
    else:
        return settings.build_json_report(None, is_error=True, error_string="Unable to update user API key")


@veilance_admin_v1.route("/login", methods=["POST"])
def admin_login():
    conf = settings.load_conf()
    data = request.get_json(silent=True, force=True) or {}
    username = data.get("username", None)
    password = data.get("password", None)
    if username is None or password is None:
        return settings.build_json_report(None, is_error=True, error_string="Username and password are required")
    real_admin_username = conf['user_config']['admin_credentials']['username']
    real_admin_password_hash = conf['user_config']['admin_credentials']['password']
    admin_password_salt = conf['user_config']['admin_credentials']['salt']
    admin_password_rounds = conf['user_config']['admin_credentials']['hash_rounds']
    if username != real_admin_username:
        return settings.build_json_report(None, is_error=True, error_string="Invalid login")
    sent_password_hash, i, x = settings.encrypt_password(password, rounds=admin_password_rounds, salt=admin_password_salt)
    if sent_password_hash != real_admin_password_hash:
        return settings.build_json_report(None, is_error=True, error_string="Invalid login")
    else:
        token = settings.create_user_token(username, is_admin=True)
        return settings.build_json_report({"token": token}, is_error=False)


@veilance_admin_v1.route("/telemetry/view", methods=["POST"])
def get_telemetry():
    data = request.get_json(silent=True, force=True) or {}
    token = data.get("token", None)
    if token is None:
        return settings.build_json_report(None, is_error=True, error_string="Token is required")
    good_token, error = validate_user_token(token, is_admin=True)
    if not good_token:
        return settings.build_json_report(None, is_error=True, error_string=error)
    telemetry = sql.get_all_active_telemetry()
    return settings.build_json_report({"telemetry": telemetry})


@veilance_admin_v1.route("/telemetry/accept", methods=["POST"])
def accept_telemetry():
    data = request.get_json(silent=True, force=True) or {}
    token = data.get("token", None)
    if token is None:
        return settings.build_json_report(None, is_error=True, error_string="Token is required")
    good_token, error = validate_user_token(token, is_admin=True)
    if not good_token:
        return settings.build_json_report(None, is_error=True, error_string=error)
    telemetry_id = data.get("telemetry_id", None)
    if telemetry_id is None:
        return settings.build_json_report(None, is_error=True, error_string="Telemetry ID is required")
    payout_amount = data.get("payout_amount", "10")
    is_accepted = sql.accept_telemetry(telemetry_id, payout_amount)
    if not is_accepted:
        return settings.build_json_report(None, is_error=True, error_string="Failed to accept telemetry")
    return settings.build_json_report({"ok": True})


@veilance_admin_v1.route("/telemetry/deny", methods=["POST"])
def deny_telemetry():
    data = request.get_json(silent=True, force=True) or {}
    token = data.get("token", None)
    if token is None:
        return settings.build_json_report(None, is_error=True, error_string="Token is required")
    good_token, error = validate_user_token(token, is_admin=True)
    if not good_token:
        return settings.build_json_report(None, is_error=True, error_string=error)
    reason = data.get("reason", "N/A")
    telemetry_id = data.get("telemetry_id", None)
    if telemetry_id is None:
        return settings.build_json_report(None, is_error=True, error_string="Telemetry ID is required")
    is_rejected = sql.deny_telemetry(telemetry_id, reason)
    if not is_rejected:
        return settings.build_json_report(None, is_error=True, error_string="Unable to reject telemetry")
    return settings.build_json_report({"ok": True})
