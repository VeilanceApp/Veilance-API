import lib.settings as settings
import lib.connectors.sql as sql
import lib.connectors.chatgpt as chatgpt

from celery import Celery


conf = settings.load_conf()
app = Celery('tasks', broker=conf['celery']['broker'], backend=conf['celery']['backend'])
app.conf.update(
    broker_connection_retry_on_startup=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_transport_options={
        "visibility_timeout": 3600,
        "socket_timeout": conf["celery"].get("timeout", 30),
        "socket_connect_timeout": conf["celery"].get("timeout", 30),
        "retry_on_timeout": True,
    },
    result_backend_transport_options={
        "retry_policy": {
            "timeout": conf["celery"].get("timeout", 30),
        }
    },
    result_expires=3600
)


@app.task
def background_llm_request(telemetry_data, privacy_policy_url, domain_url):
    payload = chatgpt.normalize_telemetry_data(telemetry_data, privacy_policy_url, domain_url)
    privacy_results = chatgpt.privacy_policy_comparison(payload)
    sql.insert_privacy_policy_analysis(privacy_results, domain_url, privacy_policy_url)
    return privacy_results


def check_user_payments():
    pass
