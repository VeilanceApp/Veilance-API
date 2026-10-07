import json

import openai

import lib.settings as settings

conf = settings.load_conf()
client = openai.OpenAI(api_key=conf["openai"]["api_key"])


def normalize_telemetry_data(raw_data, privacy_policy_url=None, domain_url=None):
    if not isinstance(raw_data, dict):
        return {}

    payload = raw_data

    for _ in range(4):
        if isinstance(payload.get("telemetry_data"), dict):
            payload = payload["telemetry_data"]
        elif isinstance(payload.get("payload"), dict):
            payload = payload["payload"]
        else:
            break

    if "observations" in payload:
        snapshots = payload["observations"]

        if (
                not isinstance(snapshots, list)
                or len(snapshots) != 1
                or not isinstance(snapshots[0], dict)
        ):
            raise ValueError(
                "Policy comparison requires exactly one telemetry snapshot"
            )

        payload = snapshots[0]

    if not isinstance(payload.get("observation"), dict):
        raise ValueError("Telemetry snapshot is missing observation data")

    local = raw_data.get("local", {})
    if not isinstance(local, dict):
        local = {}

    privacy_policy_url = (
        privacy_policy_url
        or raw_data.get("privacy_policy_url")
    )

    domain_url = (
        domain_url
        or raw_data.get("current_url")
    )

    if not domain_url:
        site = payload.get("site", {})
        hostname = site.get("hostname")

        if hostname:
            scheme = "https" if site.get("https", True) else "http"
            domain_url = f"{scheme}://{hostname}"
    observations = payload.get("observation", {})
    if not isinstance(observations, dict):
        observations = {}

    interest = payload.get("interest", {})
    if not isinstance(interest, dict):
        interest = {}

    detections = []

    for reason in interest.get("reasons", []):
        if not isinstance(reason, dict):
            continue

        reason_id = reason.get("id")
        if not isinstance(reason_id, str):
            continue
        prefix = "detection.veilance-json-detections-"
        if not reason_id.startswith(prefix):
            continue
        detections.append({
            "type": reason_id[len(prefix):],
            "severity": reason.get("severity"),
        })
    allowed_page_fields = {
        "scriptCount",
        "thirdPartyScriptCount",
        "iframeCount",
        "thirdPartyIframeCount",
        "accessibleCookieCount",
        "localStorageKeyCount",
        "sessionStorageKeyCount",
        "indexedDbCount",
        "cacheCount",
        "serviceWorkerControlled",
    }
    page_data = payload.get("page", {})
    if not isinstance(page_data, dict):
        page_data = {}
    page = {
        key: value
        for key, value in page_data.items()
        if key in allowed_page_fields
    }
    observed_at = (
        local.get("createdAt")
        or raw_data.get("created_at")
        or raw_data.get("observed_at")
        or payload.get("observedAt")
        or payload.get("timestamp")
    )

    return {
        "domain_url": domain_url,
        "privacy_policy_url": privacy_policy_url,
        "visit": {
            "snapshot_id": (
                payload.get("eventId")
                or local.get("snapshotId")
            ),
            "observed_at": observed_at,
            "duration_seconds": observations.get(
                "durationSeconds", 0
            ),
            "extension_version": payload.get(
                "extensionVersion"
            ),
        },
        "seen_behavior": {
            "observations": {
                "totalRequests": observations.get(
                    "totalRequests", 0
                ),
                "firstPartyRequests": observations.get(
                    "firstPartyRequests", 0
                ),
                "thirdPartyRequests": observations.get(
                    "thirdPartyRequests", 0
                ),
            },
            "thirdPartyHosts": payload.get(
                "thirdPartyHosts", []
            ),
            "trackers": payload.get(
                "trackers", []
            ),
            "signals": payload.get(
                "signals", []
            ),
            "page": page,
            "security": payload.get(
                "security", {}
            ),
            "detections": detections,
        },
    }


def get_verity_chat_prompt():
    return open(settings.VERITY_CHAT_PROMPT).read()


def chat_with_verity(user_msg, response_id=None):
    stream = client.responses.create(
        model=conf['openai']['model'],
        tools=conf['openai']['tools'],
        previous_response_id=response_id,
        input=user_msg,
        store=True,
        stream=True,
        reasoning={"summary": "auto"},
        instructions=get_verity_chat_prompt()
    )
    return stream


def get_privacy_policy_comparison_prompt():
    return open(settings.PRIVACY_POLICY_PROMPT).read()


def privacy_policy_comparison(payload):
    str_payload = json.dumps(payload)
    response = client.responses.create(
        model=conf['openai']['model'],
        tools=conf['openai']['tools'],
        input=[
            {
                "role": "developer",
                "content": [
                    {
                        "type": "input_text",
                        "text": get_privacy_policy_comparison_prompt()
                    }
                ]
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": f"Runtime configuration for this analysis: {str_payload}"
                    }
                ]
            }
        ]
    )
    results = json.loads(response.output_text)
    return results
