import json

import openai

import lib.settings as settings

conf = settings.load_conf()
client = openai.OpenAI(api_key=conf["openai"]["api_key"])


def normalize_telemetry_data(raw_data, privacy_policy_url, domain_url):
    payload = raw_data.get("payload", {})
    local = raw_data.get("local", {})
    detections = []
    for reason in payload.get("interest", {}).get("reasons", []):
        detections.append({
            "type": reason['id'].replace("detection.veilance-json-", ""),
            "severity": reason['severity']
        })
    observations = payload.get("observation", {})
    return {
        "domain_url": domain_url,
        "privacy_policy_url": privacy_policy_url,
        "visit": {
            "snapshot_id": payload.get("eventId") or local.get("snapshotId"),
            "observed_at": local.get("createdAt"),
            "duration_seconds": observations.get("durationSeconds", 0),
            "extension_version": payload.get("extensionVersion")
        },
        "seen_behavior": {
            "observations": {
                "totalRequests": observations.get("totalRequests", 0),
                "firstPartyRequests": observations.get("firstPartyRequests", 0),
                "thirdPartyRequests": observations.get("thirdPartyRequests", 0)
            }
        },
        "thirdPartyHosts": payload.get("thirdPartyHosts", []),
        "trackers": payload.get("trackers", []),
        "signals": payload.get("signals", []),
        "page": {
            key: value
            for key, value in payload.get("page", {}).items()
            if key in {
                "scriptCount",
                "thirdPartyScriptCount",
                "iframeCount",
                "thirdPartyIframeCount",
                "accessibleCookieCount",
                "localStorageKeyCount",
                "sessionStorageKeyCount",
                "indexedDbCount",
                "cacheCount",
                "serviceWorkerControlled"
            }
        },
        "detections": detections
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
