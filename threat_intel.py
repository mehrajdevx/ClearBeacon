from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MAX_FEED_BYTES = 2_000_000
MAX_FEED_AGE_DAYS = 14
SAFE_BROWSING_TIMEOUT_SECONDS = 5
logger = logging.getLogger(__name__)

SAFE_BROWSING_COPY = {
    "en": {
        "match_title": "Potentially unsafe match",
        "match_evidence": "Google Safe Browsing reports this URL as a potentially unsafe resource.",
        "no_match_title": "No known threat detected",
        "no_match_evidence": "Google Safe Browsing did not find this URL in its current threat results. This does not prove the site is safe.",
        "actions": [
            "A new, unreported, or missed threat may not appear in Google's results.",
            "Verify the exact domain independently before entering payment or account details.",
        ],
        "disclaimer": "Google Safe Browsing can miss unsafe sites or incorrectly flag safe sites. A match is an advisory, not proof.",
    },
    "bn": {
        "match_title": "সম্ভাব্য ঝুঁকিপূর্ণ লিংক",
        "match_evidence": "Google Safe Browsing এই URL-টিকে সম্ভাব্য ঝুঁকিপূর্ণ হিসেবে চিহ্নিত করেছে।",
        "no_match_title": "পরিচিত হুমকি শনাক্ত হয়নি",
        "no_match_evidence": "Google Safe Browsing-এর বর্তমান ফলাফলে এই URL মেলেনি। এর অর্থ সাইটটি নিরাপদ—এমন নিশ্চয়তা নয়।",
        "actions": [
            "নতুন বা রিপোর্ট না হওয়া হুমকি Google-এর ফলে নাও থাকতে পারে।",
            "পেমেন্ট বা অ্যাকাউন্টের তথ্য দেওয়ার আগে ডোমেইনটি আলাদাভাবে যাচাই করুন।",
        ],
        "disclaimer": "Google Safe Browsing ঝুঁকিপূর্ণ সাইট শনাক্ত করতে ব্যর্থ হতে পারে বা নিরাপদ সাইটকে ভুলভাবে চিহ্নিত করতে পারে। মিল পাওয়া একটি সতর্কতা, প্রমাণ নয়।",
    },
    "es": {
        "match_title": "Coincidencia potencialmente peligrosa",
        "match_evidence": "Google Safe Browsing informa que esta URL podría ser un recurso peligroso.",
        "no_match_title": "No se detectaron amenazas conocidas",
        "no_match_evidence": "Google Safe Browsing no encontró esta URL en sus resultados actuales. Esto no demuestra que el sitio sea seguro.",
        "actions": [
            "Una amenaza nueva, no denunciada o no detectada puede no aparecer en los resultados de Google.",
            "Verifica el dominio por separado antes de introducir datos de pago o de cuenta.",
        ],
        "disclaimer": "Google Safe Browsing puede pasar por alto sitios peligrosos o marcar sitios seguros por error. Una coincidencia es un aviso, no una prueba.",
    },
    "fr": {
        "match_title": "Correspondance potentiellement dangereuse",
        "match_evidence": "Google Safe Browsing signale cette URL comme une ressource potentiellement dangereuse.",
        "no_match_title": "Aucune menace connue détectée",
        "no_match_evidence": "Google Safe Browsing n'a pas trouvé cette URL dans ses résultats actuels. Cela ne prouve pas que le site est sûr.",
        "actions": [
            "Une menace nouvelle, non signalée ou non détectée peut être absente des résultats de Google.",
            "Vérifiez le domaine indépendamment avant de saisir des données de paiement ou de compte.",
        ],
        "disclaimer": "Google Safe Browsing peut ne pas détecter certains sites dangereux ou signaler par erreur des sites sûrs. Une correspondance est un avis, pas une preuve.",
    },
    "hi": {
        "match_title": "संभावित रूप से असुरक्षित लिंक मिला",
        "match_evidence": "Google Safe Browsing इस URL को संभावित रूप से असुरक्षित बता रहा है।",
        "no_match_title": "कोई ज्ञात खतरा नहीं मिला",
        "no_match_evidence": "Google Safe Browsing को अपने मौजूदा नतीजों में यह URL नहीं मिला। इससे साइट सुरक्षित साबित नहीं होती।",
        "actions": [
            "नया, रिपोर्ट न किया गया या छूटा हुआ खतरा Google के नतीजों में न हो सकता है।",
            "भुगतान या खाता जानकारी देने से पहले डोमेन को स्वतंत्र रूप से सत्यापित करें।",
        ],
        "disclaimer": "Google Safe Browsing कुछ असुरक्षित साइटों को पहचान नहीं सकता या सुरक्षित साइटों को गलती से चिह्नित कर सकता है। मिलना चेतावनी है, प्रमाण नहीं।",
    },
    "ar": {
        "match_title": "تم العثور على تطابق قد يكون خطيراً",
        "match_evidence": "تشير خدمة Google Safe Browsing إلى أن عنوان URL هذا قد يكون مورداً غير آمن.",
        "no_match_title": "لم يُعثر على تهديد معروف",
        "no_match_evidence": "لم تعثر Google Safe Browsing على عنوان URL هذا في نتائجها الحالية. وهذا لا يثبت أن الموقع آمن.",
        "actions": [
            "قد لا يظهر التهديد الجديد أو غير المُبلّغ عنه أو الذي لم يُكتشف في نتائج Google.",
            "تحقق من النطاق بشكل مستقل قبل إدخال بيانات الدفع أو الحساب.",
        ],
        "disclaimer": "قد لا تكتشف Google Safe Browsing بعض المواقع غير الآمنة أو قد تصنّف مواقع آمنة عن طريق الخطأ. التطابق تحذير وليس دليلاً.",
    },
}


def validate_feed_payload(payload: object) -> str | None:
    if not isinstance(payload, dict) or not isinstance(payload.get("domains"), list):
        return "Feed must be a JSON object with a domains array."
    domains = payload["domains"]
    if len(domains) > 100_000:
        return "Feed can contain at most 100,000 domains."
    for domain in domains:
        if (not isinstance(domain, str) or len(domain) > 253 or
                not domain.strip() or domain != domain.strip() or
                domain.endswith("..") or
                any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                    for label in domain.rstrip(".").split(".")) or
                any(not (char.isalnum() or char in ".-") for char in domain)):
            return "Each feed entry must be a plain domain name (maximum 253 characters)."
    provider = payload.get("provider", "local_file")
    if (not isinstance(provider, str) or not provider.strip() or len(provider) > 80 or
            any(ord(char) < 32 for char in provider)):
        return "Feed provider must be a non-empty label of at most 80 characters."
    try:
        updated = datetime.fromisoformat(str(payload.get("updated_at", "")).replace("Z", "+00:00"))
        if updated.tzinfo is None:
            raise ValueError("timezone required")
        age_days = (datetime.now(timezone.utc) - updated.astimezone(timezone.utc)).total_seconds() / 86400
    except (ValueError, TypeError):
        return "Feed updated_at must be a valid timestamp with a timezone."
    if age_days < -1:
        return "Feed timestamp is in the future."
    if age_days > MAX_FEED_AGE_DAYS:
        return f"Feed is stale; it must be updated within {MAX_FEED_AGE_DAYS} days."
    return None


def match_feed_payload(host: str, payload: object) -> dict[str, Any]:
    error = validate_feed_payload(payload)
    if error:
        if error.startswith("Feed is stale;") and isinstance(payload, dict):
            return {
                "status": "stale",
                "provider": str(payload.get("provider", "local_file"))[:80],
                "updated_at": str(payload.get("updated_at")),
                "match": False,
            }
        return {
            "status": "unavailable", "provider": "local_file", "updated_at": None,
            "match": False, "error": error,
        }
    assert isinstance(payload, dict)
    updated_at = str(payload["updated_at"])
    return {
        "status": "completed",
        "provider": str(payload.get("provider", "local_file"))[:80],
        "updated_at": updated_at,
        "match": host.lower().rstrip(".") in {domain.lower().rstrip(".") for domain in payload["domains"]},
    }


def match_local_feed(host: str, path: str | None, payload_json: str | None = None) -> dict[str, Any]:
    if payload_json is not None:
        try:
            payload = json.loads(payload_json)
        except json.JSONDecodeError:
            return {"status": "unavailable", "provider": "database", "updated_at": None,
                    "match": False, "error": "Active threat feed could not be parsed."}
        return match_feed_payload(host, payload)
    if not path:
        return {"status": "not_configured", "provider": None, "updated_at": None, "match": False}
    feed_path = Path(path)
    try:
        if feed_path.stat().st_size > MAX_FEED_BYTES:
            raise ValueError("Threat feed exceeds the 2 MB limit.")
        payload = json.loads(feed_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return {
            "status": "unavailable",
            "provider": "local_file",
            "updated_at": None,
            "match": False,
            "error": "Configured threat feed could not be read or parsed.",
        }
    return match_feed_payload(host, payload)


def check_google_safe_browsing(url: str, api_key: str) -> dict[str, Any]:
    provider = "Google Safe Browsing"
    if not api_key:
        return {"status": "not_configured", "provider": provider, "updated_at": None, "match": False}

    body = json.dumps({
        "client": {"clientId": "clearbeacon", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }).encode("utf-8")
    request = Request(
        "https://safebrowsing.googleapis.com/v4/threatMatches:find",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Goog-Api-Key": api_key,
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=SAFE_BROWSING_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read(32_000).decode("utf-8"))
    except HTTPError as error:
        status = "rate_limited" if error.code == 429 else "unavailable"
        logger.warning("Google Safe Browsing returned HTTP %s", error.code)
        if error.code == 403:
            message = (
                "Google Safe Browsing access is not enabled for this API key. "
                "Enable the Safe Browsing API in Google Cloud."
            )
        elif error.code == 429:
            message = "Google Safe Browsing quota is temporarily exhausted."
        else:
            message = "Google Safe Browsing could not complete the reputation lookup."
        return {
            "status": status,
            "provider": provider,
            "updated_at": None,
            "match": False,
            "error": message,
        }
    except (URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        logger.warning("Google Safe Browsing request failed (%s)", type(error).__name__)
        return {
            "status": "unavailable",
            "provider": provider,
            "updated_at": None,
            "match": False,
            "error": "Google Safe Browsing is temporarily unavailable.",
        }

    if not isinstance(payload, dict):
        return {
            "status": "unavailable", "provider": provider, "updated_at": None,
            "match": False, "error": "Google Safe Browsing returned an invalid response.",
        }
    matches = payload.get("matches", [])
    if not isinstance(matches, list):
        return {
            "status": "unavailable", "provider": provider, "updated_at": None,
            "match": False, "error": "Google Safe Browsing returned an invalid response.",
        }
    threat_types = [
        item["threatType"]
        for item in matches
        if isinstance(item, dict)
        and isinstance(item.get("threatType"), str)
        and len(item["threatType"]) <= 64
    ][:4]
    return {
        "status": "completed",
        "provider": provider,
        "updated_at": None,
        "match": bool(matches),
        "threat_types": threat_types,
    }


def apply_threat_result(
    result: dict[str, Any],
    reputation: dict[str, Any],
    safe_browsing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    safe_match = bool(
        safe_browsing
        and safe_browsing.get("status") == "completed"
        and safe_browsing.get("match")
    )
    feed_match = bool(reputation.get("match"))
    active_reputation = safe_browsing or reputation
    if feed_match and not safe_match:
        active_reputation = reputation
    entry = {
        "check": "threat_intelligence",
        "status": active_reputation["status"],
        "provider": active_reputation.get("provider"),
        "updated_at": active_reputation.get("updated_at"),
    }
    result["coverage"] = [result["coverage"][0], entry]
    if feed_match or safe_match:
        locale = result.get("locale", "en")
        copy = SAFE_BROWSING_COPY.get(locale, SAFE_BROWSING_COPY["en"])
        provider = "Google Safe Browsing" if safe_match else reputation.get("provider")
        result["risk_label"] = "known_malicious"
        result["title"] = copy["match_title"] if safe_match else "Known malicious match"
        result["score"] = 100
        result["evidence"].insert(0, {
            "type": "google_safe_browsing_match" if safe_match else "known_threat_feed_match",
            "text": copy["match_evidence"] if safe_match else f"This domain appears in the configured threat list ({provider}).",
            "strength": "strong",
            "source": provider,
        })
        result["decision_reason"].insert(0, result["evidence"][0]["text"])
        result["recommended_actions"] = [
            "Do not open the link or send money.",
            "Report the message to the service that sent it.",
        ]
        result["disclaimer"] = copy["disclaimer"] if safe_match else "A threat-list match is a warning based on this feed and is not a legal finding."
        if safe_match:
            result["attribution"] = {
                "text": "Advisory provided by Google.",
                "url": "https://developers.google.com/safe-browsing/v4/advisory",
            }
    elif (
        safe_browsing
        and safe_browsing.get("status") == "completed"
        and result.get("risk_label") == "unknown"
    ):
        locale = result.get("locale", "en")
        copy = SAFE_BROWSING_COPY.get(locale, SAFE_BROWSING_COPY["en"])
        result["risk_label"] = "no_known_threat"
        result["title"] = copy["no_match_title"]
        result["evidence"] = [{
            "type": "google_safe_browsing_no_match",
            "text": copy["no_match_evidence"],
            "strength": "weak",
            "source": "Google Safe Browsing",
        }]
        result["decision_reason"] = [copy["no_match_evidence"]]
        result["recommended_actions"] = copy["actions"]
        result["disclaimer"] = copy["disclaimer"]
    if reputation.get("error"):
        result["feed_error"] = reputation["error"]
    if safe_browsing and safe_browsing.get("error"):
        result["threat_intelligence_error"] = safe_browsing["error"]
    return result
