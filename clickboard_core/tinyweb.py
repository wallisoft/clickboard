"""Tiny-Web API calls: device registration and signup details.

Part of clickboard_core. PolyForm Small Business License 1.0.0, see LICENSE.
"""
import json
import urllib.error
import urllib.request

from . import common as C

SIGNUP_EMAIL = "signup@tiny-web.uk"        # fallbacks if signup-info.php is unreachable
SIGNUP_SMS_FALLBACK = "+447576556717"


def api_post(endpoint: str, api_key: str, payload: dict, timeout=10) -> dict:
    req = urllib.request.Request(
        C.API_BASE + endpoint,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": C.USER_AGENT,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read())
        except Exception:
            return {"ok": False, "error": f"Tiny-Web returned HTTP {exc.code}"}
    except Exception as exc:
        return {"ok": False, "error": f"Can't reach Tiny-Web: {exc}"}


def signup_info() -> dict:
    """Signup email + SMS number from Tiny-Web (load-balanced there), with fallbacks."""
    info = {"email": SIGNUP_EMAIL, "sms_number": SIGNUP_SMS_FALLBACK}
    try:
        req = urllib.request.Request(C.API_BASE + "signup-info.php",
                                     headers={"User-Agent": C.USER_AGENT})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read())
        if data.get("ok"):
            info["email"] = data.get("email") or info["email"]
            info["sms_number"] = data.get("sms_number") or info["sms_number"]
    except Exception as exc:
        C.log(f"signup info unavailable, using built-in details: {exc}")
    return info
