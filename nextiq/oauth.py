import base64
import hashlib
import hmac
import json
import time

import secrets as _secrets

import frappe
import requests

from nextiq.constants import SERVICE_URL


# ── Config helpers ────────────────────────────────────────────────────────────

def _service_url():
    # site_config override for dev; falls back to the baked-in production URL
    return frappe.conf.get("nextiq_service_url") or SERVICE_URL


def _relay_secret():
    # site_config override for dev
    secret = frappe.conf.get("nextiq_relay_secret")
    if secret:
        return secret
    # Auto-generate once and persist in NextIQ Settings (no manual config needed)
    stored = frappe.db.get_single_value("NextIQ Settings", "relay_secret")
    if stored:
        return stored
    new_secret = _secrets.token_urlsafe(48)
    frappe.db.set_single_value("NextIQ Settings", "relay_secret", new_secret)
    frappe.db.commit()
    return new_secret

def _client_id():
    # Prefer the dynamically obtained client_id stored in NextIQ Settings
    settings_id = frappe.db.get_single_value("NextIQ Settings", "oauth_client_id")
    if settings_id:
        return settings_id
    # Fallback: static value in site_config (legacy / local dev override)
    value = frappe.conf.get("nextiq_oauth_client_id")
    if not value:
        frappe.throw("OAuth client not configured. Please click Connect in NextIQ Settings.")
    return value


# ── Redis PKCE cache ──────────────────────────────────────────────────────────

def _pkce_key(nonce):
    return f"nextiq_oauth:{nonce}"

def _pop_pkce(nonce):
    """Single-use: read and delete."""
    key = _pkce_key(nonce)
    raw = frappe.cache.get_value(key)
    if not raw:
        return None
    frappe.cache.delete_value(key)
    try:
        if isinstance(raw, bytes):
            raw = raw.decode()
        return json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        frappe.log_error("NextIQ OAuth: PKCE cache parse failed", frappe.get_traceback())


# ── Signed state ──────────────────────────────────────────────────────────────

def _sign_state(payload_dict):
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload_dict, sort_keys=True).encode()
    ).rstrip(b"=").decode()
    sig = hmac.new(
        _relay_secret().encode(), payload_b64.encode(), hashlib.sha256
    ).hexdigest()
    return f"{payload_b64}.{sig}"

def _verify_state(state):
    payload_b64, sig = state.rsplit(".", 1)
    expected = hmac.new(
        _relay_secret().encode(), payload_b64.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise ValueError("bad signature")
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# ── Whitelisted helpers called by JS ─────────────────────────────────────────

@frappe.whitelist()
def begin_oauth(site):
    """
    Entry point for the Connect flow.
    1. Calls nextiq_service to get/create an OAuth Client for this site (dynamic).
    2. Generates PKCE pair + signed state server-side (crypto.subtle needs HTTPS).
    Returns {state, challenge, service_url, relay_url, client_id}.
    """
    import os
    if not site.startswith("http"):
        frappe.throw("Invalid site URL")

    site = site.rstrip("/")

    # ── Step 1: Get or create OAuth client on nextiq_service ─────────────────
    try:
        resp = requests.get(
            f"{_service_url()}/api/method/nextiq_service.api.get_or_create_oauth_client",
            params={"site_url": site},
            timeout=10,
        )
        resp.raise_for_status()
        result    = resp.json().get("message", {})
        client_id = result.get("client_id")
        if not client_id:
            frappe.log_error("NextIQ OAuth: get_or_create_oauth_client returned no client_id", str(result))
            frappe.throw("Failed to initialize OAuth client. Please try again.")
    except Exception:
        frappe.log_error("NextIQ OAuth: get_or_create_oauth_client error", frappe.get_traceback())
        frappe.throw("Could not reach NextIQ Service. Please verify the service is reachable.")

    # Persist the client_id so token refresh can use it later
    try:
        settings = frappe.get_single("NextIQ Settings")
        settings.oauth_client_id = client_id
        settings.save(ignore_permissions=True)
        frappe.db.commit()
    except Exception:
        frappe.log_error("NextIQ OAuth: saving oauth_client_id failed", frappe.get_traceback())

    # ── Step 2: Generate PKCE + signed state ─────────────────────────────────
    verifier  = base64.urlsafe_b64encode(os.urandom(48)).rstrip(b"=").decode()
    nonce     = base64.urlsafe_b64encode(os.urandom(12)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()

    relay_url = f"{site}/api/method/nextiq.oauth.callback"
    state     = _sign_state({"site": site, "nonce": nonce, "ts": int(time.time())})

    try:
        frappe.cache.set_value(
            _pkce_key(nonce),
            json.dumps({"verifier": verifier, "state": state}),
            expires_in_sec=600,
        )
    except Exception:
        frappe.log_error("NextIQ OAuth: begin_oauth Redis write failed", frappe.get_traceback())
        frappe.throw("Failed to save OAuth session. Please try again.")

    return {
        "state":       state,
        "challenge":   challenge,
        "service_url": _service_url(),
        "relay_url":   relay_url,
        "client_id":   client_id,
    }


@frappe.whitelist()
def get_connect_config():
    return {
        "service_url": _service_url(),
        "client_id":   _client_id(),
    }


# ── OAuth callback ────────────────────────────────────────────────────────────

@frappe.whitelist(allow_guest=True)
def callback(code=None, state=None, error=None):
    if error:
        frappe.log_error("nextiq_oauth_callback", f"OAuth callback error param: {error}")
        frappe.respond_as_web_page(
            "Connection Failed",
            f"Authorization failed: {error}",
            indicator_color="red",
        )
        return

    if not code or not state:
        frappe.log_error("NextIQ OAuth: Missing Params", "OAuth callback received with missing code or state")
        frappe.respond_as_web_page(
            "Connection Failed", "Missing code or state.", indicator_color="red"
        )
        return

    # Verify state signature
    try:
        payload = _verify_state(state)
        nonce   = payload["nonce"]
    except Exception as e:
        frappe.log_error("NextIQ OAuth: State Verify Failed", f"state verify failed: {e}\n\n{frappe.get_traceback()}")
        frappe.respond_as_web_page(
            "Connection Failed", "Invalid state.", indicator_color="red"
        )
        return

    # Pop PKCE data from Redis (single-use)
    pkce = _pop_pkce(nonce)
    if not pkce:
        frappe.log_error("NextIQ OAuth: Session Expired", f"PKCE session not found or expired for nonce={nonce}")
        frappe.respond_as_web_page(
            "Connection Failed",
            "Connect session expired or already used. Please click Connect again.",
            indicator_color="red",
        )
        return

    # Constant-time state comparison
    if not hmac.compare_digest(state, pkce["state"]):
        frappe.log_error("NextIQ OAuth: State Mismatch", "state mismatch between URL param and Redis cache")
        frappe.respond_as_web_page(
            "Connection Failed", "State mismatch.", indicator_color="red"
        )
        return

    # Exchange code for tokens — PKCE, no client_secret
    # relay_url must exactly match what was used in begin_oauth (derived from state)
    site      = payload.get("site", "")
    relay_url = f"{site}/api/method/nextiq.oauth.callback"

    resp = None
    try:
        resp = requests.post(
            f"{_service_url()}/api/method/frappe.integrations.oauth2.get_token",
            data={
                "grant_type":    "authorization_code",
                "code":          code,
                "client_id":     _client_id(),
                "redirect_uri":  relay_url,
                "code_verifier": pkce["verifier"],
            },
            timeout=10,
        )
        resp.raise_for_status()
        tokens = resp.json()
    except Exception as e:
        frappe.log_error(
            "NextIQ OAuth: Token Exchange Failed",
            f"token exchange failed: {e}\nresponse: {getattr(resp, 'text', '-')}\n\n{frappe.get_traceback()}",
        )
        frappe.respond_as_web_page(
            "Connection Failed",
            "Token exchange with NextIQ Service failed. Please try again.",
            indicator_color="red",
        )
        return

    if "access_token" not in tokens:
        frappe.log_error("NextIQ OAuth: Bad Token Response", f"no access_token in response: {tokens}")
        frappe.respond_as_web_page(
            "Connection Failed", "Bad token response.", indicator_color="red"
        )
        return

    # Save tokens — get_single() + save() fires Password encryption hooks
    try:
        settings = frappe.get_single("NextIQ Settings")
        settings.oauth_access_token  = tokens["access_token"]
        settings.oauth_refresh_token = tokens.get("refresh_token", "")
        settings.token_expires_at    = frappe.utils.add_to_date(
            None, seconds=int(tokens.get("expires_in", 3600))
        )
        settings.connection_status = "Connected"
        settings.save(ignore_permissions=True)
        frappe.db.commit()
    except Exception:
        frappe.log_error("NextIQ OAuth: Token Save Failed", frappe.get_traceback())
        frappe.respond_as_web_page(
            "Connection Failed",
            "Tokens received but could not be saved. Please try again.",
            indicator_color="red",
        )
        return

    # Register this site on nextiq_service
    reg = None
    try:
        reg = requests.post(
            f"{_service_url()}/api/method/nextiq_service.api.register_customer",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={"state": state},
            timeout=10,
        )
        reg.raise_for_status()
        data = reg.json().get("message", {})
    except Exception as e:
        frappe.log_error(
            "NextIQ OAuth: register_customer Failed",
            f"register_customer failed: {e}\nresponse: {getattr(reg, 'text', '-')}\n\n{frappe.get_traceback()}",
        )
        frappe.respond_as_web_page(
            "Partially Connected",
            "Tokens saved but registration on NextIQ Service failed. Please contact support.",
            indicator_color="orange",
        )
        return

    if data.get("email"):
        try:
            settings = frappe.get_single("NextIQ Settings")
            settings.connected_email = data["email"]
            settings.save(ignore_permissions=True)
            frappe.db.commit()
        except Exception:
            frappe.log_error("NextIQ OAuth: Save Connected Email Failed", frappe.get_traceback())

    if data.get("verified") is False:
        frappe.respond_as_web_page(
            "Verify Your Email",
            "Connected — but please verify your email on NextIQ Service to activate scans.",
            indicator_color="orange",
        )
    else:
        frappe.respond_as_web_page(
            "Connected!",
            "NextIQ Service connected successfully. You can now scan business cards.",
            indicator_color="green",
        )


# ── Disconnect ────────────────────────────────────────────────────────────────

@frappe.whitelist()
def disconnect():
    settings      = frappe.get_single("NextIQ Settings")
    access_token  = settings.get_password("oauth_access_token")  if settings.oauth_access_token  else None
    refresh_token = settings.get_password("oauth_refresh_token") if settings.oauth_refresh_token else None

    for token in [t for t in [access_token, refresh_token] if t]:
        try:
            requests.post(
                f"{_service_url()}/api/method/frappe.integrations.oauth2.revoke_token",
                data={"token": token, "client_id": _client_id()},
                timeout=5,
            )
        except Exception as e:
            frappe.log_error("NextIQ OAuth: revoke_token Failed", f"revoke_token failed: {e}\n\n{frappe.get_traceback()}")

    if access_token:
        try:
            requests.post(
                f"{_service_url()}/api/method/nextiq_service.api.disconnect_customer",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=5,
            )
        except Exception as e:
            frappe.log_error("NextIQ OAuth: disconnect_customer Failed", f"disconnect_customer failed: {e}\n\n{frappe.get_traceback()}")

    try:
        settings = frappe.get_single("NextIQ Settings")
        settings.oauth_access_token  = ""
        settings.oauth_refresh_token = ""
        settings.token_expires_at    = None
        settings.connection_status   = "Not Connected"
        settings.connected_email     = ""
        settings.save(ignore_permissions=True)
        frappe.db.commit()
    except Exception:
        frappe.log_error("NextIQ OAuth: Disconnect Settings Clear Failed", frappe.get_traceback())
        frappe.throw("Disconnect failed while clearing local settings. Please try again.")
    return {"success": True}
