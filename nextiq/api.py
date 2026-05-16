# Copyright (c) 2026, krushang.patel@satat.tech and contributors
# For license information, please see license.txt

import base64
import hashlib
import hmac
import html
import ipaddress
import re
import secrets
import traceback

import frappe
import requests

import nextiq
from nextiq.constants import SERVICE_URL
from nextiq.version_check import _version_lt


# ── OAuth token helpers ───────────────────────────────────────────────────────

_REFRESH_LOCK_KEY = "nextiq_token_refresh_lock"


def _token_valid(settings):
	if not settings.oauth_access_token or settings.connection_status != "Connected":
		return False
	if not settings.token_expires_at:
		return False
	return (frappe.utils.get_datetime(settings.token_expires_at)
	        > frappe.utils.add_to_date(frappe.utils.now_datetime(), seconds=60))


def _do_refresh(settings):
	"""Exchange refresh_token for a new access_token and persist it."""
	import time as _time
	refresh_token = settings.get_password("oauth_refresh_token")
	client_id     = settings.oauth_client_id or frappe.conf.get("nextiq_oauth_client_id", "")
	resp = requests.post(
		f"{SERVICE_URL}/api/method/frappe.integrations.oauth2.get_token",
		data={
			"grant_type":    "refresh_token",
			"refresh_token": refresh_token,
			"client_id":     client_id,
		},
		timeout=10,
	)
	resp.raise_for_status()
	tokens = resp.json()
	if "access_token" not in tokens:
		raise ValueError("No access_token in refresh response")
	s = frappe.get_single("NextIQ Settings")
	s.oauth_access_token = tokens["access_token"]
	if tokens.get("refresh_token"):
		s.oauth_refresh_token = tokens["refresh_token"]
	s.token_expires_at = frappe.utils.add_to_date(
		None, seconds=int(tokens.get("expires_in", 3600))
	)
	s.save(ignore_permissions=True)
	frappe.db.commit()
	return tokens["access_token"]


def _get_valid_access_token():
	"""Return a valid Bearer access token, refreshing if within 60 s of expiry."""
	import time as _time
	settings = frappe.get_single("NextIQ Settings")
	if settings.connection_status != "Connected" or not settings.oauth_access_token:
		frappe.throw(
			"NextIQ Service is not connected. Please connect via NextIQ Settings.",
			title="Not Connected",
		)
	if _token_valid(settings):
		return settings.get_password("oauth_access_token")
	# Token near/past expiry — acquire Redis lock (SETNX) and refresh
	if not frappe.cache.set(_REFRESH_LOCK_KEY, "1", nx=True, ex=30):
		_time.sleep(2)
		settings = frappe.get_single("NextIQ Settings")
		if _token_valid(settings):
			return settings.get_password("oauth_access_token")
		frappe.throw("Token refresh in progress. Please retry in a moment.")
	try:
		return _do_refresh(settings)
	except Exception as e:
		frappe.log_error(
			"NextIQ: OAuth Token Refresh Failed",
			f"Token refresh request failed: {e}\n\n{frappe.get_traceback()}",
		)
		try:
			s = frappe.get_single("NextIQ Settings")
			s.connection_status = "Not Connected"
			s.save(ignore_permissions=True)
			frappe.db.commit()
		except Exception:
			frappe.log_error("NextIQ: Failed to update connection_status after refresh failure", frappe.get_traceback())
		frappe.throw(
			"OAuth token expired and refresh failed. Please reconnect via NextIQ Settings.",
			title="Token Refresh Failed",
		)
	finally:
		frappe.cache.delete_value(_REFRESH_LOCK_KEY)


# Fields allowed when creating a Lead from scan data — mirrors the service-side list
_ALLOWED_LEAD_FIELDS = frozenset({
	"salutation", "first_name", "middle_name", "last_name",
	"gender", "job_title", "email_id", "mobile_no", "whatsapp_no",
	"phone", "phone_ext", "company_name", "website",
	"fax",
})

# Address fields are stored in Address doctype (linked to Lead), not on Lead itself
_ADDRESS_FIELDS = frozenset({"address_line1", "address_line2", "city", "state", "pincode", "country"})
_MAX_FIELD_LEN = 500   # max characters per Lead field value

# CRM Lead uses different field names for 2 fields; 3 fields don't exist in CRM Lead at all
_CRM_FIELD_REMAP = {"email_id": "email", "company_name": "organization"}
_CRM_DROP_FIELDS = frozenset({"whatsapp_no", "phone_ext", "fax"})

# Map Frappe DocType names (as they appear in "Could not find X: Y" errors) to
# the Lead field name, so _find_bad_field can strip the offending field.
_LINK_DOCTYPE_TO_FIELD = {
	"country":    "country",
	"salutation": "salutation",
	"Country":    "country",
	"Salutation": "salutation",
}

# Maps lowercase field labels (as Frappe uses them in error messages) to Lead field names.
# Lets _find_bad_field identify any field from a ValidationError, not just link fields.
_FIELD_LABEL_TO_NAME = {
	"salutation":   "salutation",
	"first name":   "first_name",
	"middle name":  "middle_name",
	"last name":    "last_name",
	"gender":       "gender",
	"job title":    "job_title",
	"email id":     "email_id",
	"email":        "email_id",
	"mobile no":    "mobile_no",
	"mobile":       "mobile_no",
	"whatsapp no":  "whatsapp_no",
	"whatsapp":     "whatsapp_no",
	"phone":        "phone",
	"phone ext":    "phone_ext",
	"company name": "company_name",
	"company":      "company_name",
	"website":      "website",
	"fax":          "fax",
	"address line 1": "address_line1",
	"address line 2": "address_line2",
	"city":           "city",
	"state":          "state",
	"country":        "country",
	"pincode":        "pincode",
	"postal code":    "pincode",
	"zip code":       "pincode",
	"pin code":       "pincode",
}


def _find_bad_field(error_msg, data):
	"""
	Parse a Frappe ValidationError message and return the Lead field name
	that caused it, or None if it cannot be determined.
	"""
	import re
	# "Could not find {DocType}: {value}" — Link field resolution failure
	m = re.search(r"Could not find ([\w ]+):", error_msg)
	if m:
		doctype = m.group(1).strip()
		field = _LINK_DOCTYPE_TO_FIELD.get(doctype) or _LINK_DOCTYPE_TO_FIELD.get(doctype.lower())
		if field and field in data:
			return field
	# Check if any field's current value appears verbatim in the error message
	for field, value in data.items():
		if value and str(value) in error_msg:
			return field
	# Check if any field label appears in the error message
	# (e.g. "Value for Gender must be one of …", "Invalid Email Id")
	err_lower = error_msg.lower()
	for label, field in _FIELD_LABEL_TO_NAME.items():
		if label in err_lower and field in data:
			return field
	return None


def _create_lead_address(lead_name, address_data, address_type="Office"):
	"""Create an Address record linked to the given Lead.

	Invalid fields are stripped one-by-one and retried (same pattern as lead creation).
	Any skipped fields are noted as a comment on the Lead. Errors are always logged,
	never raised — address failure must not prevent lead creation.
	"""
	try:
		remaining = dict(address_data)
		skipped = {}

		# address_line1 is mandatory in Frappe's Address doctype.
		# The AI extracts city/state/country but never address_line1, so fall back to
		# the lead's company name (or the lead name itself) to satisfy the constraint.
		company_name = frappe.db.get_value("Lead", lead_name, "company_name") or lead_name
		if not remaining.get("address_line1"):
			remaining["address_line1"] = company_name

		# Sanitize pincode — strip spaces and non-digit characters so "395 007" → "395007"
		if remaining.get("pincode"):
			clean_pin = re.sub(r"\D", "", remaining["pincode"])
			if clean_pin:
				remaining["pincode"] = clean_pin
			else:
				remaining.pop("pincode")

		for _attempt in range(len(remaining) + 1):
			if not remaining:
				break
			try:
				address = frappe.get_doc({
					"doctype": "Address",
					"address_title": company_name,
					"address_type": address_type,
					"address_line1": remaining.get("address_line1"),
					"address_line2": remaining.get("address_line2"),
					"city": remaining.get("city"),
					"state": remaining.get("state"),
					"pincode": remaining.get("pincode"),
					"country": remaining.get("country"),
					"links": [{"link_doctype": "Lead", "link_name": lead_name}],
				})
				address.insert(ignore_permissions=True)
				frappe.db.commit()
				break
			except frappe.ValidationError as e:
				frappe.db.rollback()
				bad_field = _find_bad_field(str(e), remaining)
				if bad_field:
					skipped[bad_field] = remaining.pop(bad_field)
				else:
					raise
		else:
			raise frappe.ValidationError("All address fields were invalid; address could not be created.")

		if skipped:
			try:
				lines = ["<b>NextIQ: the following address fields were skipped (invalid values):</b><ul>"]
				for f, v in skipped.items():
					lines.append(f"<li><b>{f}</b>: {v}</li>")
				lines.append("</ul>")
				frappe.get_doc({
					"doctype": "Comment",
					"comment_type": "Info",
					"reference_doctype": "Lead",
					"reference_name": lead_name,
					"content": "".join(lines),
				}).insert(ignore_permissions=True)
				frappe.db.commit()
			except Exception:
				frappe.log_error(f"NextIQ: Failed to post skipped-fields comment for Lead {lead_name}", frappe.get_traceback())

	except Exception as e:
		frappe.log_error(f"NextIQ: Address creation failed for Lead {lead_name}", frappe.get_traceback())
		# Leave a comment on the Lead so the sales rep can add the address manually
		try:
			err_str = str(e)
			lines = ["<b>NextIQ: Address could not be created automatically.</b>"]
			if err_str:
				lines.append(f"<br><b>Reason:</b> {html.escape(err_str)}")
			if address_data:
				lines.append("<br>Address data extracted from the card:<ul>")
				for f, v in address_data.items():
					if v:
						lines.append(f"<li><b>{f}</b>: {html.escape(str(v))}</li>")
				lines.append("</ul>")
			lines.append("<p>Please add the address manually to this lead.</p>")
			frappe.get_doc({
				"doctype": "Comment",
				"comment_type": "Info",
				"reference_doctype": "Lead",
				"reference_name": lead_name,
				"content": "".join(lines),
			}).insert(ignore_permissions=True)
			frappe.db.commit()
		except Exception:
			pass


def _create_erpnext_lead(data, address_data, scanned_by, log_name):
	"""Create an ERPNext Lead from scan data. Raises on failure."""
	skipped_fields = {}
	lead_name = None

	_orig_user = frappe.session.user
	try:
		frappe.set_user(scanned_by or "Administrator")

		for _attempt in range(len(data) + 1):
			try:
				lead_doc_data = {"doctype": "Lead", **data}
				if scanned_by and scanned_by != "Guest":
					lead_doc_data["lead_owner"] = scanned_by
				lead = frappe.get_doc(lead_doc_data)
				lead.insert(ignore_permissions=True)
				frappe.db.commit()
				lead_name = lead.name
				break
			except frappe.exceptions.DuplicateEntryError:
				raise
			except frappe.ValidationError as e:
				frappe.db.rollback()
				bad_field = _find_bad_field(str(e), data)
				if bad_field:
					skipped_fields[bad_field] = data.pop(bad_field)
				else:
					raise
		else:
			raise frappe.ValidationError("All fields were invalid; no lead could be created.")

		if skipped_fields:
			frappe.db.set_value("Lead", lead_name, {f: None for f in skipped_fields})
			lines = ["<b>NextIQ: the following fields were skipped (invalid values):</b><ul>"]
			for f, v in skipped_fields.items():
				lines.append(f"<li><b>{f}</b>: {v}</li>")
			lines.append("</ul>")
			frappe.get_doc({
				"doctype": "Comment",
				"comment_type": "Info",
				"reference_doctype": "Lead",
				"reference_name": lead_name,
				"content": "".join(lines),
			}).insert(ignore_permissions=True)
			frappe.db.commit()

		for addr_type, addr_fields in (address_data or []):
			_create_lead_address(lead_name, addr_fields, addr_type)
	finally:
		frappe.set_user(_orig_user)

	return lead_name


def _create_crm_lead(data, scanned_by, log_name):
	"""Create a Frappe CRM Lead from scan data. Address fields are dropped — CRM Lead has none."""
	crm_data = {
		_CRM_FIELD_REMAP.get(k, k): v
		for k, v in data.items()
		if k not in _CRM_DROP_FIELDS
	}

	# CRM Lead requires first_name — use organization name as fallback for company-only cards
	if not crm_data.get("first_name") and crm_data.get("organization"):
		crm_data["first_name"] = crm_data["organization"]

	skipped_fields = {}
	lead_name = None

	_orig_user = frappe.session.user
	try:
		# Run as scanned_by: fixes CRM Lead assign_to() permission check in after_insert
		frappe.set_user(scanned_by or "Administrator")

		for _attempt in range(len(crm_data) + 1):
			try:
				doc = {"doctype": "CRM Lead", **crm_data}
				if scanned_by and scanned_by != "Guest":
					doc["lead_owner"] = scanned_by
				lead = frappe.get_doc(doc)
				lead.insert(ignore_permissions=True)
				frappe.db.commit()
				lead_name = lead.name
				break
			except frappe.exceptions.DuplicateEntryError:
				raise
			except frappe.ValidationError as e:
				frappe.db.rollback()
				bad_field = _find_bad_field(str(e), crm_data)
				if bad_field:
					skipped_fields[bad_field] = crm_data.pop(bad_field)
				else:
					raise
		else:
			raise frappe.ValidationError("All CRM Lead fields were invalid; no CRM Lead could be created.")

		if skipped_fields:
			lines = ["<b>NextIQ: the following fields were skipped (invalid values):</b><ul>"]
			for f, v in skipped_fields.items():
				lines.append(f"<li><b>{f}</b>: {v}</li>")
			lines.append("</ul>")
			frappe.get_doc({
				"doctype": "Comment",
				"comment_type": "Info",
				"reference_doctype": "CRM Lead",
				"reference_name": lead_name,
				"content": "".join(lines),
			}).insert(ignore_permissions=True)
			frappe.db.commit()
	finally:
		frappe.set_user(_orig_user)

	return lead_name


class _QuotaExceededError(Exception):
    pass


# ── Helpers ──────────────────────────────────────────────────────────────────


def _get_client_ip():
	"""
	Return the best-available client IP.

	Priority:
	  1. X-Real-IP   — set by nginx/trusted proxy; client cannot forge it.
	  2. X-Forwarded-For (rightmost valid entry) — added by the nearest trusted
	     proxy, not the client. The leftmost entry is client-controlled and forgeable.
	  3. remote_addr — correct when Frappe is directly exposed (no proxy).
	"""
	req = frappe.request
	real_ip = (req.headers.get("X-Real-IP") or "").strip()
	if real_ip:
		try:
			ipaddress.ip_address(real_ip)
			return real_ip
		except ValueError:
			pass
	forwarded = req.headers.get("X-Forwarded-For") or ""
	for candidate in reversed([x.strip() for x in forwarded.split(",") if x.strip()]):
		try:
			ipaddress.ip_address(candidate)
			return candidate
		except ValueError:
			continue
	return req.remote_addr or "unknown"


def _rate_limit(key, max_per_minute):
	"""
	Sliding-window rate limit via Redis INCR + EXPIRE.
	Returns True (allow) or False (block).
	Fails open if Redis is unavailable.
	"""
	try:
		pipe = frappe.cache().redis_client.pipeline()
		pipe.incr(key)
		pipe.expire(key, 60)
		count = pipe.execute()[0]
		return count <= max_per_minute
	except Exception:
		frappe.logger("nextiq").warning(
			f"Rate limit Redis check failed for key '{key}' — allowing (fail-open)"
		)
		return True


# ── Public endpoints (called from card-scan portal JS) ───────────────────────

@frappe.whitelist()
def submit_card_scan(merged_image_base64, filename="business_card.jpg", notes=None,
                     voice_clips=None):
	"""
	Receive merged business card image + optional voice clips from the portal.
	voice_clips: JSON array of {base64, mime} objects (up to 3).

	Generates job_id + cb_secret, saves image + audio files, enqueues _fire_scan_to_service.
	Returns immediately: {"log_name": str}
	"""
	# Block if the installed app is below the service-required minimum version
	_service_min = frappe.db.get_value(
		"NextIQ Settings", "NextIQ Settings", "service_min_version"
	) or ""
	if _service_min and _version_lt(nextiq.__version__, _service_min):
		frappe.throw(
			"The NextIQ app on this site requires an update before scanning can continue. "
			"Please ask your administrator to update the app.",
			title="App Update Required",
		)

	# Rate limit: 10 scans per minute per user
	_user_hash = hashlib.sha256(frappe.session.user.encode()).hexdigest()
	if not _rate_limit(f"nextiq_scan:{_user_hash}", max_per_minute=10):
		frappe.throw(
			"Too many scan requests. Please wait a moment and try again.",
			title="Rate Limited",
		)

	if "," in merged_image_base64:
		merged_image_base64 = merged_image_base64.split(",")[1]

	MAX_B64 = 10 * 1024 * 1024
	if len(merged_image_base64) > MAX_B64:
		frappe.throw("Image is too large (max 7.5 MB). Please use a smaller image.", title="Image Too Large")

	notes_clean = re.sub(r"<[^>]+>", "", str(notes or "")).strip()[:2000] or None

	# Parse voice clips — browser sends JSON string or list
	if isinstance(voice_clips, str):
		try:
			import json as _json
			voice_clips = _json.loads(voice_clips)
		except Exception:
			voice_clips = []
	if not isinstance(voice_clips, list):
		voice_clips = []
	voice_clips = voice_clips[:3]  # hard cap at 3

	job_id    = secrets.token_urlsafe(32)
	cb_secret = secrets.token_urlsafe(32)

	log = frappe.get_doc({
		"doctype": "Card Scan Log",
		"status": "Pending",
		"submitted_at": frappe.utils.now(),
		"job_id": job_id,
		"cb_secret": cb_secret,
		"scanned_by": frappe.session.user,
		"notes": notes_clean,
	})
	log.insert(ignore_permissions=True)
	frappe.db.commit()

	# Save merged image
	try:
		file_doc = frappe.get_doc({
			"doctype": "File",
			"file_name": f"card_scan_{log.name}.jpg",
			"content": base64.b64decode(merged_image_base64),
			"is_private": 1,
			"attached_to_doctype": "Card Scan Log",
			"attached_to_name": log.name,
		})
		file_doc.save(ignore_permissions=True)
		frappe.db.set_value("Card Scan Log", log.name, "merged_image", file_doc.file_url)
		frappe.db.commit()
	except Exception as e:
		frappe.db.set_value("Card Scan Log", log.name, {
			"status": "Failed",
			"error_message": f"Image save failed: {str(e)[:400]}",
			"processed_at": frappe.utils.now(),
		})
		frappe.db.commit()
		return {"log_name": log.name}

	# Save each voice clip as a private file; store URLs on the log
	saved_clips = []   # [{url, mime}]
	for idx, clip in enumerate(voice_clips):
		if not isinstance(clip, dict) or not clip.get("base64"):
			continue
		try:
			b64 = clip["base64"]
			if "," in b64:
				b64 = b64.split(",")[1]
			mime = (str(clip.get("mime") or "audio/webm"))[:50]
			ext  = "mp4" if "mp4" in mime else ("ogg" if "ogg" in mime else "webm")
			audio_doc = frappe.get_doc({
				"doctype": "File",
				"file_name": f"voice_{log.name}_{idx + 1}.{ext}",
				"content": base64.b64decode(b64),
				"is_private": 1,
				"attached_to_doctype": "Card Scan Log",
				"attached_to_name": log.name,
			})
			audio_doc.save(ignore_permissions=True)
			saved_clips.append({"url": audio_doc.file_url, "mime": mime})
		except Exception:
			frappe.log_error(
				f"NextIQ: Voice clip {idx+1} save failed for {log.name}",
				frappe.get_traceback())

	# Store clip URLs in voice_audio, voice_audio_2, voice_audio_3
	if saved_clips:
		clip_fields = {}
		field_names = ["voice_audio", "voice_audio_2", "voice_audio_3"]
		for i, c in enumerate(saved_clips[:3]):
			clip_fields[field_names[i]] = c["url"]
		frappe.db.set_value("Card Scan Log", log.name, clip_fields)
		frappe.db.commit()

	frappe.enqueue(
		"nextiq.api._fire_scan_to_service",
		log_name=log.name,
		saved_clips=saved_clips,
		queue="long",
		timeout=60,
		now=False,
	)

	return {"log_name": log.name}


@frappe.whitelist(allow_guest=True)
def scan_callback(job_id, cb_secret, success, data=None, error=None,
                  message=None, scans_used=None, scans_allowed=None, scans_remaining=None,
                  voice_notes=None):
	"""
	Called by nextiq_service when scan processing is complete.

	Security:
	  - allow_guest=True is intentional — this is server-to-server, no session exists.
	  - cb_secret is a single-use token generated by nextiq.test at submit time.
	  - Comparison uses hmac.compare_digest to prevent timing attacks.
	  - cb_secret is cleared from DB after first successful callback (prevents replay).
	"""
	# Rate limit: 60 callbacks per minute per IP — real service sends 1 per scan
	remote_ip = _get_client_ip()
	if not _rate_limit(f"nextiq_cb:{remote_ip}", max_per_minute=60):
		return {"success": False, "error": "rate_limited"}

	if not job_id or not cb_secret:
		return {"success": False, "error": "missing_params"}

	log_data = frappe.db.get_value(
		"Card Scan Log", {"job_id": job_id}, ["name", "scanned_by"], as_dict=True
	)
	if not log_data:
		return {"success": False, "error": "invalid_job_id"}
	log_name = log_data.name
	scanned_by = log_data.scanned_by

	# Constant-time secret comparison — prevents timing-based enumeration
	stored_secret = frappe.db.get_value("Card Scan Log", log_name, "cb_secret") or ""
	if not stored_secret or not hmac.compare_digest(stored_secret, str(cb_secret)):
		frappe.log_error(
			"NextIQ: Callback Auth Failed",
			f"Invalid cb_secret received for job_id={job_id}",
		)
		return {"success": False, "error": "invalid_secret"}

	# Idempotency guard — if already terminal, accept silently (handles callback retries)
	current_status = frappe.db.get_value("Card Scan Log", log_name, "status")
	if current_status not in ("Pending", "Processing"):
		return {"success": True, "note": "already_processed"}

	# Explicit cast — prevents "false" string being truthy when sent form-encoded
	success = success if isinstance(success, bool) else str(success).lower() == "true"

	if success:
		lead_name = None
		crm_lead_name = None
		address_data = []   # list of (address_type, fields_dict)
		original_data = dict(data) if data and isinstance(data, dict) else {}
		if data and isinstance(data, dict):
			# Pull the nested address block out first — service sends it as {"address": [...]}
			# Each item is {"address_type": "Office"/"Other", ...address fields...}
			raw_address = data.pop("address", None)
			if isinstance(raw_address, dict):
				# Backward-compat: single address object (pre-LEP_V.0.0.4)
				raw_address = [raw_address]
			if isinstance(raw_address, list):
				for idx, addr_item in enumerate(raw_address):
					if not isinstance(addr_item, dict):
						continue
					addr_type = addr_item.get("address_type", "Office" if idx == 0 else "Other")
					addr_fields = {
						k: str(v)[:_MAX_FIELD_LEN]
						for k, v in addr_item.items()
						if k in _ADDRESS_FIELDS and v not in (None, "")
					}
					if addr_fields:
						address_data.append((addr_type, addr_fields))
			# Validate and truncate remaining flat lead fields
			data = {
				k: str(v)[:_MAX_FIELD_LEN]
				for k, v in data.items()
				if k in _ALLOWED_LEAD_FIELDS and v not in (None, "")
			}
		if data:
			destination = frappe.db.get_value(
				"NextIQ Settings", "NextIQ Settings", "lead_destination"
			) or "ERPNext"
			installed = frappe.get_installed_apps()
			make_erpnext = destination in ("ERPNext", "Both") and "erpnext" in installed
			make_crm = destination in ("Frappe CRM", "Both") and "crm" in installed

			try:
				if make_erpnext:
					lead_name = _create_erpnext_lead(data.copy(), address_data, scanned_by, log_name)

				if make_crm:
					if destination == "Both":
						# Best-effort in Both mode — ERPNext may already have succeeded
						try:
							crm_lead_name = _create_crm_lead(data.copy(), scanned_by, log_name)
						except Exception:
							frappe.log_error(
								f"NextIQ: CRM Lead creation failed for {log_name}",
								traceback.format_exc(),
							)
					else:
						crm_lead_name = _create_crm_lead(data.copy(), scanned_by, log_name)

				_apply_voice_notes(lead_name, voice_notes, scanned_by)
				if crm_lead_name:
					_apply_crm_voice_notes(crm_lead_name, voice_notes, scanned_by)

				# Add raw written note only when AI produced no summary (note already in AI summary otherwise)
				ai_has_summary = bool((voice_notes or {}).get("summary_note"))
				if not ai_has_summary:
					if lead_name:
						_append_scan_note(lead_name, log_name, scanned_by)
					if crm_lead_name:
						_append_crm_lead_note(crm_lead_name, log_name, scanned_by)

				if lead_name:
					_append_media_comment("Lead", lead_name, log_name)
				if crm_lead_name:
					_append_media_comment("CRM Lead", crm_lead_name, log_name, comment_type="Comment")

			except frappe.exceptions.DuplicateEntryError as e:
				err_msg = str(e)[:500] or "A lead with this email address already exists."
				frappe.db.rollback()
				frappe.db.set_value("Card Scan Log", log_name, {
					"status": "Duplicate Lead",
					"error_message": err_msg,
					"processed_at": frappe.utils.now(),
					"cb_secret": "",
				})
				frappe.db.commit()
				_send_scan_notification(log_name, "duplicate_lead", message=err_msg)
				return {"success": False, "error": "duplicate_lead"}
			except frappe.ValidationError as e:
				err_msg = str(e)[:500] or "AI data could not be saved as a Lead — all field values were invalid."
				frappe.db.rollback()
				frappe.db.set_value("Card Scan Log", log_name, {
					"status": "Invalid Data",
					"error_message": err_msg,
					"ai_response": frappe.as_json({"lead": original_data or {}, "voice_notes": voice_notes or {}}),
					"processed_at": frappe.utils.now(),
					"cb_secret": "",
				})
				frappe.db.commit()
				_send_scan_notification(log_name, "invalid_data", message=err_msg)
				frappe.enqueue(
					"nextiq.api._send_feedback_to_service",
					log_name=log_name,
					feedback_type="Invalid Data",
					queue="short",
					timeout=30,
					now=False,
				)
				return {"success": False, "error": "invalid_lead_data"}
			except Exception as e:
				frappe.log_error(f"NextIQ: Lead creation failed for {log_name}", traceback.format_exc())
				err_msg = str(e)[:500] or "Lead could not be created from scan data."
				frappe.db.rollback()
				frappe.db.set_value("Card Scan Log", log_name, {
					"status": "Failed",
					"error_message": err_msg,
					"processed_at": frappe.utils.now(),
					"cb_secret": "",
				})
				frappe.db.commit()
				_send_scan_notification(log_name, "failed", message=err_msg)
				frappe.enqueue(
					"nextiq.api._send_feedback_to_service",
					log_name=log_name,
					feedback_type="Failed",
					queue="short",
					timeout=30,
					now=False,
				)
				return {"success": False, "error": "lead_creation_failed"}

		success_fields = {
			"status": "Success",
			"lead": lead_name,
			"processed_at": frappe.utils.now(),
			"ai_response": frappe.as_json({"lead": original_data or {}, "voice_notes": voice_notes or {}}),
			"cb_secret": "",   # single-use — clear after successful callback
		}
		if "crm" in frappe.get_installed_apps():
			success_fields["crm_lead"] = crm_lead_name
		if scans_remaining is not None:
			success_fields["scans_remaining"] = scans_remaining
		frappe.db.set_value("Card Scan Log", log_name, success_fields)
		frappe.db.commit()
		_send_scan_notification(log_name, "success",
			lead_name=lead_name, scans_remaining=scans_remaining)

	else:
		status_map = {
			"quota_exceeded":     "Quota Exceeded",
			"not_a_business_card": "Invalid Image",
			"processing_failed":  "Failed",
			"suspended":          "Failed",
		}
		status = status_map.get(error or "", "Failed")

		update_fields = {
			"status": status,
			"error_message": message or "Scan failed.",
			"processed_at": frappe.utils.now(),
			"cb_secret": "",   # clear regardless of outcome
		}
		if scans_remaining is not None:
			update_fields["scans_remaining"] = scans_remaining
		frappe.db.set_value("Card Scan Log", log_name, update_fields)
		frappe.db.commit()
		_send_scan_notification(log_name, error or "failed",
			message=message, scans_remaining=scans_remaining)

	return {"success": True}


# ── Background job ────────────────────────────────────────────────────────────

def _fire_scan_to_service(log_name, saved_clips=None):
	"""
	Lightweight RQ job: load image + voice clips, fire to nextiq_service.
	saved_clips: list of {url, mime} dicts saved by submit_card_scan.
	"""
	logger = frappe.logger("nextiq")
	logger.info(f"[NextIQ] Firing scan to service: {log_name}")

	try:
		frappe.db.set_value("Card Scan Log", log_name, "status", "Processing")
		frappe.db.commit()

		access_token = _get_valid_access_token()

		log = frappe.get_doc("Card Scan Log", log_name)
		if not log.merged_image:
			raise Exception("No image attached to this log.")
		if not log.job_id or not log.cb_secret:
			raise Exception("Scan log is missing job credentials. Please re-submit.")

		# Load image
		file_doc     = frappe.get_doc("File", {"file_url": log.merged_image})
		image_base64 = base64.b64encode(file_doc.get_content()).decode()

		# Load voice clips from saved file URLs
		voice_clips_payload = []
		for clip_info in (saved_clips or []):
			if not isinstance(clip_info, dict) or not clip_info.get("url"):
				continue
			try:
				af = frappe.get_doc("File", {"file_url": clip_info["url"]})
				voice_clips_payload.append({
					"base64": base64.b64encode(af.get_content()).decode(),
					"mime":   clip_info.get("mime", "audio/webm"),
				})
			except Exception:
				frappe.log_error(f"NextIQ: Voice clip load failed for {log_name} — skipping", frappe.get_traceback())

		callback_url = frappe.utils.get_url() + "/api/method/nextiq.api.scan_callback"
		logger.info(f"[NextIQ] Calling service at {SERVICE_URL}, job_id={log.job_id}")

		payload = {
			"image_base64":    image_base64,
			"filename":        log.merged_image.split("/")[-1] if log.merged_image else "business_card.jpg",
			"job_id":          log.job_id,
			"callback_url":    callback_url,
			"cb_secret":       log.cb_secret,
			"customer_log_id": log.name,
			"notes":           log.notes or "",
			"scanned_by":      log.scanned_by,
			"today":           frappe.utils.today(),
		}
		if voice_clips_payload:
			payload["voice_clips"] = voice_clips_payload

		try:
			response = requests.post(
				f"{SERVICE_URL}/api/method/nextiq_service.api.process_scan",
				json=payload,
				headers={
					"Content-Type":            "application/json",
					"Authorization":           f"Bearer {access_token}",
					"X-NextIQ-Client-Version": nextiq.__version__,
				},
				timeout=15,  # service should accept in <1s — short timeout
			)
		except requests.exceptions.ConnectionError:
			raise Exception(
				f"Cannot reach NextIQ Service at {SERVICE_URL}. "
				"Please contact support."
			)
		except requests.exceptions.Timeout:
			raise Exception(
				"NextIQ Service did not accept the job in time. "
				"The service may be down. Please try again."
			)

		if response.status_code == 503:
			raise Exception("NextIQ Service is temporarily unavailable (503). Please try again.")
		elif response.status_code == 502:
			raise Exception("NextIQ Service returned a bad gateway error (502). Please try again.")
		elif response.status_code >= 500:
			raise Exception(f"NextIQ Service returned a server error ({response.status_code}).")
		elif response.status_code == 402:
			raise _QuotaExceededError("Scan quota exhausted. Please contact the NextIQ team to top up.")
		elif response.status_code in (401, 403):
			frappe.log_error(
				"NextIQ: Service Auth Rejected",
				f"NextIQ Service rejected scan request with {response.status_code}. Response: {getattr(response, 'text', '-')[:500]}",
			)
			try:
				s = frappe.get_single("NextIQ Settings")
				s.connection_status = "Suspended" if response.status_code == 403 else "Not Connected"
				s.save(ignore_permissions=True)
				frappe.db.commit()
			except Exception:
				frappe.log_error("NextIQ: Failed to update connection_status after 401/403", frappe.get_traceback())
			raise Exception(
				f"NextIQ Service rejected the request ({response.status_code}). "
				"Please reconnect via NextIQ Settings."
			)
		elif response.status_code >= 400:
			raise Exception(f"NextIQ Service returned error {response.status_code}.")

		result = response.json().get("message", {})

		if result.get("error"):
			# Synchronous rejection (e.g. missing params, invalid key)
			raise Exception(result.get("message", "Service rejected the request."))

		if not result.get("queued"):
			raise Exception("Service did not confirm job was queued.")

		logger.info(
			f"[NextIQ] Job accepted. job_id={log.job_id}. "
			"RQ worker done — result will arrive via scan_callback."
		)
		# RQ job ends here in <1s. Lead creation happens in scan_callback.

	except _QuotaExceededError as e:
		logger.warning(f"[NextIQ] Quota exceeded for scan {log_name}: {e}")
		frappe.db.set_value("Card Scan Log", log_name, {
			"status": "Quota Exceeded",
			"error_message": str(e)[:1000],
			"processed_at": frappe.utils.now(),
		})
		frappe.db.commit()
		_send_scan_notification(log_name, "quota_exceeded", message=str(e))
	except Exception as e:
		logger.error(f"[NextIQ] Failed to fire scan {log_name}: {e}\n{traceback.format_exc()}")
		frappe.log_error(f"NextIQ: Fire Scan Failed: {log_name}", traceback.format_exc())
		frappe.db.set_value("Card Scan Log", log_name, {
			"status": "Failed",
			"error_message": str(e)[:1000],
			"processed_at": frappe.utils.now(),
		})
		frappe.db.commit()
		_send_scan_notification(log_name, "failed", message=str(e))


# ── Notes helper ─────────────────────────────────────────────────────────────

def _append_media_comment(ref_doctype, ref_name, log_name, comment_type="Info"):
	"""Post scanned card image and voice clips as a comment on the lead. Fails silently."""
	try:
		log = frappe.db.get_value(
			"Card Scan Log", log_name,
			["merged_image", "voice_audio", "voice_audio_2", "voice_audio_3"],
			as_dict=True,
		)
		if not log:
			return

		lines = []

		if log.merged_image:
			escaped = html.escape(log.merged_image)
			lines.append(
				f'<p><b>Business Card:</b></p>'
				f'<p><img src="{escaped}" style="max-width:500px;border-radius:4px;"></p>'
			)

		for label, url in (
			("Voice Note 1", log.voice_audio),
			("Voice Note 2", log.voice_audio_2),
			("Voice Note 3", log.voice_audio_3),
		):
			if url:
				escaped = html.escape(url)
				lines.append(
					f'<p><b>{label}:</b><br>'
					f'<audio controls src="{escaped}" style="width:100%;max-width:420px;"></audio></p>'
				)

		if not lines:
			return

		frappe.get_doc({
			"doctype": "Comment",
			"comment_type": comment_type,
			"reference_doctype": ref_doctype,
			"reference_name": ref_name,
			"content": "".join(lines),
		}).insert(ignore_permissions=True)
		frappe.db.commit()
	except Exception:
		frappe.log_error(
			f"NextIQ: Media comment failed for {ref_doctype} {ref_name}",
			frappe.get_traceback(),
		)


def _append_scan_note(lead_name, log_name, scanned_by):
	"""Add the user's scan-time note to the Lead's notes child table. Fails silently."""
	try:
		log_notes = frappe.db.get_value("Card Scan Log", log_name, "notes")
		if not log_notes or not lead_name:
			return
		note_html = "<p>" + html.escape(str(log_notes)).replace("\n", "<br>") + "</p>"
		lead_doc = frappe.get_doc("Lead", lead_name)
		lead_doc.append("notes", {
			"note": note_html,
			"added_by": scanned_by,
			"added_on": frappe.utils.now_datetime(),
		})
		lead_doc.save(ignore_permissions=True)
		frappe.db.commit()
	except Exception:
		frappe.log_error(
			f"NextIQ: Note append failed for Lead {lead_name}",
			frappe.get_traceback(),
		)


# ── CRM Lead note helper ─────────────────────────────────────────────────────

def _append_crm_lead_note(crm_lead_name, log_name, scanned_by):
	"""Add the scan-time written note to the CRM Lead as an FCRM Note. Fails silently."""
	try:
		log_notes = frappe.db.get_value("Card Scan Log", log_name, "notes")
		if not log_notes or not crm_lead_name:
			return
		note_html = "<p>" + html.escape(str(log_notes)).replace("\n", "<br>") + "</p>"
		frappe.get_doc({
			"doctype": "FCRM Note",
			"title": "Scan Note",
			"content": note_html,
			"reference_doctype": "CRM Lead",
			"reference_docname": crm_lead_name,
		}).insert(ignore_permissions=True)
		frappe.db.commit()
	except Exception:
		frappe.log_error(
			f"NextIQ: Note append failed for CRM Lead {crm_lead_name}",
			frappe.get_traceback(),
		)


# ── Bilingual text helpers ────────────────────────────────────────────────────

def _bi_html(en, native):
	"""
	Return HTML combining English + native text.
	- Strips any trailing (...) the AI may have already appended to `en`.
	- Only adds native in parentheses when it differs from `en` AND contains
	  non-ASCII characters (actual script, not a transliteration duplicate).
	"""
	en_clean = re.sub(r"\s*\([^)]*\)\s*$", "", str(en or "")).strip() or str(en or "")
	nat      = str(native or "").strip()
	if nat and nat != en_clean and any(ord(c) > 127 for c in nat):
		return en_clean + "<p><em>(" + nat.replace("<p>", "").replace("</p>", "") + ")</em></p>"
	return en_clean or str(en or "")


def _bi_inline(en, native, max_len=100):
	"""
	Return 'English (Native)' inline string for subjects/titles.
	Same guard: native must differ from en and contain non-ASCII script.
	"""
	en_clean = re.sub(r"\s*\([^)]*\)\s*$", "", str(en or "")).strip() or str(en or "")
	nat      = str(native or "").strip()
	if nat and nat != en_clean and any(ord(c) > 127 for c in nat):
		return f"{en_clean} ({nat})"[:max_len]
	return en_clean[:max_len]


# ── Voice notes helper ───────────────────────────────────────────────────────

def _apply_voice_notes(lead_name, voice_notes, scanned_by):
	"""
	Create ERPNext summary note, ToDo tasks, and Events from AI-extracted voice note data.
	Fails silently — voice note errors must never block the lead creation flow.
	"""
	if not lead_name or not voice_notes or not isinstance(voice_notes, dict):
		return

	summary_note = voice_notes.get("summary_note") or ""
	tasks        = voice_notes.get("tasks") or []
	events       = voice_notes.get("events") or []

	if not summary_note and not tasks and not events:
		return

	_orig_user = frappe.session.user
	try:
		# Run as scanned_by so all created records are owned by the real user
		# (Private events owned by Guest are invisible in the Event list)
		frappe.set_user(scanned_by or "Administrator")

		# ── Summary note ───────────────────────────────────────────────────────
		if summary_note.strip():
			try:
				lead_doc = frappe.get_doc("Lead", lead_name)
				lead_doc.append("notes", {
					"note":     summary_note,
					"added_by": scanned_by or frappe.session.user,
					"added_on": frappe.utils.now_datetime(),
				})
				lead_doc.save(ignore_permissions=True)
				frappe.db.commit()
			except Exception:
				frappe.log_error(f"NextIQ: ERPNext Note failed for Lead {lead_name}", frappe.get_traceback())

		# ── Tasks (ToDo) ────────────────────────────────────────────────────────
		try:
			for task in tasks:
				if not isinstance(task, dict) or not task.get("description"):
					continue
				task_html = _bi_html(task.get("description", ""), task.get("description_native"))
				frappe.get_doc({
					"doctype":        "ToDo",
					"status":         "Open",
					"priority":       "Medium",
					"description":    task_html[:2000],
					"date":           (task.get("date") or frappe.utils.today())[:10],
					"reference_type": "Lead",
					"reference_name": lead_name,
					"allocated_to":   scanned_by or frappe.session.user,
				}).insert(ignore_permissions=True)
			if tasks:
				frappe.db.commit()
		except Exception:
			frappe.log_error(f"NextIQ: ERPNext Tasks failed for Lead {lead_name}", frappe.get_traceback())

		# ── Events ─────────────────────────────────────────────────────────────
		_VALID_CATEGORIES = {"Event", "Meeting", "Call", "Sent/Received Email", "Other"}
		try:
			for event in events:
				if not isinstance(event, dict) or not event.get("subject"):
					continue
				category = event.get("event_category", "Meeting")
				if category not in _VALID_CATEGORIES:
					category = "Other"
				starts_on    = event.get("starts_on") or str(frappe.utils.today())
				full_subject = _bi_inline(event.get("subject", ""), event.get("subject_native"), max_len=100)
				event_desc   = _bi_html(event.get("description", ""), event.get("description_native"))
				frappe.get_doc({
					"doctype":           "Event",
					"subject":           full_subject,
					"event_category":    category,
					"starts_on":         starts_on,
					"description":       event_desc[:2000],
					"status":            "Open",
					"event_type":        "Private",
					"event_participants": [{
						"reference_doctype": "Lead",
						"reference_docname": lead_name,
					}],
				}).insert(ignore_permissions=True)
			if events:
				frappe.db.commit()
		except Exception:
			frappe.log_error(f"NextIQ: ERPNext Events failed for Lead {lead_name}", frappe.get_traceback())

	finally:
		frappe.set_user(_orig_user)


# ── CRM voice notes helper ───────────────────────────────────────────────────

def _apply_crm_voice_notes(crm_lead_name, voice_notes, scanned_by):
	"""
	Create FCRM Note, CRM Tasks, and Events from AI-extracted voice note data for a CRM Lead.
	Mirrors _apply_voice_notes but uses CRM-native doctypes.
	Fails silently — errors must never block lead creation.
	"""
	if not crm_lead_name or not voice_notes or not isinstance(voice_notes, dict):
		return

	summary_note = voice_notes.get("summary_note") or ""
	tasks        = voice_notes.get("tasks") or []
	events       = voice_notes.get("events") or []

	if not summary_note and not tasks and not events:
		return

	_orig_user = frappe.session.user
	try:
		# Run as scanned_by: fixes CRM Task assign_to() permission check
		# and ensures all records are owned by the real user (not Guest)
		frappe.set_user(scanned_by or "Administrator")

		# ── Summary note as FCRM Note ─────────────────────────────────────────
		if summary_note.strip():
			try:
				frappe.get_doc({
					"doctype":           "FCRM Note",
					"title":             "Scan Note",
					"content":           summary_note,
					"reference_doctype": "CRM Lead",
					"reference_docname": crm_lead_name,
				}).insert(ignore_permissions=True)
				frappe.db.commit()
			except Exception:
				frappe.log_error(f"NextIQ: CRM Note failed for {crm_lead_name}", frappe.get_traceback())

		# ── Tasks as CRM Task ─────────────────────────────────────────────────
		try:
			for task in tasks:
				if not isinstance(task, dict) or not task.get("description"):
					continue
				task_html = _bi_html(task.get("description", ""), task.get("description_native"))
				title = re.sub(r"<[^>]+>", "", re.sub(r"\s*\([^)]*\)\s*$", "", str(task.get("description", ""))).strip()).strip()[:140] or "Task"
				frappe.get_doc({
					"doctype":           "CRM Task",
					"title":             title,
					"description":       task_html[:2000],
					"status":            "Todo",
					"priority":          "Medium",
					"due_date":          (task.get("date") or frappe.utils.today())[:10],
					"assigned_to":       scanned_by or frappe.session.user,
					"reference_doctype": "CRM Lead",
					"reference_docname": crm_lead_name,
				}).insert(ignore_permissions=True)
			if tasks:
				frappe.db.commit()
		except Exception:
			frappe.log_error(f"NextIQ: CRM Tasks failed for {crm_lead_name}", frappe.get_traceback())

		# ── Events ───────────────────────────────────────────────────────────
		_VALID_CATEGORIES = {"Event", "Meeting", "Call", "Sent/Received Email", "Other"}
		try:
			for event in events:
				if not isinstance(event, dict) or not event.get("subject"):
					continue
				category = event.get("event_category", "Meeting")
				if category not in _VALID_CATEGORIES:
					category = "Other"
				starts_on    = event.get("starts_on") or str(frappe.utils.today())
				full_subject = _bi_inline(event.get("subject", ""), event.get("subject_native"), max_len=100)
				event_desc   = _bi_html(event.get("description", ""), event.get("description_native"))
				frappe.get_doc({
					"doctype":            "Event",
					"subject":            full_subject,
					"event_category":     category,
					"starts_on":          starts_on,
					"description":        event_desc[:2000],
					"status":             "Open",
					"event_type":         "Private",
					"reference_doctype":  "CRM Lead",
					"reference_docname":  crm_lead_name,
					"event_participants": [{
						"reference_doctype": "CRM Lead",
						"reference_docname": crm_lead_name,
					}],
				}).insert(ignore_permissions=True)
			if events:
				frappe.db.commit()
		except Exception:
			frappe.log_error(f"NextIQ: CRM Events failed for {crm_lead_name}", frappe.get_traceback())

	finally:
		frappe.set_user(_orig_user)


# ── Feedback to service ───────────────────────────────────────────────────────

def _send_feedback_to_service(log_name, feedback_type):
	"""
	Fire scan feedback to nextiq_service for model training.

	Runs as an enqueued background job — errors are logged, never raised,
	so they never affect the customer-facing scan flow.
	"""
	try:
		log = frappe.get_doc("Card Scan Log", log_name)
		settings = frappe.get_single("NextIQ Settings")
		if settings.connection_status != "Connected" or not settings.oauth_access_token:
			return

		try:
			access_token = _get_valid_access_token()
		except Exception:
			return

		requests.post(
			f"{SERVICE_URL}/api/method/nextiq_service.api.receive_scan_feedback",
			json={
				"job_id":          log.job_id,
				"feedback_type":   feedback_type,
				"error_message":   log.error_message or "",
				"ai_response":     log.ai_response or "",
				"customer_log_id": log.name,
			},
			headers={
				"Content-Type":  "application/json",
				"Authorization": f"Bearer {access_token}",
			},
			timeout=15,
		)
	except Exception:
		frappe.log_error(
			f"NextIQ: Feedback Send Failed: {log_name}",
			frappe.get_traceback(),
		)


# ── Email notification ────────────────────────────────────────────────────────

def _send_scan_notification(log_name, outcome, lead_name=None, message=None, scans_remaining=None):
	"""Send email to the ERPNext user who submitted the scan."""
	try:
		owner = frappe.db.get_value("Card Scan Log", log_name, "owner")
		user_email = frappe.db.get_value("User", owner, "email")
		if not user_email:
			return

		if outcome == "quota_exceeded":
			frappe.sendmail(
				recipients=[user_email],
				subject="[NextIQ] Scan quota exhausted",
				message=(
					"<p>Your scan quota is exhausted. No more scans can be processed.</p>"
					"<p>Please contact the NextIQ team to increase your quota.</p>"
				),
				delayed=False,
			)

		elif outcome == "failed":
			frappe.sendmail(
				recipients=[user_email],
				subject="[NextIQ] Card scan failed",
				message=(
					"<p>Your card scan could not be completed.</p>"
					+ (f"<p><strong>Reason:</strong> {message}</p>" if message else "")
					+ "<p>Please try scanning again.</p>"
				),
				delayed=False,
			)

	except Exception:
		frappe.log_error(
			f"NextIQ: Email notification failed for {log_name}",
			frappe.get_traceback(),
		)


# ── Lead destination helper ──────────────────────────────────────────────────

@frappe.whitelist()
def get_installed_lead_destinations():
	"""Return which lead-capable apps are installed. Used by NextIQ Settings JS to filter options."""
	installed = frappe.get_installed_apps()
	return {
		"has_erpnext": "erpnext" in installed,
		"has_crm":     "crm" in installed,
	}


# ── Time saved metric ────────────────────────────────────────────────────────

@frappe.whitelist()
def get_time_saved_minutes():
	"""Number Card data source: successful leads × 2 minutes per lead."""
	count = frappe.db.count("Card Scan Log", {"status": "Success"})
	return (count or 0) * 2


# ── Live balance proxy ────────────────────────────────────────────────────────

@frappe.whitelist()
def get_live_balance():
	"""
	Fetch live scan balance from nextiq_service.

	Requires a valid Frappe login session — API key is read server-side from
	NextIQ Settings and never exposed to the browser.

	Returns the service response dict, or {"success": False, ...} on error.
	"""
	access_token = _get_valid_access_token()

	try:
		resp = requests.get(
			f"{SERVICE_URL}/api/method/nextiq_service.api.check_quota",
			headers={
				"Authorization": f"Bearer {access_token}",
				"Content-Type":  "application/json",
			},
			timeout=10,
		)
	except requests.exceptions.ConnectionError:
		frappe.throw(f"Cannot reach NextIQ Service at {SERVICE_URL}.",
					 title="Connection Error")
	except requests.exceptions.Timeout:
		frappe.throw("NextIQ Service did not respond in time.", title="Timeout")

	if resp.status_code == 429:
		frappe.throw("Balance check rate limit reached. Please wait a moment.",
					 title="Rate Limited")
	if resp.status_code >= 400:
		frappe.throw(f"NextIQ Service returned error {resp.status_code}.",
					 title="Service Error")

	return resp.json().get("message", {})
