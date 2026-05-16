import nextiq
import frappe
import requests

from nextiq.constants import SERVICE_URL


def _version_lt(v1, v2):
	"""Return True if semver v1 < v2. Ignores pre-release suffixes."""
	def _parse(v):
		return tuple(int(x) for x in v.lstrip("v").split("-")[0].split(".")[:3])
	try:
		return _parse(v1) < _parse(v2)
	except Exception:
		return False


@frappe.whitelist()
def check_service_version():
	"""
	Hourly scheduled job — also callable manually from NextIQ Settings form.
	Fetches version requirements from NextIQ Service and caches the result
	in NextIQ Settings for the boot session to read.
	"""
	try:
		settings = frappe.get_single("NextIQ Settings")
		if settings.connection_status != "Connected" or not settings.oauth_access_token:
			return

		from nextiq.api import _get_valid_access_token
		try:
			access_token = _get_valid_access_token()
		except Exception:
			return

		response = requests.get(
			f"{SERVICE_URL}/api/method/nextiq_service.api.get_service_info",
			headers={
				"Authorization":           f"Bearer {access_token}",
				"X-NextIQ-Client-Version": nextiq.__version__,
			},
			timeout=10,
		)
		response.raise_for_status()

		data = response.json().get("message", {})
		if not data.get("success"):
			frappe.log_error(
				f"get_service_info returned: {data}",
				"NextIQ: version check failed",
			)
			return

		min_version  = data.get("min_client_version") or "0.0.1"
		needs_update = _version_lt(nextiq.__version__, min_version)

		frappe.db.set_value("NextIQ Settings", "NextIQ Settings", {
			"service_min_version":    min_version,
			"needs_mandatory_update": 1 if needs_update else 0,
			"version_last_checked":   frappe.utils.now_datetime(),
		})
		frappe.db.commit()
		frappe.clear_document_cache("NextIQ Settings", "NextIQ Settings")
		# Force all sessions to re-compute boot banner on next full page load
		try:
			frappe.cache().delete_key("bootinfo")
		except Exception:
			pass

		return {
			"mandatory":       needs_update,
			"current_version": nextiq.__version__,
			"min_version":     min_version,
		}

	except requests.exceptions.ConnectionError:
		frappe.logger("nextiq").warning("NextIQ: version check skipped — service unreachable")
	except Exception:
		frappe.log_error(frappe.get_traceback(), "NextIQ: check_service_version failed")
