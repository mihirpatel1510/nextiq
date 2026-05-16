frappe.ui.form.on("NextIQ Settings", {
	refresh(frm) {
		// Filter lead_destination options to only apps that are installed
		frappe.call({
			method: "nextiq.api.get_installed_lead_destinations",
			callback(r) {
				if (!r.message) return;
				const { has_erpnext, has_crm } = r.message;
				let options = [];
				if (has_erpnext) options.push("ERPNext");
				if (has_crm)     options.push("Frappe CRM");
				if (has_erpnext && has_crm) options.push("Both");
				frm.set_df_property("lead_destination", "options", options.join("\n"));
				if (options.length && !options.includes(frm.doc.lead_destination)) {
					frm.set_value("lead_destination", options[0]);
				}
			},
		});

		const connected = frm.doc.connection_status === "Connected";

		if (!connected) {
			frm.add_custom_button(__("Connect to NextIQ Service"), function () {
				_startOAuthConnect(frm);
			}, __("Actions"));
		} else {
			frm.add_custom_button(__("Disconnect"), function () {
				frappe.confirm(
					__("Disconnect from NextIQ Service? This will revoke the OAuth token."),
					function () {
						frappe.call({
							method: "nextiq.oauth.disconnect",
							callback(r) {
								frm.reload_doc();
								frappe.show_alert({ message: __("Disconnected from NextIQ Service."), indicator: "orange" });
							},
						});
					}
				);
			}, __("Actions"));
		}

		frm.add_custom_button(__("Check Updates"), function () {
			frappe.show_alert({ message: __("Checking version status…"), indicator: "blue" });
			frappe.call({
				method: "nextiq.version_check.check_service_version",
				callback(r) {
					if (r.exc) {
						frappe.show_alert({ message: __("Version check failed. Check the Error Log."), indicator: "red" });
						return;
					}
					if (!r.message) {
						frappe.show_alert({ message: __("Version check failed. Verify your connection."), indicator: "red" });
						return;
					}
					frm.reload_doc();
					frappe.show_alert({ message: __("Version status updated."), indicator: "green" });
					frappe.boot.nextiq_update = r.message;
					frappe._nextiq_notifications_shown = false;
					nextiq.show_update_notifications();
				},
			});
		}, __("Actions"));
	},
});


// ── OAuth connect ─────────────────────────────────────────────────────────────

async function _startOAuthConnect(frm) {
	try {
		frappe.show_alert({ message: __("Starting OAuth connect…"), indicator: "blue" });

		// All PKCE + state generation is done server-side (crypto.subtle requires HTTPS)
		const session = await frappe.xcall("nextiq.oauth.begin_oauth", {
			site: window.location.origin,
		});

		const params = new URLSearchParams({
			response_type:         "code",
			client_id:             session.client_id,
			redirect_uri:          session.relay_url,
			scope:                 "openid all",
			state:                 session.state,
			code_challenge:        session.challenge,
			code_challenge_method: "S256",
		});

		window.location.href = `${session.service_url}/api/method/frappe.integrations.oauth2.authorize?${params}`;
	} catch (e) {
		frappe.show_alert({ message: __("Connect failed. Check the console for details."), indicator: "red" });
		console.error("NextIQ OAuth connect error:", e);
	}
}
