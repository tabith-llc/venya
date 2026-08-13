/**
 * Enrollment page client logic.
 *
 * Flow:
 * 1. User enters enrollment token, submits form
 * 2. POST /api/v1/enroll/browser/start -> WebAuthn registration challenge
 * 3. User enters credential label
 * 4. startRegistration() -> browser prompts for passkey creation
 * 5. POST /api/v1/enroll/browser/complete -> store credential, consume token
 * 6. Redirect to / on success
 */

(function () {
    "use strict";

    var form = document.getElementById("enroll-form");
    var tokenInput = document.getElementById("token");
    var enrollBtn = document.getElementById("enroll-btn");
    var messageDiv = document.getElementById("message");

    function showMessage(text, type) {
        messageDiv.textContent = text;
        messageDiv.className = "message message-" + type;
        messageDiv.hidden = false;
    }

    function clearMessage() {
        messageDiv.textContent = "";
        messageDiv.className = "message";
        messageDiv.hidden = true;
    }

    function setLoading(loading) {
        enrollBtn.disabled = loading;
        enrollBtn.textContent = loading ? "Enrolling..." : "Enroll";
        tokenInput.disabled = loading;
    }

    function apiBase() {
        return "/api/v1";
    }

    async function requestEnrollmentChallenge(enrollmentToken) {
        var resp = await fetch(apiBase() + "/enroll/browser/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enrollment_token: enrollmentToken }),
        });

        if (!resp.ok) {
            var data = await resp.json().catch(function () { return ({}); });
            throw new Error(data.detail || "Failed to start enrollment");
        }

        return resp.json();
    }

    async function completeEnrollment(enrollmentToken, challengeId, response, label) {
        var resp = await fetch(apiBase() + "/enroll/browser/complete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                enrollment_token: enrollmentToken,
                challenge_id: challengeId,
                response: response,
                label: label,
            }),
        });

        if (!resp.ok) {
            var data = await resp.json().catch(function () { return ({}); });
            throw new Error(data.detail || "Enrollment failed");
        }

        return resp.json();
    }

    function promptCredentialLabel() {
        return new Promise(function (resolve, reject) {
            var overlay = document.createElement("div");
            overlay.className = "modal-overlay";
            overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.4);display:flex;align-items:center;justify-content:center;z-index:1000;";

            var modal = document.createElement("div");
            modal.className = "modal";
            modal.innerHTML = '<h2 class="modal-title">Name Your Security Key</h2>' +
                '<form id="label-form">' +
                '<label>Label<input type="text" id="credential-label" placeholder="e.g. MacBook Pro" required></label>' +
                '<div class="modal-buttons">' +
                '<button type="button" id="label-cancel" class="btn-secondary">Cancel</button>' +
                '<button type="submit" id="label-submit" class="btn-primary">Continue</button>' +
                '</div></form>';

            overlay.appendChild(modal);
            document.body.appendChild(overlay);

            var labelInput = document.getElementById("credential-label");
            if (labelInput) labelInput.focus();

            var cancelBtn = document.getElementById("label-cancel");
            var submitBtn = document.getElementById("label-submit");

            if (cancelBtn) {
                cancelBtn.addEventListener("click", function () {
                    document.body.removeChild(overlay);
                    reject(new Error("Enrollment cancelled"));
                });
            }

            var labelForm = document.getElementById("label-form");
            if (labelForm) {
                labelForm.addEventListener("submit", function (e) {
                    e.preventDefault();
                    var label = labelInput ? labelInput.value.trim() : "";
                    if (!label) {
                        if (labelInput) labelInput.focus();
                        return;
                    }
                    document.body.removeChild(overlay);
                    resolve(label);
                });
            }
        });
    }

    function webauthnSupported() {
        return (
            typeof window !== "undefined" &&
            typeof window.PublicKeyCredential === "function" &&
            typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
        );
    }

    async function handleEnroll(event) {
        event.preventDefault();
        clearMessage();

        var token = tokenInput.value.trim();

        if (!token) {
            showMessage("Please enter an enrollment token.", "error");
            return;
        }

        if (!webauthnSupported()) {
            showMessage("WebAuthn is not supported in this browser. Please use a modern browser.", "error");
            return;
        }

        setLoading(true);

        try {
            var challenge = await requestEnrollmentChallenge(token);
            var options = challenge.options;

            var label = await promptCredentialLabel();

            var registrationResponse = await VenyaWebAuthn.startRegistration(options);

            await completeEnrollment(token, challenge.challenge_id, registrationResponse, label);

            showMessage("Enrollment successful! Redirecting to login...", "success");
            setTimeout(function () {
                window.location.href = "/";
            }, 1500);
        } catch (err) {
            if (err.message && err.message.indexOf("already been used") !== -1) {
                showMessage("This enrollment token has already been used.", "error");
            } else if (err.message && err.message.indexOf("expired") !== -1) {
                showMessage("This enrollment token has expired. Request a new one.", "error");
            } else if (err.message && err.message.indexOf("invalidated") !== -1) {
                showMessage("This enrollment token has been invalidated due to too many failed attempts.", "error");
            } else if (err.message && err.message.indexOf("not supported") !== -1) {
                showMessage("Your security key does not support this authentication method.", "error");
            } else if (err.message && err.message.indexOf("cancelled") !== -1) {
                clearMessage();
            } else {
                showMessage(err.message || "Enrollment failed. Please try again.", "error");
            }
        } finally {
            setLoading(false);
        }
    }

    form.addEventListener("submit", handleEnroll);
})();
