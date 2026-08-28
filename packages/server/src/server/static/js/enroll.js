/**
 * Enrollment page client logic.
 *
 * Flow:
 * 1. User enters enrollment token, submits form
 * 2. POST /api/v1/enroll/browser → WebAuthn registration challenge
 * 3. startRegistration() → browser prompts for passkey creation
 * 4. POST /api/v1/enroll/browser/complete → store credential, consume token
 * 5. Redirect to / on success
 */

(function () {
    "use strict";

    const form = document.getElementById("enroll-form");
    const tokenInput = document.getElementById("token");
    const enrollBtn = document.getElementById("enroll-btn");
    const messageDiv = document.getElementById("message");

    /**
     * Show a message to the user.
     * @param {string} text - Message text.
     * @param {"error"|"success"} type - Message type.
     */
    function showMessage(text, type) {
        messageDiv.textContent = text;
        messageDiv.className = "message message-" + type;
        messageDiv.hidden = false;
    }

    /**
     * Clear the message display.
     */
    function clearMessage() {
        messageDiv.textContent = "";
        messageDiv.className = "message";
        messageDiv.hidden = true;
    }

    /**
     * Toggle UI loading state.
     * @param {boolean} loading - Whether the UI is loading.
     */
    function setLoading(loading) {
        enrollBtn.disabled = loading;
        enrollBtn.textContent = loading ? "Enrolling..." : "Enroll";
        tokenInput.disabled = loading;
    }

    /**
     * Get the API base path.
     * @returns {string}
     */
    function apiBase() {
        return "/api/v1";
    }

    /**
     * Step 1: Request enrollment challenge from the server.
     * @param {string} token - The enrollment token.
     * @returns {Promise<{challenge_id: string, options: object}>}
     */
    async function requestEnrollmentChallenge(token) {
        const resp = await fetch(apiBase() + "/enroll/browser", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enrollment_token: token }),
        });

        if (!resp.ok) {
            const data = await resp.json().catch(() => ({}));
            throw new Error(data.detail || "Failed to start enrollment");
        }

        return resp.json();
    }

    /**
     * Step 2: Complete enrollment by submitting the attestation response.
     * @param {string} token - The enrollment token.
     * @param {string} challengeId - The challenge ID.
     * @param {object} response - The WebAuthn attestation response.
     * @returns {Promise<object>}
     */
    async function completeEnrollment(token, challengeId, response) {
        const resp = await fetch(apiBase() + "/enroll/browser/complete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                enrollment_token: token,
                challenge_id: challengeId,
                response: response,
                label: "Security Key",
            }),
        });

        if (!resp.ok) {
            const data = await resp.json().catch(() => ({}));
            throw new Error(data.detail || "Enrollment failed");
        }

        return resp.json();
    }

    /**
     * Check if the browser supports WebAuthn.
     * @returns {boolean}
     */
    function webauthnSupported() {
        return (
            typeof window !== "undefined" &&
            typeof window.PublicKeyCredential === "function" &&
            typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
        );
    }

    /**
     * Main enrollment handler.
     * @param {Event} event - The form submit event.
     */
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

            var registrationResponse = await VenyaWebAuthn.startRegistration(options);

            await completeEnrollment(token, challenge.challenge_id, registrationResponse);

            showMessage("Success! It is now safe to close this browser window.", "success");
        } catch (err) {
            if (err.message && err.message.indexOf("already been used") !== -1) {
                showMessage("This enrollment token has already been used.", "error");
            } else if (err.message && err.message.indexOf("expired") !== -1) {
                showMessage("This enrollment token has expired. Request a new one.", "error");
            } else if (err.message && err.message.indexOf("invalidated") !== -1) {
                showMessage("This enrollment token has been invalidated due to too many failed attempts.", "error");
            } else if (err.message && err.message.indexOf("not supported") !== -1) {
                showMessage("Your security key does not support this authentication method.", "error");
            } else {
                showMessage(err.message || "Enrollment failed. Please try again.", "error");
            }
        } finally {
            setLoading(false);
        }
    }

    form.addEventListener("submit", handleEnroll);
})();
