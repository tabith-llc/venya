/**
 * Admin enrollment page client logic.
 *
 * Flow:
 * 1. User clicks "Enroll Security Key"
 * 2. POST /api/v1/init → WebAuthn registration challenge
 * 3. startRegistration() → browser prompts for security key touch
 * 4. POST /api/v1/init/complete → store credential
 * 5. Redirect to / on success
 */

(function () {
    "use strict";

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
        enrollBtn.textContent = loading ? "Enrolling..." : "Enroll Security Key";
    }

    async function startEnrollment() {
        clearMessage();
        setLoading(true);

        try {
            // Step 1: Get challenge from /api/v1/init
            var initResp = await fetch("/api/v1/init", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ user_id: "admin-1" }),
            });

            if (!initResp.ok) {
                var data = await initResp.json().catch(function () { return {}; });
                throw new Error(data.detail || "Failed to get enrollment challenge");
            }

            var init_data = await initResp.json();
            var options = init_data.options;

            // Step 2: WebAuthn registration
            var registrationResponse = await VenyaWebAuthn.startRegistration(options);

            // Step 3: Complete enrollment via /api/v1/init/complete
            var completeResp = await fetch("/api/v1/init/complete", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    user_id: "admin-1",
                    challenge_id: init_data.challenge_id,
                    response: registrationResponse,
                }),
            });

            if (!completeResp.ok) {
                var data = await completeResp.json().catch(function () { return {}; });
                throw new Error(data.detail || "Enrollment failed");
            }

            var result = await completeResp.json();
            showMessage("Enrollment successful! Recovery code: " + result.recovery_code + ". Redirecting to login...", "success");
            setTimeout(function () {
                window.location.href = "/";
            }, 3000);
        } catch (err) {
            showMessage(err.message || "Enrollment failed. Please try again.", "error");
        } finally {
            setLoading(false);
        }
    }

    enrollBtn.addEventListener("click", startEnrollment);
})();
