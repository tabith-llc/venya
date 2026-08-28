/**
 * Admin enrollment page client logic.
 *
 * Flow:
 * 1. User enters username, clicks "Enroll Security Key"
 * 2. POST /api/v1/init -> WebAuthn registration challenge
 * 3. startRegistration() -> browser prompts for security key touch
 * 4. POST /api/v1/init/complete -> store credential
 * 5. Show success modal with recovery code (stays until acknowledged)
 */

(function () {
    "use strict";

    var form = document.getElementById("enroll-form");
    var usernameInput = document.getElementById("username-input");
    var enrollBtn = document.getElementById("enroll-btn");
    var messageDiv = document.getElementById("message");
    var successModal = document.getElementById("success-modal");
    var successUsername = document.getElementById("success-username");
    var recoveryCodeBox = document.getElementById("recovery-code-box");
    var acknowledgeBtn = document.getElementById("acknowledge-btn");

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
        usernameInput.disabled = loading;
    }

    function showSuccess(username, recoveryCode) {
        successUsername.textContent = username;
        recoveryCodeBox.textContent = recoveryCode;
        successModal.hidden = false;
    }

    function hideSuccess() {
        successModal.hidden = true;
        messageDiv.textContent = "Success! It is now safe to close this browser window.";
        messageDiv.className = "message message-success";
        messageDiv.hidden = false;
    }

    async function startEnrollment(username) {
        clearMessage();
        setLoading(true);

        try {
            // Step 1: Get challenge from /api/v1/init
            var initResp = await fetch("/api/v1/init", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ user_id: username }),
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
                    user_id: username,
                    challenge_id: init_data.challenge_id,
                    response: registrationResponse,
                }),
            });

            if (!completeResp.ok) {
                var data = await completeResp.json().catch(function () { return {}; });
                throw new Error(data.detail || "Enrollment failed");
            }

            var result = await completeResp.json();
            showSuccess(username, result.recovery_code);
        } catch (err) {
            showMessage(err.message || "Enrollment failed. Please try again.", "error");
        } finally {
            setLoading(false);
        }
    }

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        var username = usernameInput.value.trim();
        if (!username) {
            showMessage("Please enter a username.", "error");
            return;
        }
        if (username.length > 64) {
            showMessage("Username must be 64 characters or fewer.", "error");
            return;
        }
        if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
            showMessage("Username can only contain letters, numbers, hyphens, and underscores.", "error");
            return;
        }
        startEnrollment(username);
    });

    acknowledgeBtn.addEventListener("click", hideSuccess);
})();
