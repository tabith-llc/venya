/**
 * Login page client logic.
 *
 * Flow:
 * 1. User enters username, clicks "Login"
 * 2. POST /api/v1/auth/login/browser/challenge -> WebAuthn challenge
 * 3. startAuthentication() -> browser prompts for security key touch
 * 4. POST /api/v1/auth/login/browser/assert -> verify assertion, set session cookie
 * 5. Redirect to /dashboard on success
 */

(function () {
    "use strict";

    var form = document.getElementById("login-form");
    var usernameInput = document.getElementById("username");
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
        var btn = document.getElementById("login-btn");
        btn.disabled = loading;
        btn.textContent = loading ? "Logging in..." : "Login";
        usernameInput.disabled = loading;
    }

    async function login(username) {
        clearMessage();
        setLoading(true);

        try {
            // Step 1: Get challenge from server
            var resp = await fetch("/api/v1/auth/login/browser/challenge", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ user_id: username }),
            });

            if (!resp.ok) {
                var data = await resp.json().catch(function () { return {}; });
                throw new Error(data.detail || "Login failed");
            }

            var challengeData = await resp.json();
            var options = challengeData.options;

            // Step 2: WebAuthn assertion via virtual/hardware authenticator
            var assertionResponse = await VenyaWebAuthn.startAuthentication(options);

            // Step 3: Submit assertion to server
            var assertResp = await fetch("/api/v1/auth/login/browser/assert", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    challenge_id: challengeData.challenge_id,
                    response: assertionResponse,
                }),
            });

            if (!assertResp.ok) {
                var errData = await assertResp.json().catch(function () { return {}; });
                throw new Error(errData.detail || "Authentication failed");
            }

            // Success — browser should have set session cookie
            showMessage("Success! It is now safe to close this browser window.", "success");
        } catch (err) {
            showMessage(err.message || "Login failed. Please try again.", "error");
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
        login(username);
    });
})();
