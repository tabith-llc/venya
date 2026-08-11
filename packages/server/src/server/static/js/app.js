/**
 * Login page client logic.
 *
 * Flow:
 * 1. User enters user_id, clicks login
 * 2. POST /api/v1/auth/login/browser/challenge → WebAuthn authentication challenge
 * 3. startAuthentication() → browser prompts for security key touch
 * 4. POST /api/v1/auth/login/browser/assert → sets HttpOnly cookie
 * 5. Redirect to /dashboard on success
 */

(function () {
    "use strict";

    var form = document.getElementById("login-form");
    var userIdInput = document.getElementById("user_id");
    var loginBtn = document.getElementById("login-btn");
    var messageDiv = document.getElementById("message");

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
        loginBtn.disabled = loading;
        loginBtn.textContent = loading ? "Authenticating..." : "Login";
        userIdInput.disabled = loading;
    }

    /**
     * Get the API base path.
     * @returns {string}
     */
    function apiBase() {
        return "/api/v1";
    }

    /**
     * Step 1: Request authentication challenge from the server.
     * @param {string} userId - The user ID.
     * @returns {Promise<{challenge_id: string, options: object}>}
     */
    async function requestChallenge(userId) {
        var body = {};
        if (userId) {
            body.user_id = userId;
        }

        var resp = await fetch(apiBase() + "/auth/login/browser/challenge", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });

        if (!resp.ok) {
            var data = await resp.json().catch(function () { return {}; });
            throw new Error(data.detail || "Failed to get authentication challenge");
        }

        return resp.json();
    }

    /**
     * Step 2: Submit the authentication assertion to the server.
     * @param {string} challengeId - The challenge ID.
     * @param {object} response - The WebAuthn authentication response.
     * @returns {Promise<void>}
     */
    async function submitAssertion(challengeId, response) {
        var resp = await fetch(apiBase() + "/auth/login/browser/assert", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                challenge_id: challengeId,
                response: response,
            }),
        });

        if (!resp.ok) {
            var data = await resp.json().catch(function () { return {}; });
            throw new Error(data.detail || "Authentication failed");
        }
    }

    /**
     * Check if the browser supports WebAuthn.
     * @returns {boolean}
     */
    function webauthnSupported() {
        return (
            typeof window !== "undefined" &&
            typeof window.PublicKeyCredential === "function"
        );
    }

    /**
     * Main login handler.
     * @param {Event} event - The form submit event.
     */
    async function handleLogin(event) {
        event.preventDefault();
        clearMessage();

        var userId = userIdInput.value.trim();

        if (!userId) {
            showMessage("Please enter your user ID.", "error");
            return;
        }

        if (!webauthnSupported()) {
            showMessage("WebAuthn is not supported in this browser. Please use a modern browser.", "error");
            return;
        }

        setLoading(true);

        try {
            var challenge = await requestChallenge(userId);
            var options = challenge.options;

            var authenticationResponse = await VenyaWebAuthn.startAuthentication(options);

            await submitAssertion(challenge.challenge_id, authenticationResponse);

            window.location.href = "/dashboard";
        } catch (err) {
            if (err.message && err.message.indexOf("not found") !== -1) {
                showMessage("No credentials found for this user ID.", "error");
            } else if (err.message && err.message.indexOf("Invalid") !== -1) {
                showMessage("Authentication failed. Please try again with your security key.", "error");
            } else if (err.message && err.message.indexOf("Challenge") !== -1) {
                showMessage("Authentication challenge expired. Please try again.", "error");
            } else {
                showMessage(err.message || "Login failed. Please try again.", "error");
            }
        } finally {
            setLoading(false);
        }
    }

    form.addEventListener("submit", handleLogin);
})();
