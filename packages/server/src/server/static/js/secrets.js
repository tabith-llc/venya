/**
 * Secrets management UI.
 *
 * Features:
 * - List secrets with masked values
 * - Store new secrets via modal
 * - Unmask with re-authentication (WebAuthn elevation)
 * - Delete with confirmation
 * - Auto-hide unmasked values after 30 seconds
 * - Session timeout handling with form state preservation
 */

(function () {
    "use strict";

    var API_BASE = "/api/v1";
    var AUTO_HIDE_TIMEOUT = 30000; // 30 seconds
    var STORE_FORM_STATE_KEY = "venya_store_form_state";
    var REFRESH_INTERVAL = 240000; // 4 minutes (token lives 5 min)

    // In-memory form state for session recovery
    var pendingFormState = null;

    // Track active auto-hide timers: { secretKey: timeoutId }
    var autoHideTimers = {};

    // Session refresh timer
    var refreshTimerId = null;

    // --- DOM elements ---

    var secretsTbody = document.getElementById("secrets-tbody");
    var storeSecretBtn = document.getElementById("store-secret-btn");
    var modalOverlay = document.getElementById("modal-overlay");
    var modalContent = document.getElementById("modal-content");
    var auditSection = document.getElementById("audit-section");
    var dashboardSection = document.getElementById("dashboard-section");

    // --- API helpers ---

    /**
     * Make a fetch request with cookie auth.
     * Handles 401 by redirecting to login and preserving form state.
     */
    async function apiFetch(url, options) {
        options = options || {};
        options.credentials = "include";
        if (!options.headers) {
            options.headers = {};
        }
        if (options.body && typeof options.body === "string") {
            options.headers["Content-Type"] = "application/json";
        }

        var resp = await fetch(url, options);

        if (!resp.ok) {
            var data;
            try {
                data = await resp.json();
            } catch (e) {
                data = {};
            }
            throw new Error(data.detail || "Request failed");
        }

        // Check if response is JSON
        var contentType = resp.headers.get("content-type") || "";
        if (contentType.indexOf("application/json") !== -1) {
            return resp.json();
        }
        return null;
    }

    // --- Session refresh (shared via session-refresh.js) ---


    // --- Session timeout handling ---

    function handleSessionExpired() {
        // Preserve form state if modal is open with data
        if (modalOverlay && !modalOverlay.hidden) {
            var keyInput = document.getElementById("secret-key-input");
            var valueInput = document.getElementById("secret-value-input");
            var roleSelect = document.getElementById("secret-role-select");

            if (keyInput || valueInput || roleSelect) {
                pendingFormState = {
                    key: keyInput ? keyInput.value : "",
                    value: valueInput ? valueInput.value : "",
                    roles: roleSelect ? roleSelect.value : "",
                };
                // Set in sessionStorage for recovery after re-login
                try {
                    sessionStorage.setItem(STORE_FORM_STATE_KEY, JSON.stringify(pendingFormState));
                } catch (e) {
                    // sessionStorage not available
                }
            }
        }

        window.location.href = "/";
    }

    function restoreFormState() {
        try {
            var saved = sessionStorage.getItem(STORE_FORM_STATE_KEY);
            if (!saved) return;
            var state = JSON.parse(saved);
            if (!state || !state.key && !state.value) return;

            var keyInput = document.getElementById("secret-key-input");
            var valueInput = document.getElementById("secret-value-input");
            var roleSelect = document.getElementById("secret-role-select");

            if (keyInput) keyInput.value = state.key || "";
            if (valueInput) valueInput.value = state.value || "";
            if (roleSelect) roleSelect.value = state.roles || "";

            // Clear after restoring
            sessionStorage.removeItem(STORE_FORM_STATE_KEY);
        } catch (e) {
            // Ignore parse errors
        }
    }

    // --- Navigation ---

    function handleHashChange() {
        var hash = window.location.hash;
        if (hash === "#audit" || hash === "") {
            if (auditSection) auditSection.hidden = false;
            if (dashboardSection) dashboardSection.hidden = true;
            if (auditSection) window.location.hash = "audit";
        } else if (hash === "#dashboard") {
            if (dashboardSection) dashboardSection.hidden = false;
            if (auditSection) auditSection.hidden = true;
        }
    }

    function showDashboard() {
        window.location.hash = "dashboard";
        if (dashboardSection) dashboardSection.hidden = false;
        if (auditSection) auditSection.hidden = true;
        startSessionRefresh();
    }

    function showAudit() {
        window.location.hash = "audit";
        if (auditSection) auditSection.hidden = false;
        if (dashboardSection) dashboardSection.hidden = true;
        stopSessionRefresh();
    }

    // --- Secrets table rendering ---

    function maskValue(value) {
        if (!value || value.length === 0) return "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
        var masked = "";
        for (var i = 0; i < value.length; i++) {
            masked += "\u2022";
        }
        return masked;
    }

    function renderSecrets(secrets) {
        if (!secretsTbody) return;
        secretsTbody.innerHTML = "";

        if (!secrets || secrets.length === 0) {
            var tr = document.createElement("tr");
            var td = document.createElement("td");
            td.colSpan = 4;
            td.textContent = "No secrets found.";
            tr.appendChild(td);
            secretsTbody.appendChild(tr);
            return;
        }

        for (var i = 0; i < secrets.length; i++) {
            var secret = secrets[i];
            var tr = document.createElement("tr");

            // Key column
            var keyTd = document.createElement("td");
            keyTd.textContent = secret.key;
            tr.appendChild(keyTd);

            // Roles column
            var rolesTd = document.createElement("td");
            if (secret.role_ids && secret.role_ids.length > 0) {
                rolesTd.textContent = secret.role_ids.join(", ");
            } else {
                rolesTd.textContent = "\u2014";
            }
            tr.appendChild(rolesTd);

            // Value column (masked by default, in <input readonly>)
            var valueTd = document.createElement("td");
            var valueInput = document.createElement("input");
            valueInput.type = "text";
            valueInput.className = "secret-value-input";
            valueInput.readOnly = true;
            valueInput.dataset.secretKey = secret.key;
            valueInput.value = maskValue("");
            valueInput.disabled = true;
            valueTd.appendChild(valueInput);
            tr.appendChild(valueTd);

            // Actions column
            var actionsTd = document.createElement("td");

            // Reveal button
            var revealBtn = document.createElement("button");
            revealBtn.className = "btn-reveal";
            revealBtn.textContent = "\u25B6"; // play triangle
            revealBtn.title = "Reveal secret";
            revealBtn.disabled = true;
            revealBtn.dataset.secretKey = secret.key;
            revealBtn.addEventListener("click", function () {
                revealSecret(this.dataset.secretKey, valueInput);
            });
            actionsTd.appendChild(revealBtn);

            // Delete button
            var deleteBtn = document.createElement("button");
            deleteBtn.className = "btn-delete";
            deleteBtn.textContent = "\u2716"; // X
            deleteBtn.title = "Delete secret";
            deleteBtn.disabled = true;
            deleteBtn.dataset.secretKey = secret.key;
            deleteBtn.addEventListener("click", function () {
                deleteSecret(this.dataset.secretKey);
            });
            actionsTd.appendChild(deleteBtn);

            tr.appendChild(actionsTd);
            secretsTbody.appendChild(tr);

            // Store the masked value for later unmasking
            secret._maskedElement = valueInput;
            secret._revealBtn = revealBtn;
            secret._deleteBtn = deleteBtn;
        }
    }

    // --- Reveal (unmask) flow ---

    async function revealSecret(secretKey, valueInput) {
        if (!valueInput) return;

        valueInput.value = "Authenticating...";
        valueInput.disabled = true;

        // Disable buttons during elevation
        var row = valueInput.closest("tr");
        if (row) {
            var revealBtn = row.querySelector(".btn-reveal");
            var deleteBtn = row.querySelector(".btn-delete");
            if (revealBtn) revealBtn.disabled = true;
            if (deleteBtn) deleteBtn.disabled = true;
        }

        try {
            // Step 1: Get elevation challenge
            var challengeData = await apiFetch(API_BASE + "/auth/elevate/browser/challenge", {
                method: "POST",
            });

            if (!challengeData) return; // 401 handled by apiFetch

            var options = challengeData.options;

            // Step 2: WebAuthn authentication
            var assertion = await VenyaWebAuthn.startAuthentication(options);

            // Step 3: Submit assertion, get elevation token back
            var assertResult = await apiFetch(API_BASE + "/auth/elevate/browser/assert", {
                method: "POST",
                body: JSON.stringify({
                    challenge_id: challengeData.challenge_id,
                    response: assertion,
                }),
            });

            if (!assertResult) return; // 401 handled

            var elevationToken = assertResult.elevation_token;
            if (!elevationToken) {
                throw new Error("No elevation token received");
            }

            // Step 4: Get secret with elevation token
            var secretData = await apiFetch(
                API_BASE + "/secrets/" + encodeURIComponent(secretKey) +
                "?unmask=true&elevation_token=" + encodeURIComponent(elevationToken)
            );

            if (!secretData) return; // 401 handled

            // Step 5: Display plaintext in readonly input
            valueInput.value = secretData.value;
            valueInput.disabled = false;
            valueInput.style.borderColor = "#f0c040";
            valueInput.style.backgroundColor = "#fff8e0";

            // Disable reveal/delete buttons during unmasked period
            if (row) {
                var rb = row.querySelector(".btn-reveal");
                var db = row.querySelector(".btn-delete");
                if (rb) rb.disabled = true;
                if (db) db.disabled = true;
            }

            // Start auto-hide timer
            startAutoHide(valueInput);

        } catch (err) {
            valueInput.value = maskValue("");
            valueInput.disabled = true;
            valueInput.style.borderColor = "";
            valueInput.style.backgroundColor = "";

            // Re-enable buttons
            if (row) {
                var rb = row.querySelector(".btn-reveal");
                var db = row.querySelector(".btn-delete");
                if (rb) rb.disabled = false;
                if (db) db.disabled = false;
            }

            showMessage("Failed to reveal secret: " + err.message, "error");
        }
    }

    // --- Store secret modal ---

    function openStoreModal() {
        if (!modalContent) return;

        modalContent.innerHTML = "";

        var form = document.createElement("form");
        form.id = "store-secret-form";

        var keyLabel = document.createElement("label");
        keyLabel.textContent = "Key";
        var keyInput = document.createElement("input");
        keyInput.type = "text";
        keyInput.id = "secret-key-input";
        keyInput.name = "key";
        keyInput.required = true;
        keyInput.placeholder = "Enter secret key";
        keyInput.autocomplete = "off";
        keyLabel.appendChild(keyInput);
        form.appendChild(keyLabel);

        var valueLabel = document.createElement("label");
        valueLabel.textContent = "Value";
        var valueInput = document.createElement("input");
        valueInput.type = "text";
        valueInput.id = "secret-value-input";
        valueInput.name = "value";
        valueInput.required = true;
        valueInput.placeholder = "Enter secret value";
        valueInput.autocomplete = "off";
        valueLabel.appendChild(valueInput);
        form.appendChild(valueLabel);

        var roleLabel = document.createElement("label");
        roleLabel.textContent = "Role";
        var roleSelect = document.createElement("select");
        roleSelect.id = "secret-role-select";
        roleSelect.name = "roles";
        roleSelect.required = true;
        var defaultOption = document.createElement("option");
        defaultOption.value = "";
        defaultOption.textContent = "Select a role";
        roleSelect.appendChild(defaultOption);

        // Load roles from API
        apiFetch(API_BASE + "/roles").then(function(data) {
            if (data && data.roles) {
                for (var i = 0; i < data.roles.length; i++) {
                    var opt = document.createElement("option");
                    opt.value = data.roles[i].name;
                    opt.textContent = data.roles[i].name;
                    roleSelect.appendChild(opt);
                }
            }
        }).catch(function(err) {
            console.error("Failed to load roles:", err);
        });

        roleLabel.appendChild(roleSelect);
        form.appendChild(roleLabel);

        var btnContainer = document.createElement("div");
        btnContainer.className = "modal-buttons";

        var submitBtn = document.createElement("button");
        submitBtn.type = "submit";
        submitBtn.className = "btn-primary";
        submitBtn.textContent = "Store";

        var cancelBtn = document.createElement("button");
        cancelBtn.type = "button";
        cancelBtn.className = "btn-secondary";
        cancelBtn.textContent = "Cancel";
        cancelBtn.addEventListener("click", closeStoreModal);

        btnContainer.appendChild(submitBtn);
        btnContainer.appendChild(cancelBtn);
        form.appendChild(btnContainer);

        form.addEventListener("submit", handleStoreSecret);

        modalContent.appendChild(form);
        modalOverlay.hidden = false;

        // Restore saved form state if available
        restoreFormState();

        // Focus key input
        setTimeout(function () {
            var ki = document.getElementById("secret-key-input");
            if (ki) ki.focus();
        }, 100);
    }

    function closeStoreModal() {
        if (modalOverlay) {
            modalOverlay.hidden = true;
        }
        if (modalContent) {
            modalContent.innerHTML = "";
        }
    }

    async function handleStoreSecret(event) {
        event.preventDefault();

        var keyInput = document.getElementById("secret-key-input");
        var valueInput = document.getElementById("secret-value-input");
        var roleSelect = document.getElementById("secret-role-select");

        var key = keyInput ? keyInput.value.trim() : "";
        var value = valueInput ? valueInput.value : "";
        var roles = roleSelect ? roleSelect.value : "";

        if (!key || !value || !roles) {
            showMessage("Please fill in all fields.", "error");
            return;
        }

        // Disable submit button
        var submitBtn = modalContent.querySelector('button[type="submit"]');
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.textContent = "Storing...";
        }

        try {
            var kvResponse = await apiFetch(API_BASE + "/key-versions/active");
            if (!kvResponse) return;
            var keyVersionId = kvResponse.key_version_id;

            var payload = {
                key: key,
                value: value,
                roles: [roles],
                key_version_id: keyVersionId,
            };

            var result = await apiFetch(API_BASE + "/secrets", {
                method: "POST",
                body: JSON.stringify(payload),
            });

            if (!result) return; // 401 handled

            showMessage("Secret stored successfully.", "success");
            closeStoreModal();
            loadSecrets();
        } catch (err) {
            showMessage("Failed to store secret: " + err.message, "error");
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = "Store";
            }
        }
    }

    // --- Delete secret ---

    async function deleteSecret(secretKey) {
        var confirmed = confirm("Delete secret '" + secretKey + "'? This cannot be undone.");
        if (!confirmed) return;

        try {
            var result = await apiFetch(API_BASE + "/secrets/" + encodeURIComponent(secretKey), {
                method: "DELETE",
            });

            if (!result) return; // 401 handled

            showMessage("Secret deleted.", "success");
            loadSecrets();
        } catch (err) {
            showMessage("Failed to delete secret: " + err.message, "error");
        }
    }

    // --- Load secrets ---

    async function loadSecrets() {
        if (!secretsTbody) return;
        secretsTbody.innerHTML = "";

        // Show loading state
        var tr = document.createElement("tr");
        var td = document.createElement("td");
        td.colSpan = 4;
        td.textContent = "Loading secrets...";
        tr.appendChild(td);
        secretsTbody.appendChild(tr);

        try {
            var data = await apiFetch(API_BASE + "/secrets");
            if (!data) return; // 401 handled

            renderSecrets(data.secrets);
        } catch (err) {
            secretsTbody.innerHTML = "";
            var tr = document.createElement("tr");
            var td = document.createElement("td");
            td.colSpan = 4;
            td.textContent = "Failed to load secrets: " + err.message;
            tr.appendChild(td);
            secretsTbody.appendChild(tr);
        }
    }

    // --- Message display ---

    function showMessage(text, type) {
        // Use a global message element if available, otherwise alert
        var msgDiv = document.getElementById("message");
        if (msgDiv) {
            msgDiv.textContent = text;
            msgDiv.className = "message message-" + type;
            msgDiv.hidden = false;
            setTimeout(function () {
                msgDiv.hidden = true;
            }, 5000);
        } else {
            // Fallback for dashboard page without message div
            alert(text);
        }
    }

    // --- Auto-hide timers ---

    function startAutoHide(inputEl) {
        // Clear any existing timer for this element
        var secretKey = inputEl.dataset.secretKey;
        if (secretKey && autoHideTimers[secretKey]) {
            clearTimeout(autoHideTimers[secretKey]);
        }

        autoHideTimers[secretKey] = setTimeout(function () {
            inputEl.value = maskValue("");
            inputEl.disabled = true;
            inputEl.style.borderColor = "";
            inputEl.style.backgroundColor = "";

            // Enable reveal/delete buttons
            var revealBtn = inputEl.parentElement.previousElementSibling
                ? inputEl.closest("tr").querySelector(".btn-reveal")
                : null;
            var deleteBtn = inputEl.closest("tr").querySelector(".btn-delete");
            if (revealBtn) revealBtn.disabled = false;
            if (deleteBtn) deleteBtn.disabled = false;

            delete autoHideTimers[secretKey];
        }, AUTO_HIDE_TIMEOUT);
    }

    // --- Event listeners ---

    // Store secret button
    if (storeSecretBtn) {
        storeSecretBtn.addEventListener("click", openStoreModal);
    }

    // Close modal on overlay click
    if (modalOverlay) {
        modalOverlay.addEventListener("click", function (e) {
            if (e.target === modalOverlay) {
                closeStoreModal();
            }
        });
    }

    // Nav links
    var navSecrets = document.getElementById("nav-secrets");
    var navAudit = document.getElementById("nav-audit");

    if (navSecrets) {
        navSecrets.addEventListener("click", function (e) {
            e.preventDefault();
            showDashboard();
        });
    }

    if (navAudit) {
        navAudit.addEventListener("click", function (e) {
            e.preventDefault();
            showAudit();
        });
    }

    // Hash change navigation
    window.addEventListener("hashchange", handleHashChange);

    // --- Initialize ---

    // Check if we're on the dashboard page
    if (secretsTbody || dashboardSection) {
        // Load user info for welcome bar
        initWelcomeBar();

        // Show/hide admin nav links
        initNavVisibility();

        // Load roles for the role selector
        loadSecrets();

        // Check for restored form state from session recovery
        restoreFormState();

        // Start session refresh timer
        startSessionRefresh();
    }

    // Expose for external use (e.g., audit.js)
    window.VenyaSecrets = {
        load: loadSecrets,
        showDashboard: showDashboard,
    };

    // --- Welcome bar ---

    async function initWelcomeBar() {
        var welcomeBar = document.getElementById("welcome-bar");
        var welcomeText = document.getElementById("welcome-text");
        if (!welcomeBar || !welcomeText) return;

        try {
            var me = await apiFetch(API_BASE + "/auth/me");
            if (me && me.display_name) {
                welcomeText.textContent = "Welcome, " + me.display_name + "!";
                welcomeBar.hidden = false;
            } else if (me && me.user_id) {
                welcomeText.textContent = "Welcome, " + me.user_id + "!";
                welcomeBar.hidden = false;
            }
        } catch (err) {
            // Silently fail — welcome bar stays hidden
        }
    }

    // --- Nav visibility ---

    async function initNavVisibility() {
        try {
            var me = await apiFetch(API_BASE + "/auth/me");
            if (!me || !me.roles) return;

            var isAdmin = false;
            for (var i = 0; i < me.roles.length; i++) {
                if (me.roles[i] === "admin") {
                    isAdmin = true;
                    break;
                }
            }

            var navUsers = document.getElementById("nav-users");
            var navTokens = document.getElementById("nav-tokens");

            if (!isAdmin) {
                if (navUsers) navUsers.style.display = "none";
                if (navTokens) navTokens.style.display = "none";
            }
        } catch (err) {
            // Silently fail
        }
    }
})();
