/**
 * My Credentials management UI.
 *
 * Features:
 * - List own credentials (label, created, last used)
 * - Add credential via WebAuthn (requires elevation)
 * - Remove credential via WebAuthn (requires elevation, last-key guard)
 * - No admin gate (all authenticated users can access)
 * - Auto-refresh session
 */

(function () {
    "use strict";

    var API_BASE = "/api/v1";
    var REFRESH_INTERVAL = 240000; // 4 minutes

    // --- DOM elements ---

    var credentialsTbody = document.getElementById("credentials-tbody");
    var emptyState = document.getElementById("empty-state");
    var loadingState = document.getElementById("loading-state");
    var addCredentialBtn = document.getElementById("add-credential-btn");
    var lastKeyWarning = document.getElementById("last-key-warning");

    // Modals
    var addModal = document.getElementById("add-modal");
    var addForm = document.getElementById("add-credential-form");
    var addLabel = document.getElementById("add-label");
    var addError = document.getElementById("add-error");
    var addCancelBtn = document.getElementById("add-cancel-btn");
    var addSubmitBtn = document.getElementById("add-submit-btn");

    var removeModal = document.getElementById("remove-modal");
    var removeLabel = document.getElementById("remove-label");
    var removeError = document.getElementById("remove-error");
    var removeCancelBtn = document.getElementById("remove-cancel-btn");
    var removeConfirmBtn = document.getElementById("remove-confirm-btn");

    // --- State ---

    var currentCredentialId = null;
    var refreshTimerId = null;

    // --- API helpers ---

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

        if (resp.status === 401) {
            window.location.href = "/";
            return null;
        }

        if (!resp.ok) {
            var data;
            try {
                data = await resp.json();
            } catch (e) {
                data = {};
            }
            throw new Error(data.detail || "Request failed");
        }

        var contentType = resp.headers.get("content-type") || "";
        if (contentType.indexOf("application/json") !== -1) {
            return resp.json();
        }
        return null;
    }

    // --- Session refresh ---

    function refreshSession() {
        fetch(API_BASE + "/auth/refresh/browser", {
            method: "POST",
            credentials: "include",
        }).catch(function () {});
    }

    function startSessionRefresh() {
        if (refreshTimerId !== null) return;
        refreshSession();
        refreshTimerId = setInterval(refreshSession, REFRESH_INTERVAL);
    }

    function stopSessionRefresh() {
        if (refreshTimerId === null) return;
        clearInterval(refreshTimerId);
        refreshTimerId = null;
    }

    // --- Toast notifications ---

    function showToast(message, type) {
        var existing = document.querySelectorAll(".toast-notification");
        for (var i = 0; i < existing.length; i++) {
            existing[i].parentNode.removeChild(existing[i]);
        }

        var toast = document.createElement("div");
        toast.className = "toast-notification toast-" + (type || "success");
        toast.textContent = message;
        toast.style.cssText = "position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:4px;font-size:14px;z-index:10000;box-shadow:0 2px 8px rgba(0,0,0,0.15);animation:fadeIn 0.2s ease;max-width:400px;";
        if (type === "error") {
            toast.style.background = "#cc3333";
            toast.style.color = "#fff";
        } else {
            toast.style.background = "#2e7d32";
            toast.style.color = "#fff";
        }
        document.body.appendChild(toast);
        setTimeout(function () {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 5000);
    }

    // --- Elevation flow ---

    // Same pattern as secrets.js revealSecret()
    async function elevate() {
        // Step 1: Get elevation challenge
        var challengeData = await apiFetch(API_BASE + "/auth/elevate/browser/challenge", {
            method: "POST",
        });
        if (!challengeData) return null;

        var options = challengeData.options;

        // Step 2: WebAuthn authentication
        var assertion = await VenyaWebAuthn.startAuthentication(options);

        // Step 3: Submit assertion, get elevation token
        var assertResult = await apiFetch(API_BASE + "/auth/elevate/browser/assert", {
            method: "POST",
            body: JSON.stringify({
                challenge_id: challengeData.challenge_id,
                response: assertion,
            }),
        });
        if (!assertResult) return null;

        return assertResult.elevation_token;
    }

    // --- Credential table rendering ---

    function formatDateTime(dt) {
        if (!dt) return "\u2014";
        try {
            var d = new Date(dt);
            return d.toLocaleDateString() + " " + d.toLocaleTimeString();
        } catch (e) {
            return dt;
        }
    }

    function renderCredentials(credentials) {
        if (!credentialsTbody) return;
        credentialsTbody.innerHTML = "";

        if (!credentials || credentials.length === 0) {
            if (emptyState) emptyState.hidden = false;
            if (loadingState) loadingState.hidden = true;
            if (addCredentialBtn) addCredentialBtn.disabled = true;
            return;
        }

        if (emptyState) emptyState.hidden = true;
        if (loadingState) loadingState.hidden = true;
        if (addCredentialBtn) addCredentialBtn.disabled = false;

        var isLastKey = credentials.length === 1;
        if (lastKeyWarning) {
            lastKeyWarning.hidden = !isLastKey;
        }

        for (var i = 0; i < credentials.length; i++) {
            var cred = credentials[i];
            var tr = document.createElement("tr");

            // ID
            var idTd = document.createElement("td");
            idTd.textContent = cred.id;
            tr.appendChild(idTd);

            // Label
            var labelTd = document.createElement("td");
            labelTd.textContent = cred.label || "\u2014";
            tr.appendChild(labelTd);

            // Created
            var createdTd = document.createElement("td");
            createdTd.textContent = formatDateTime(cred.created_at);
            tr.appendChild(createdTd);

            // Last Used
            var lastUsedTd = document.createElement("td");
            lastUsedTd.textContent = formatDateTime(cred.last_used_at);
            tr.appendChild(lastUsedTd);

            // Actions
            var actionsTd = document.createElement("td");

            // Remove button
            var removeBtn = document.createElement("button");
            removeBtn.className = "btn-delete";
            removeBtn.textContent = "\u2716";
            removeBtn.title = "Remove";
            removeBtn.dataset.credentialId = cred.id;
            removeBtn.dataset.label = cred.label || "Credential #" + cred.id;

            if (isLastKey) {
                removeBtn.disabled = true;
                removeBtn.title = "Cannot remove last credential";
            }

            removeBtn.addEventListener("click", function () {
                openRemoveModal(this.dataset.credentialId, this.dataset.label);
            });
            actionsTd.appendChild(removeBtn);

            tr.appendChild(actionsTd);
            credentialsTbody.appendChild(tr);
        }
    }

    // --- Load credentials ---

    async function loadCredentials() {
        if (!credentialsTbody) return;
        credentialsTbody.innerHTML = "";

        if (loadingState) loadingState.hidden = false;

        try {
            var data = await apiFetch(API_BASE + "/credentials");
            if (!data) return;
            renderCredentials(data.credentials);
        } catch (err) {
            if (loadingState) {
                loadingState.hidden = true;
                loadingState.innerHTML = "<p style='color:#cc3333'>Failed to load credentials: " + escapeHtml(err.message) + "</p>";
                loadingState.hidden = false;
            }
        }
    }

    function escapeHtml(str) {
        var div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    // --- Add Credential Modal ---

    function openAddModal() {
        if (!addModal) return;
        if (addForm) addForm.reset();
        if (addError) addError.hidden = true;
        addModal.hidden = false;
        setTimeout(function () {
            var el = document.getElementById("add-label");
            if (el) el.focus();
        }, 100);
    }

    function closeAddModal() {
        if (addModal) addModal.hidden = true;
    }

    // --- Remove Modal ---

    function openRemoveModal(credentialId, label) {
        currentCredentialId = credentialId;
        if (!removeModal) return;
        removeLabel.textContent = label;
        if (removeError) removeError.hidden = true;
        removeModal.hidden = false;
    }

    function closeRemoveModal() {
        currentCredentialId = null;
        if (removeModal) removeModal.hidden = true;
    }

    // --- Add credential with elevation ---

    async function addCredential(label) {
        // Step 1: Elevate
        var elevationToken = await elevate();
        if (!elevationToken) {
            throw new Error("Elevation failed. Please try again.");
        }

        // Step 2: Start add flow
        var startData = await apiFetch(API_BASE + "/credentials/add/browser/start", {
            method: "POST",
            body: JSON.stringify({ label: label }),
            headers: {
                "X-Elevation-Token": elevationToken,
            },
        });
        if (!startData) return null;

        var options = startData.options;

        // Step 3: WebAuthn registration
        var attestation = await VenyaWebAuthn.startRegistration(options);

        // Step 4: Complete add flow
        var result = await apiFetch(API_BASE + "/credentials/add/browser/complete", {
            method: "POST",
            body: JSON.stringify({
                challenge_id: startData.challenge_id,
                response: attestation,
                label: label,
            }),
            headers: {
                "X-Elevation-Token": elevationToken,
            },
        });
        if (!result) return null;

        return result;
    }

    // --- Remove credential with elevation ---

    async function removeCredential(credentialId) {
        // Step 1: Elevate
        var elevationToken = await elevate();
        if (!elevationToken) {
            throw new Error("Elevation failed. Please try again.");
        }

        // Step 2: Remove
        var result = await apiFetch(API_BASE + "/credentials/" + credentialId, {
            method: "DELETE",
            headers: {
                "X-Elevation-Token": elevationToken,
            },
        });
        if (!result) return null;

        return result;
    }

    // --- Event listeners ---

    // Add credential button
    if (addCredentialBtn) {
        addCredentialBtn.addEventListener("click", openAddModal);
    }

    // Add credential form submit
    if (addForm) {
        addForm.addEventListener("submit", function (event) {
            event.preventDefault();

            var label = addLabel ? addLabel.value.trim() : "";
            if (!label) {
                if (addError) {
                    addError.textContent = "Label is required.";
                    addError.hidden = false;
                }
                return;
            }

            if (addSubmitBtn) {
                addSubmitBtn.disabled = true;
                addSubmitBtn.textContent = "Adding...";
            }
            if (addError) addError.hidden = true;

            addCredential(label).then(function (result) {
                if (!result) return;
                closeAddModal();
                showToast("Credential added.", "success");
                loadCredentials();
            }).catch(function (err) {
                if (addError) {
                    addError.textContent = err.message;
                    addError.hidden = false;
                }
            }).finally(function () {
                if (addSubmitBtn) {
                    addSubmitBtn.disabled = false;
                    addSubmitBtn.textContent = "Add";
                }
            });
        });
    }

    // Add cancel
    if (addCancelBtn) {
        addCancelBtn.addEventListener("click", closeAddModal);
    }

    // Remove confirm
    if (removeConfirmBtn) {
        removeConfirmBtn.addEventListener("click", function () {
            if (!currentCredentialId) return;

            removeConfirmBtn.disabled = true;
            removeConfirmBtn.textContent = "Removing...";
            if (removeError) removeError.hidden = true;

            removeCredential(currentCredentialId).then(function (result) {
                if (!result) return;
                closeRemoveModal();
                showToast("Credential removed.", "success");
                loadCredentials();
            }).catch(function (err) {
                if (removeError) {
                    removeError.textContent = err.message;
                    removeError.hidden = false;
                }
            }).finally(function () {
                if (removeConfirmBtn) {
                    removeConfirmBtn.disabled = false;
                    removeConfirmBtn.textContent = "Remove";
                }
            });
        });
    }

    // Remove cancel
    if (removeCancelBtn) {
        removeCancelBtn.addEventListener("click", closeRemoveModal);
    }

    // Close modals on overlay click
    var modals = [addModal, removeModal];
    for (var m = 0; m < modals.length; m++) {
        if (modals[m]) {
            modals[m].addEventListener("click", function (e) {
                if (e.target === this) {
                    this.hidden = true;
                }
            });
        }
    }

    // Nav links
    var navLinks = document.querySelectorAll("#nav a");
    for (var n = 0; n < navLinks.length; n++) {
        navLinks[n].addEventListener("click", function (e) {
            e.preventDefault();
            window.location.href = this.href;
        });
    }

    // Logout button
    var logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", function () {
            stopSessionRefresh();
            fetch(API_BASE + "/auth/logout/browser", {
                method: "POST",
                credentials: "include",
            }).finally(function () {
                window.location.href = "/";
            });
        });
    }

    // --- Initialize ---

    stopSessionRefresh();
    initThemeToggle();
    initNavVisibility();
    loadCredentials();

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

    // --- Dark mode toggle ---

    function initThemeToggle() {
        var toggle = document.getElementById("theme-toggle");
        if (!toggle) return;

        var saved = localStorage.getItem("venya-theme");
        if (saved) {
            document.documentElement.setAttribute("data-theme", saved);
        } else if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
            document.documentElement.setAttribute("data-theme", "dark");
        }

        toggle.addEventListener("click", function () {
            var current = document.documentElement.getAttribute("data-theme");
            var next = current === "dark" ? "light" : "dark";
            document.documentElement.setAttribute("data-theme", next);
            localStorage.setItem("venya-theme", next);
            toggle.textContent = next === "dark" ? "\u2600" : "\u263E";
        });

        var theme = document.documentElement.getAttribute("data-theme");
        toggle.textContent = theme === "dark" ? "\u2600" : "\u263E";
    }
})();
