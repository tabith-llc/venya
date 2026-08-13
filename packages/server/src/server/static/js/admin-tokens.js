/**
 * Admin Tokens management UI.
 *
 * Features:
 * - List active enrollment tokens with user, state, timestamps
 * - Filter tokens by user
 * - Issue new token for a user (revokes existing active tokens)
 * - Revoke individual tokens
 * - Admin-only gate (redirects to dashboard if not admin)
 * - Auto-refresh every 30 seconds (tokens expire quickly)
 */

(function () {
    "use strict";

    var API_BASE = "/api/v1";
    var REFRESH_INTERVAL = 240000; // 4 minutes for session
    var TOKEN_REFRESH_INTERVAL = 30000; // 30 seconds for token list

    // --- DOM elements ---

    var tokensTbody = document.getElementById("tokens-tbody");
    var emptyState = document.getElementById("empty-state");
    var loadingState = document.getElementById("loading-state");
    var filterUser = document.getElementById("filter-user");
    var issueTokenBtn = document.getElementById("issue-token-btn");

    // Modals
    var issueModal = document.getElementById("issue-modal");
    var issueForm = document.getElementById("issue-token-form");
    var issueUser = document.getElementById("issue-user");
    var issueError = document.getElementById("issue-error");
    var issueCancelBtn = document.getElementById("issue-cancel-btn");
    var issueSubmitBtn = document.getElementById("issue-submit-btn");

    var tokenModal = document.getElementById("token-modal");
    var tokenUsername = document.getElementById("token-username");
    var tokenDisplay = document.getElementById("token-display");
    var tokenExpiry = document.getElementById("token-expiry");
    var copyTokenBtn = document.getElementById("copy-token-btn");
    var tokenCloseBtn = document.getElementById("token-close-btn");

    var revokeModal = document.getElementById("revoke-modal");
    var revokeTokenId = document.getElementById("revoke-token-id");
    var revokeUsername = document.getElementById("revoke-username");
    var revokeError = document.getElementById("revoke-error");
    var revokeCancelBtn = document.getElementById("revoke-cancel-btn");
    var revokeConfirmBtn = document.getElementById("revoke-confirm-btn");

    // --- State ---

    var allUsers = [];
    var currentTokenId = null;
    var sessionRefreshTimerId = null;
    var tokenRefreshTimerId = null;

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
        if (sessionRefreshTimerId !== null) return;
        refreshSession();
        sessionRefreshTimerId = setInterval(refreshSession, REFRESH_INTERVAL);
    }

    function stopSessionRefresh() {
        if (sessionRefreshTimerId === null) return;
        clearInterval(sessionRefreshTimerId);
        sessionRefreshTimerId = null;
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

    // --- Admin check ---

    async function checkAdmin() {
        try {
            var me = await apiFetch(API_BASE + "/auth/me");
            if (!me) return;

            var isAdmin = false;
            if (me.roles) {
                for (var i = 0; i < me.roles.length; i++) {
                    if (me.roles[i] === "admin") {
                        isAdmin = true;
                        break;
                    }
                }
            }

            if (!isAdmin) {
                window.location.href = "/dashboard";
                return;
            }

            loadUsersForFilter();
            window.startSessionRefresh();
        } catch (err) {
            window.location.href = "/";
        }
    }

    // --- User dropdown population ---

    async function loadUsersForFilter() {
        try {
            var data = await apiFetch(API_BASE + "/admin/users");
            if (!data) return;
            allUsers = data.users || [];

            var options = filterUser.innerHTML;
            for (var i = 0; i < allUsers.length; i++) {
                var u = allUsers[i];
                var opt = document.createElement("option");
                opt.value = u.user_id;
                var label = u.display_name ? u.display_name + " (" + u.user_id + ")" : u.user_id;
                opt.textContent = label;
                filterUser.appendChild(opt);
            }

            loadTokens();
        } catch (err) {
            console.error("Failed to load users for filter:", err);
        }
    }

    // --- Token table rendering ---

    function formatDateTime(dt) {
        if (!dt) return "\u2014";
        try {
            var d = new Date(dt);
            return d.toLocaleDateString() + " " + d.toLocaleTimeString();
        } catch (e) {
            return dt;
        }
    }

    function renderTokens(tokens) {
        if (!tokensTbody) return;
        tokensTbody.innerHTML = "";

        if (!tokens || tokens.length === 0) {
            if (emptyState) emptyState.hidden = false;
            if (loadingState) loadingState.hidden = true;
            return;
        }

        if (emptyState) emptyState.hidden = true;
        if (loadingState) loadingState.hidden = true;

        for (var i = 0; i < tokens.length; i++) {
            var token = tokens[i];
            var tr = document.createElement("tr");

            // ID
            var idTd = document.createElement("td");
            idTd.textContent = token.id;
            tr.appendChild(idTd);

            // User
            var userTd = document.createElement("td");
            userTd.textContent = token.user_id || "\u2014";
            tr.appendChild(userTd);

            // State
            var stateTd = document.createElement("td");
            stateTd.textContent = token.state || "\u2014";
            tr.appendChild(stateTd);

            // Created
            var createdTd = document.createElement("td");
            createdTd.textContent = formatDateTime(token.created_at);
            tr.appendChild(createdTd);

            // Expires
            var expiresTd = document.createElement("td");
            expiresTd.textContent = formatDateTime(token.expires_at);
            tr.appendChild(expiresTd);

            // Used
            var usedTd = document.createElement("td");
            usedTd.textContent = formatDateTime(token.used_at);
            tr.appendChild(usedTd);

            // Actions
            var actionsTd = document.createElement("td");

            // Revoke button
            var revokeBtn = document.createElement("button");
            revokeBtn.className = "btn-delete";
            revokeBtn.textContent = "\u2716";
            revokeBtn.title = "Revoke";
            revokeBtn.dataset.tokenId = token.id;
            revokeBtn.dataset.userId = token.user_id;
            revokeBtn.addEventListener("click", function () {
                openRevokeModal(this.dataset.tokenId, this.dataset.userId);
            });
            actionsTd.appendChild(revokeBtn);

            tr.appendChild(actionsTd);
            tokensTbody.appendChild(tr);
        }
    }

    // --- Load tokens ---

    async function loadTokens() {
        if (!tokensTbody) return;
        tokensTbody.innerHTML = "";

        if (loadingState) loadingState.hidden = false;

        try {
            var data = await apiFetch(API_BASE + "/enrollment/tokens");
            if (!data) return;

            var tokens = data.tokens || [];
            var filter = filterUser ? filterUser.value : "";

            if (filter) {
                var filtered = [];
                for (var i = 0; i < tokens.length; i++) {
                    if (tokens[i].user_id === filter) {
                        filtered.push(tokens[i]);
                    }
                }
                tokens = filtered;
            }

            renderTokens(tokens);
        } catch (err) {
            if (loadingState) {
                loadingState.hidden = true;
                loadingState.innerHTML = "<p class=\"message-error\">Failed to load tokens: " + escapeHtml(err.message) + "</p>";
                loadingState.hidden = false;
            }
        }
    }

    function escapeHtml(str) {
        var div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    // --- Issue Token Modal ---

    function openIssueModal() {
        if (!issueModal) return;
        if (issueForm) issueForm.reset();
        if (issueError) issueError.hidden = true;
        issueModal.hidden = false;
        setTimeout(function () {
            var el = document.getElementById("issue-user");
            if (el) el.focus();
        }, 100);
    }

    function closeIssueModal() {
        if (issueModal) issueModal.hidden = true;
    }

    // --- Token Display Modal ---

    function openTokenModal(username, token) {
        if (!tokenModal) return;
        tokenUsername.textContent = username;
        tokenDisplay.value = token;
        tokenExpiry.textContent = "This token expires in 15 minutes. Display only once.";
        tokenModal.hidden = false;
    }

    function closeTokenModal() {
        if (tokenModal) tokenModal.hidden = true;
    }

    // --- Revoke Modal ---

    function openRevokeModal(tokenId, userId) {
        currentTokenId = tokenId;
        if (!revokeModal) return;
        revokeTokenId.textContent = "#" + tokenId;
        revokeUsername.textContent = userId;
        if (revokeError) revokeError.hidden = true;
        revokeModal.hidden = false;
    }

    function closeRevokeModal() {
        currentTokenId = null;
        if (revokeModal) revokeModal.hidden = true;
    }

    // --- Event listeners ---

    // Filter change
    if (filterUser) {
        filterUser.addEventListener("change", function () {
            loadTokens();
        });
    }

    // Issue token button
    if (issueTokenBtn) {
        issueTokenBtn.addEventListener("click", openIssueModal);
    }

    // Issue token form submit
    if (issueForm) {
        issueForm.addEventListener("submit", function (event) {
            event.preventDefault();

            var userId = issueUser ? issueUser.value : "";
            if (!userId) {
                if (issueError) {
                    issueError.textContent = "Please select a user.";
                    issueError.hidden = false;
                }
                return;
            }

            if (issueSubmitBtn) {
                issueSubmitBtn.disabled = true;
                issueSubmitBtn.textContent = "Issuing...";
            }
            if (issueError) issueError.hidden = true;

            apiFetch(API_BASE + "/admin/users/" + encodeURIComponent(userId) + "/enrollment-tokens", {
                method: "POST",
            }).then(function (data) {
                if (!data) return;
                closeIssueModal();
                showToast("Token issued for " + userId + ".", "success");
                loadTokens();
                openTokenModal(userId, data.enrollment_token);
            }).catch(function (err) {
                if (issueError) {
                    issueError.textContent = err.message;
                    issueError.hidden = false;
                }
            }).finally(function () {
                if (issueSubmitBtn) {
                    issueSubmitBtn.disabled = false;
                    issueSubmitBtn.textContent = "Issue";
                }
            });
        });
    }

    // Issue cancel
    if (issueCancelBtn) {
        issueCancelBtn.addEventListener("click", closeIssueModal);
    }

    // Revoke confirm
    if (revokeConfirmBtn) {
        revokeConfirmBtn.addEventListener("click", function () {
            if (!currentTokenId) return;

            revokeConfirmBtn.disabled = true;
            revokeConfirmBtn.textContent = "Revoking...";
            if (revokeError) revokeError.hidden = true;

            apiFetch(API_BASE + "/admin/enrollment-tokens/" + currentTokenId, {
                method: "DELETE",
            }).then(function (data) {
                if (!data) return;
                closeRevokeModal();
                showToast("Token revoked.", "success");
                loadTokens();
            }).catch(function (err) {
                if (revokeError) {
                    revokeError.textContent = err.message;
                    revokeError.hidden = false;
                }
            }).finally(function () {
                if (revokeConfirmBtn) {
                    revokeConfirmBtn.disabled = false;
                    revokeConfirmBtn.textContent = "Revoke";
                }
            });
        });
    }

    // Revoke cancel
    if (revokeCancelBtn) {
        revokeCancelBtn.addEventListener("click", closeRevokeModal);
    }

    // Copy token button
    if (copyTokenBtn) {
        copyTokenBtn.addEventListener("click", function () {
            if (!tokenDisplay) return;
            tokenDisplay.select();
            try {
                document.execCommand("copy");
                showToast("Token copied to clipboard.", "success");
            } catch (e) {
                showToast("Failed to copy. Select and copy manually.", "error");
            }
        });
    }

    // Token modal close
    if (tokenCloseBtn) {
        tokenCloseBtn.addEventListener("click", closeTokenModal);
    }

    // Close modals on overlay click
    var modals = [issueModal, tokenModal, revokeModal];
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
            window.stopSessionRefresh();
            fetch(API_BASE + "/auth/logout/browser", {
                method: "POST",
                credentials: "include",
            }).finally(function () {
                window.location.href = "/";
            });
        });
    }

    // --- Initialize ---

    window.stopSessionRefresh();
    initThemeToggle();
    checkAdmin();

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
