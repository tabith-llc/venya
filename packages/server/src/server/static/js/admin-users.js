/**
 * Admin Users management UI.
 *
 * Features:
 * - List all users with status, auth mode, session timeout
 * - Create user with username, display name, roles
 * - Configure user (display name, status, session timeout)
 * - Re-enroll user (invalidate credentials, require re-enrollment)
 * - Remove user (permanent deletion)
 * - Admin-only gate (redirects to dashboard if not admin)
 */

(function () {
    "use strict";

    var API_BASE = "/api/v1";
    var REFRESH_INTERVAL = 240000; // 4 minutes

    // --- DOM elements ---

    var usersTbody = document.getElementById("users-tbody");
    var emptyState = document.getElementById("empty-state");
    var loadingState = document.getElementById("loading-state");
    var createUserBtn = document.getElementById("create-user-btn");

    // Modals
    var createModal = document.getElementById("create-modal");
    var createForm = document.getElementById("create-user-form");
    var createUsername = document.getElementById("create-username");
    var createDisplayName = document.getElementById("create-display-name");
    var createRoles = document.getElementById("create-roles");
    var createError = document.getElementById("create-error");
    var createCancelBtn = document.getElementById("create-cancel-btn");
    var createSubmitBtn = document.getElementById("create-submit-btn");

    var configureModal = document.getElementById("configure-modal");
    var configureForm = document.getElementById("configure-user-form");
    var configDisplayName = document.getElementById("config-display-name");
    var configStatus = document.getElementById("config-status");
    var configSessionTimeout = document.getElementById("config-session-timeout");
    var configError = document.getElementById("config-error");
    var configCancelBtn = document.getElementById("config-cancel-btn");
    var configSubmitBtn = document.getElementById("config-submit-btn");

    var reenrollModal = document.getElementById("reenroll-modal");
    var reenrollUsername = document.getElementById("reenroll-username");
    var reenrollError = document.getElementById("reenroll-error");
    var reenrollCancelBtn = document.getElementById("reenroll-cancel-btn");
    var reenrollConfirmBtn = document.getElementById("reenroll-confirm-btn");

    var removeModal = document.getElementById("remove-modal");
    var removeUsername = document.getElementById("remove-username");
    var removeError = document.getElementById("remove-error");
    var removeCancelBtn = document.getElementById("remove-cancel-btn");
    var removeConfirmBtn = document.getElementById("remove-confirm-btn");

    var tokenModal = document.getElementById("token-modal");
    var tokenUsername = document.getElementById("token-username");
    var tokenDisplay = document.getElementById("token-display");
    var tokenExpiry = document.getElementById("token-expiry");
    var copyTokenBtn = document.getElementById("copy-token-btn");
    var tokenCloseBtn = document.getElementById("token-close-btn");

    // --- State ---

    var currentConfigUser = null;
    var currentReenrollUser = null;
    var currentRemoveUser = null;
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
            console.error("API error:", url, resp.status, data);
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

    function window.stopSessionRefresh() {
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

            loadUsers();
            window.startSessionRefresh();
        } catch (err) {
            window.location.href = "/";
        }
    }

    // --- User table rendering ---

    function formatDateTime(dt) {
        if (!dt) return "\u2014";
        try {
            var d = new Date(dt);
            return d.toLocaleDateString() + " " + d.toLocaleTimeString();
        } catch (e) {
            return dt;
        }
    }

    function formatTimeout(seconds) {
        if (!seconds) return "\u2014";
        var mins = Math.floor(seconds / 60);
        if (mins >= 60) {
            var hrs = Math.floor(mins / 60);
            var remMins = mins % 60;
            return remMins > 0 ? hrs + "h " + remMins + "m" : hrs + "h";
        }
        return mins + "m";
    }

    function renderUsers(users) {
        if (!usersTbody) return;
        usersTbody.innerHTML = "";

        if (!users || users.length === 0) {
            if (emptyState) emptyState.hidden = false;
            if (loadingState) loadingState.hidden = true;
            return;
        }

        if (emptyState) emptyState.hidden = true;
        if (loadingState) loadingState.hidden = true;

        for (var i = 0; i < users.length; i++) {
            var user = users[i];
            var tr = document.createElement("tr");

            // User ID
            var userIdTd = document.createElement("td");
            userIdTd.textContent = user.user_id;
            tr.appendChild(userIdTd);

            // Display Name
            var displayNameTd = document.createElement("td");
            displayNameTd.textContent = user.display_name || "\u2014";
            tr.appendChild(displayNameTd);

            // Status
            var statusTd = document.createElement("td");
            statusTd.textContent = user.status || "\u2014";
            tr.appendChild(statusTd);

            // Auth Mode
            var authModeTd = document.createElement("td");
            authModeTd.textContent = user.auth_mode || "\u2014";
            tr.appendChild(authModeTd);

            // Enrolled At
            var enrolledAtTd = document.createElement("td");
            enrolledAtTd.textContent = formatDateTime(user.enrolled_at);
            tr.appendChild(enrolledAtTd);

            // Session Timeout
            var timeoutTd = document.createElement("td");
            timeoutTd.textContent = formatTimeout(user.session_timeout);
            tr.appendChild(timeoutTd);

            // Actions
            var actionsTd = document.createElement("td");

            // Configure button
            var configBtn = document.createElement("button");
            configBtn.className = "btn-reveal";
            configBtn.textContent = "\u2699"; // gear
            configBtn.title = "Configure";
            configBtn.dataset.userId = user.user_id;
            configBtn.addEventListener("click", function () {
                openConfigureModal(this.dataset.userId, user);
            });
            actionsTd.appendChild(configBtn);

            // Re-enroll button
            var reenrollBtn = document.createElement("button");
            reenrollBtn.className = "btn-reveal";
            reenrollBtn.textContent = "\u21BB"; // refresh
            reenrollBtn.title = "Re-enroll";
            reenrollBtn.dataset.userId = user.user_id;
            reenrollBtn.addEventListener("click", function () {
                openReenrollModal(this.dataset.userId);
            });
            actionsTd.appendChild(reenrollBtn);

            // Remove button
            var removeBtn = document.createElement("button");
            removeBtn.className = "btn-delete";
            removeBtn.textContent = "\u2716"; // X
            removeBtn.title = "Remove";
            removeBtn.dataset.userId = user.user_id;
            removeBtn.addEventListener("click", function () {
                openRemoveModal(this.dataset.userId);
            });
            actionsTd.appendChild(removeBtn);

            tr.appendChild(actionsTd);
            usersTbody.appendChild(tr);
        }
    }

    // --- Load users ---

    async function loadUsers() {
        if (!usersTbody) return;
        usersTbody.innerHTML = "";

        if (loadingState) loadingState.hidden = false;

        try {
            var data = await apiFetch(API_BASE + "/admin/users");
            if (!data) return;
            renderUsers(data.users);
        } catch (err) {
            if (loadingState) {
                loadingState.hidden = true;
                loadingState.innerHTML = "<p class=\"message-error\">Failed to load users: " + escapeHtml(err.message) + "</p>";
                loadingState.hidden = false;
            }
        }
    }

    function escapeHtml(str) {
        var div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    // --- Create User Modal ---

    function openCreateModal() {
        if (!createModal) return;
        createForm.reset();
        if (createError) createError.hidden = true;
        if (createModal) createModal.hidden = false;
        setTimeout(function () {
            var el = document.getElementById("create-username");
            if (el) el.focus();
        }, 100);
    }

    function closeCreateModal() {
        if (createModal) createModal.hidden = true;
    }

    // --- Configure User Modal ---

    function openConfigureModal(userId, user) {
        currentConfigUser = userId;
        if (!configureModal) return;
        configDisplayName.value = user.display_name || "";
        configStatus.value = user.status || "active";
        configSessionTimeout.value = user.session_timeout || 900;
        if (configError) configError.hidden = true;
        configureModal.hidden = false;
        setTimeout(function () {
            var el = document.getElementById("config-display-name");
            if (el) el.focus();
        }, 100);
    }

    function closeConfigureModal() {
        currentConfigUser = null;
        if (configureModal) configureModal.hidden = true;
    }

    // --- Re-enroll Modal ---

    function openReenrollModal(userId) {
        currentReenrollUser = userId;
        if (!reenrollModal) return;
        reenrollUsername.textContent = userId;
        if (reenrollError) reenrollError.hidden = true;
        reenrollModal.hidden = false;
    }

    function closeReenrollModal() {
        currentReenrollUser = null;
        if (reenrollModal) reenrollModal.hidden = true;
    }

    // --- Remove Modal ---

    function openRemoveModal(userId) {
        currentRemoveUser = userId;
        if (!removeModal) return;
        removeUsername.textContent = userId;
        if (removeError) removeError.hidden = true;
        removeModal.hidden = false;
    }

    function closeRemoveModal() {
        currentRemoveUser = null;
        if (removeModal) removeModal.hidden = true;
    }

    // --- Token Display Modal ---

    function openTokenModal(username, token, expiresAt) {
        if (!tokenModal) return;
        tokenUsername.textContent = username;
        tokenDisplay.value = token;
        if (expiresAt) {
            try {
                var expDate = new Date(expiresAt);
                tokenExpiry.textContent = "This token expires at " + expDate.toLocaleString() + ". Display only once.";
            } catch (e) {
                tokenExpiry.textContent = "Token expires soon. Display only once.";
            }
        } else {
            tokenExpiry.textContent = "Token expires in 15 minutes. Display only once.";
        }
        if (tokenModal) tokenModal.hidden = false;
    }

    function closeTokenModal() {
        if (tokenModal) tokenModal.hidden = true;
    }

    // --- Event listeners ---

    // Create user button
    if (createUserBtn) {
        createUserBtn.addEventListener("click", openCreateModal);
    }

    // Create form submit
    if (createForm) {
        createForm.addEventListener("submit", function (event) {
            event.preventDefault();

            var username = createUsername ? createUsername.value.trim() : "";
            var displayName = createDisplayName ? createDisplayName.value.trim() : "";
            var roles = [];
            if (createRoles) {
                var options = createRoles.options;
                for (var i = 0; i < options.length; i++) {
                    if (options[i].selected) {
                        roles.push(options[i].value);
                    }
                }
            }

            if (!username) {
                if (createError) {
                    createError.textContent = "Username is required.";
                    createError.hidden = false;
                }
                return;
            }

            if (createSubmitBtn) {
                createSubmitBtn.disabled = true;
                createSubmitBtn.textContent = "Creating...";
            }
            if (createError) createError.hidden = true;

            var payload = {
                username: username,
            };
            if (displayName) {
                payload.display_name = displayName;
            }
            if (roles.length > 0) {
                payload.roles = roles;
            }

            apiFetch(API_BASE + "/admin/users", {
                method: "POST",
                body: JSON.stringify(payload),
            }).then(function (data) {
                if (!data) return;

                closeCreateModal();
                showToast("User created successfully.", "success");
                loadUsers();

                if (data.enrollment_token) {
                    openTokenModal(username, data.enrollment_token, null);
                }
            }).catch(function (err) {
                if (createError) {
                    createError.textContent = err.message;
                    createError.hidden = false;
                }
            }).finally(function () {
                if (createSubmitBtn) {
                    createSubmitBtn.disabled = false;
                    createSubmitBtn.textContent = "Create";
                }
            });
        });
    }

    // Create cancel
    if (createCancelBtn) {
        createCancelBtn.addEventListener("click", closeCreateModal);
    }

    // Configure form submit
    if (configureForm) {
        configureForm.addEventListener("submit", function (event) {
            event.preventDefault();

            if (!currentConfigUser) return;

            var payload = {};
            var newName = configDisplayName ? configDisplayName.value.trim() : "";
            var newStatus = configStatus ? configStatus.value : "";
            var newTimeout = configSessionTimeout ? parseInt(configSessionTimeout.value, 10) : null;

            if (newName !== null && newName !== undefined) {
                payload.display_name = newName || null;
            }
            if (newStatus) {
                payload.status = newStatus;
            }
            if (newTimeout && newTimeout > 0) {
                payload.session_timeout = newTimeout;
            }

            if (configSubmitBtn) {
                configSubmitBtn.disabled = true;
                configSubmitBtn.textContent = "Saving...";
            }
            if (configError) configError.hidden = true;

            apiFetch(API_BASE + "/admin/users/" + encodeURIComponent(currentConfigUser), {
                method: "PUT",
                body: JSON.stringify(payload),
            }).then(function (data) {
                if (!data) return;
                closeConfigureModal();
                showToast("User updated.", "success");
                loadUsers();
            }).catch(function (err) {
                if (configError) {
                    configError.textContent = err.message;
                    configError.hidden = false;
                }
            }).finally(function () {
                if (configSubmitBtn) {
                    configSubmitBtn.disabled = false;
                    configSubmitBtn.textContent = "Save";
                }
            });
        });
    }

    // Configure cancel
    if (configCancelBtn) {
        configCancelBtn.addEventListener("click", closeConfigureModal);
    }

    // Re-enroll confirm
    if (reenrollConfirmBtn) {
        reenrollConfirmBtn.addEventListener("click", function () {
            if (!currentReenrollUser) return;

            reenrollConfirmBtn.disabled = true;
            reenrollConfirmBtn.textContent = "Re-enrolling...";
            if (reenrollError) reenrollError.hidden = true;

            apiFetch(API_BASE + "/admin/users/" + encodeURIComponent(currentReenrollUser) + "/re-enroll", {
                method: "POST",
            }).then(function (data) {
                if (!data) return;
                closeReenrollModal();
                if (data.enrollment_token) {
                    openTokenModal(currentReenrollUser, data.enrollment_token, null);
                } else {
                    showToast("User re-enrollment initiated.", "success");
                }
                loadUsers();
            }).catch(function (err) {
                if (reenrollError) {
                    reenrollError.textContent = err.message;
                    reenrollError.hidden = false;
                }
            }).finally(function () {
                if (reenrollConfirmBtn) {
                    reenrollConfirmBtn.disabled = false;
                    reenrollConfirmBtn.textContent = "Re-enroll";
                }
            });
        });
    }

    // Re-enroll cancel
    if (reenrollCancelBtn) {
        reenrollCancelBtn.addEventListener("click", closeReenrollModal);
    }

    // Remove confirm
    if (removeConfirmBtn) {
        removeConfirmBtn.addEventListener("click", function () {
            if (!currentRemoveUser) return;

            removeConfirmBtn.disabled = true;
            removeConfirmBtn.textContent = "Removing...";
            if (removeError) removeError.hidden = true;

            apiFetch(API_BASE + "/admin/users/" + encodeURIComponent(currentRemoveUser), {
                method: "DELETE",
            }).then(function (data) {
                if (!data) return;
                closeRemoveModal();
                showToast("User removed.", "success");
                loadUsers();
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
    var modals = [createModal, configureModal, reenrollModal, removeModal, tokenModal];
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