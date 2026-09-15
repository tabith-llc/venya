// Copyright (c) 2026 Tabith LLC.
// Use of this source code is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository. As of the
// Change Date listed there, the work is available under MPL 2.0.
// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared navigation bar.
 * Injected into all pages via <div id="nav-container"></div>.
 * Not shown on public pages (login, enroll).
 * Handles logout and theme toggle for all pages.
 */

(function () {
    "use strict";

    // Don't show nav on public pages
    var publicPaths = ["/", "/enroll", "/enroll-admin"];
    var path = window.location.pathname;
    for (var i = 0; i < publicPaths.length; i++) {
        if (path === publicPaths[i] || path.indexOf(publicPaths[i] + "?") === 0) {
            return; // Skip nav injection
        }
    }

    var NAV_HTML = [
        '<nav id="nav">',
        '    <a href="/dashboard#dashboard" id="nav-secrets">Secrets</a>',
        '    <a href="/dashboard#audit" id="nav-audit">Audit Log</a>',
        '    <a href="/admin/users" id="nav-users">Users</a>',
        '    <a href="/admin/tokens" id="nav-tokens">Tokens</a>',
        '    <a href="/admin/roles" id="nav-roles">Roles</a>',
        '    <a href="/credentials" id="nav-credentials">Credentials</a>',
        '    <button id="theme-toggle" class="nav-theme-toggle" title="Toggle dark mode">&#9683;</button>',
        '    <button id="logout-btn" class="nav-logout">Logout</button>',
        '</nav>',
    ].join("\n");

    // Inject nav into all pages
    var container = document.getElementById("nav-container");
    if (container) {
        container.innerHTML = NAV_HTML;
        initNav();
    }

    function initNav() {
        // Theme toggle
        var toggle = document.getElementById("theme-toggle");
        if (toggle) {
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

        // Logout button
        var logoutBtn = document.getElementById("logout-btn");
        if (logoutBtn) {
            logoutBtn.addEventListener("click", function () {
                if (window.stopSessionRefresh) {
                    window.stopSessionRefresh();
                }
                fetch("/api/v1/auth/logout/browser", {
                    method: "POST",
                    credentials: "include",
                }).finally(function () {
                    window.location.href = "/";
                });
            });
        }

        // Nav links — prevent default to allow SPA-like behavior
        var navLinks = document.querySelectorAll("#nav a");
        for (var i = 0; i < navLinks.length; i++) {
            navLinks[i].addEventListener("click", function (e) {
                e.preventDefault();
                window.location.href = this.href;
            });
        }
    }
})();
