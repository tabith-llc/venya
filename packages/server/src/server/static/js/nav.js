/**
 * Shared navigation bar.
 * Injected into all pages via <div id="nav-container"></div>.
 * Not shown on public pages (login, enroll).
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
    }
})();
