/**
 * Shared session refresh logic.
 * Call startSessionRefresh() on any page that needs session maintenance.
 * Automatically stops when user navigates away (page unload).
 */

(function () {
    "use strict";

    var REFRESH_INTERVAL = 240000; // 4 minutes (token lives 5 min)
    var refreshTimerId = null;
    var API_BASE = "/api/v1";

    function refreshSession() {
        fetch(API_BASE + "/auth/refresh/browser", {
            method: "POST",
            credentials: "include",
        }).catch(function () {
            // Refresh failed — session expired
        });
    }

    window.startSessionRefresh = function () {
        if (refreshTimerId !== null) return;
        refreshSession();
        refreshTimerId = setInterval(refreshSession, REFRESH_INTERVAL);
    };

    window.stopSessionRefresh = function () {
        if (refreshTimerId === null) return;
        clearInterval(refreshTimerId);
        refreshTimerId = null;
    };

    // Auto-stop on page unload
    window.addEventListener("unload", function () {
        stopSessionRefresh();
    });
})();
