/**
 * Audit log viewer.
 *
 * Features:
 * - Filterable audit log table with pagination
 * - User dropdown filter (populated from audit data)
 * - Key text filter, date range filters
 * - CSV export of filtered results
 * - Color-coded event status
 */

(function () {
    "use strict";

    var API_BASE = "/api/v1";
    var DEFAULT_DAYS = 1;
    var DEFAULT_LIMIT = 100;
    var MAX_LIMIT = 1000;

    // --- DOM elements ---

    var auditTbody = document.getElementById("audit-tbody");
    var auditTable = document.getElementById("audit-table");
    var filterUser = document.getElementById("filter-user");
    var filterKey = document.getElementById("filter-key");
    var filterStartDate = document.getElementById("filter-start-date");
    var filterEndDate = document.getElementById("filter-end-date");
    var exportCsvBtn = document.getElementById("export-csv-btn");

    // Current filter state
    var currentFilters = {
        user: "",
        key: "",
        start_date: "",
        end_date: "",
        days: DEFAULT_DAYS,
        limit: DEFAULT_LIMIT,
        offset: 0,
    };

    // Known users for dropdown
    var knownUsers = [];

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
            window.location.href = "/?expired=1";
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

    // --- Event type helpers ---

    function getStatusClass(eventType) {
        if (!eventType) return "";
        var successTypes = [
            "secret_created", "secret_retrieved", "secret_updated",
            "secret_deleted", "credential_revoked", "login_success",
            "registration_success", "enrollment_success",
            "role_created", "role_updated", "role_deleted",
            "user_added", "user_updated", "user_deleted",
            "key_rotation_success", "command_policy_updated",
            "executor_registered", "heartbeat_success",
        ];
        var failureTypes = [
            "login_failure", "registration_failure", "enrollment_failure",
            "secret_access_denied", "authorization_failure",
            "role_not_found", "user_not_found",
        ];
        if (successTypes.indexOf(eventType) !== -1) return "success";
        if (failureTypes.indexOf(eventType) !== -1) return "failure";
        return "";
    }

    function formatEventType(type) {
        return type
            .replace(/_/g, " ")
            .replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    }

    function formatTimestamp(isoString) {
        if (!isoString) return "";
        try {
            var d = new Date(isoString);
            return d.toLocaleString();
        } catch (e) {
            return isoString;
        }
    }

    function extractKeyFromFields(fields, eventType) {
        if (!fields) return "";
        if (fields.key) return fields.key;
        if (fields.secret_key) return fields.secret_key;
        if (fields.secret_id) return fields.secret_id;
        return "";
    }

    // --- Rendering ---

    function renderAuditTable(events, total, limit, offset) {
        if (!auditTbody) return;
        auditTbody.innerHTML = "";

        if (!events || events.length === 0) {
            var tr = document.createElement("tr");
            var td = document.createElement("td");
            td.colSpan = 5;
            td.textContent = "No audit events found.";
            tr.appendChild(td);
            auditTbody.appendChild(tr);
            return;
        }

        for (var i = 0; i < events.length; i++) {
            var event = events[i];
            var tr = document.createElement("tr");

            // Timestamp column
            var tsTd = document.createElement("td");
            tsTd.textContent = formatTimestamp(event.timestamp);
            tr.appendChild(tsTd);

            // Event type column
            var typeTd = document.createElement("td");
            typeTd.textContent = formatEventType(event.event_type);
            var statusClass = getStatusClass(event.event_type);
            if (statusClass) {
                typeTd.className = "audit-" + statusClass;
            }
            tr.appendChild(typeTd);

            // User column
            var userTd = document.createElement("td");
            userTd.textContent = event.user_id || "\u2014";
            tr.appendChild(userTd);

            // Key column
            var keyTd = document.createElement("td");
            var secretKey = extractKeyFromFields(event.fields, event.event_type);
            keyTd.textContent = secretKey || "\u2014";
            tr.appendChild(keyTd);

            // Status column
            var statusTd = document.createElement("td");
            if (statusClass === "success") {
                statusTd.textContent = "Success";
                statusTd.className = "audit-" + statusClass;
            } else if (statusClass === "failure") {
                statusTd.textContent = "Failed";
                statusTd.className = "audit-" + statusClass;
            } else {
                statusTd.textContent = "\u2014";
            }
            tr.appendChild(statusTd);

            auditTbody.appendChild(tr);
        }

        updatePagination(total, limit, offset);
    }

    function updatePagination(total, limit, offset) {
        // Clear existing pagination controls
        var existing = auditTable.parentElement.querySelector(".pagination");
        if (existing) existing.remove();

        if (total <= limit) return;

        var pagination = document.createElement("div");
        pagination.className = "pagination";

        var prevBtn = document.createElement("button");
        prevBtn.textContent = "\u2190 Previous";
        prevBtn.disabled = offset <= 0;
        prevBtn.addEventListener("click", function () {
            currentFilters.offset = Math.max(0, currentFilters.offset - limit);
            loadAudit();
        });
        pagination.appendChild(prevBtn);

        var info = document.createElement("span");
        info.className = "pagination-info";
        var startItem = offset + 1;
        var endItem = Math.min(offset + limit, total);
        info.textContent = "Showing " + startItem + "-" + endItem + " of " + total;
        pagination.appendChild(info);

        var nextBtn = document.createElement("button");
        nextBtn.textContent = "Next \u2192";
        nextBtn.disabled = offset + limit >= total;
        nextBtn.addEventListener("click", function () {
            currentFilters.offset = currentFilters.offset + limit;
            loadAudit();
        });
        pagination.appendChild(nextBtn);

        auditTable.parentElement.appendChild(pagination);
    }

    function populateUserDropdown(users) {
        if (!filterUser) return;
        knownUsers = users || [];

        // Keep the "All" option, clear the rest
        var currentVal = filterUser.value;
        filterUser.innerHTML = '<option value="">All</option>';

        for (var i = 0; i < knownUsers.length; i++) {
            var opt = document.createElement("option");
            opt.value = knownUsers[i];
            opt.textContent = knownUsers[i];
            filterUser.appendChild(opt);
        }

        // Restore selection if still valid
        var valid = false;
        for (var j = 0; j < filterUser.options.length; j++) {
            if (filterUser.options[j].value === currentVal) {
                filterUser.selectedIndex = j;
                valid = true;
                break;
            }
        }
        if (!valid) filterUser.selectedIndex = 0;
    }

    // --- Data loading ---

    async function loadAudit() {
        if (!auditTbody) return;
        auditTbody.innerHTML = "";

        var tr = document.createElement("tr");
        var td = document.createElement("td");
        td.colSpan = 5;
        td.textContent = "Loading audit events...";
        tr.appendChild(td);
        auditTbody.appendChild(tr);

        var params = new URLSearchParams();
        if (currentFilters.days) params.set("days", currentFilters.days);
        if (currentFilters.limit) params.set("limit", currentFilters.limit);
        if (currentFilters.offset) params.set("offset", currentFilters.offset);
        if (currentFilters.user) params.set("user", currentFilters.user);
        if (currentFilters.key) params.set("key", currentFilters.key);
        if (currentFilters.start_date) params.set("start_date", currentFilters.start_date);
        if (currentFilters.end_date) params.set("end_date", currentFilters.end_date);

        var url = API_BASE + "/audit?" + params.toString();

        try {
            var data = await apiFetch(url);
            if (!data) return;

            // Extract unique users for dropdown
            var userIds = {};
            var events = data.events || [];
            for (var i = 0; i < events.length; i++) {
                if (events[i].user_id) {
                    userIds[events[i].user_id] = true;
                }
            }
            var userArray = Object.keys(userIds);
            populateUserDropdown(userArray);

            renderAuditTable(events, data.total, data.limit, data.offset);
        } catch (err) {
            auditTbody.innerHTML = "";
            var errTr = document.createElement("tr");
            var errTd = document.createElement("td");
            errTd.colSpan = 5;
            errTd.textContent = "Failed to load audit log: " + err.message;
            errTr.appendChild(errTd);
            auditTbody.appendChild(errTr);
        }
    }

    // --- CSV export ---

    async function exportCsv() {
        if (!exportCsvBtn) return;

        exportCsvBtn.disabled = true;
        exportCsvBtn.textContent = "Exporting...";

        try {
            var params = new URLSearchParams();
            if (currentFilters.days) params.set("days", currentFilters.days);
            if (currentFilters.limit) params.set("limit", MAX_LIMIT);
            if (currentFilters.offset) params.set("offset", currentFilters.offset);
            if (currentFilters.user) params.set("user", currentFilters.user);
            if (currentFilters.key) params.set("key", currentFilters.key);
            if (currentFilters.start_date) params.set("start_date", currentFilters.start_date);
            if (currentFilters.end_date) params.set("end_date", currentFilters.end_date);

            var url = API_BASE + "/audit?" + params.toString();
            var data = await apiFetch(url);
            if (!data) return;

            var events = data.events || [];
            var rows = [];
            rows.push(["Timestamp", "Event Type", "User", "Key", "Status"]);

            for (var i = 0; i < events.length; i++) {
                var e = events[i];
                var key = extractKeyFromFields(e.fields, e.event_type);
                var statusText = "";
                var sc = getStatusClass(e.event_type);
                if (sc === "success") statusText = "Success";
                else if (sc === "failure") statusText = "Failed";

                rows.push([
                    e.timestamp,
                    formatEventType(e.event_type),
                    e.user_id || "",
                    key,
                    statusText,
                ]);
            }

            var csvContent = "";
            for (var j = 0; j < rows.length; j++) {
                var line = "";
                for (var k = 0; k < rows[j].length; k++) {
                    var cell = String(rows[j][k]).replace(/"/g, '""');
                    if (cell.indexOf(",") !== -1 || cell.indexOf('"') !== -1 || cell.indexOf("\n") !== -1) {
                        cell = '"' + cell + '"';
                    }
                    if (k > 0) line += ",";
                    line += cell;
                }
                csvContent += line + "\r\n";
            }

            var blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
            var link = document.createElement("a");
            var urlObj = URL.createObjectURL(blob);
            link.href = urlObj;
            link.download = "venya_audit_" + new Date().toISOString().slice(0, 10) + ".csv";
            link.style.display = "none";
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(urlObj);

            exportCsvBtn.textContent = "Export CSV";
        } catch (err) {
            exportCsvBtn.textContent = "Export CSV";
            alert("Failed to export CSV: " + err.message);
        } finally {
            exportCsvBtn.disabled = false;
        }
    }

    // --- Filter handling ---

    function applyFilters() {
        currentFilters.user = filterUser ? filterUser.value : "";
        currentFilters.key = filterKey ? filterKey.value.trim() : "";
        currentFilters.start_date = filterStartDate ? filterStartDate.value : "";
        currentFilters.end_date = filterEndDate ? filterEndDate.value : "";
        currentFilters.offset = 0;
        loadAudit();
    }

    // --- Event listeners ---

    if (filterUser) {
        filterUser.addEventListener("change", applyFilters);
    }

    if (filterKey) {
        filterKey.addEventListener("input", function () {
            // Debounce key filter
            clearTimeout(filterKey._timeout);
            filterKey._timeout = setTimeout(applyFilters, 400);
        });
    }

    if (filterStartDate) {
        filterStartDate.addEventListener("change", applyFilters);
    }

    if (filterEndDate) {
        filterEndDate.addEventListener("change", applyFilters);
    }

    if (exportCsvBtn) {
        exportCsvBtn.addEventListener("click", exportCsv);
    }

    // --- Initialize ---

    if (auditTbody || auditTable) {
        loadAudit();
    }

    window.VenyaAudit = {
        load: loadAudit,
    };
})();
