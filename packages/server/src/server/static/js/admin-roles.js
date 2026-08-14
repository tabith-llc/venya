/**
 * Admin Roles page client logic.
 *
 * Features:
 * - List all roles with name, permissions, description, member count
 * - Create new role
 * - Edit existing role
 * - Delete role
 * - Manage role members (add/remove users)
 * - Admin-only gate (redirects to dashboard if not admin)
 */

(function () {
    "use strict";

    var API_BASE = "/api/v1";
    var REFRESH_INTERVAL = 60000; // 1 minute

    // --- DOM Elements ---

    var createRoleBtn = document.getElementById("create-role-btn");
    var rolesTbody = document.getElementById("roles-tbody");
    var emptyState = document.getElementById("empty-state");
    var loadingState = document.getElementById("loading-state");
    var rolesTable = document.getElementById("roles-table");

    var createRoleModal = document.getElementById("create-role-modal");
    var createRoleForm = document.getElementById("create-role-form");
    var createRoleName = document.getElementById("create-role-name");
    var createRolePermissions = document.getElementById("create-role-permissions");
    var createRoleDescription = document.getElementById("create-role-description");
    var createRoleError = document.getElementById("create-role-error");
    var createRoleCancelBtn = document.getElementById("create-role-cancel-btn");
    var createRoleSubmitBtn = document.getElementById("create-role-submit-btn");

    var editRoleModal = document.getElementById("edit-role-modal");
    var editRoleForm = document.getElementById("edit-role-form");
    var editRoleName = document.getElementById("edit-role-name");
    var editRolePermissions = document.getElementById("edit-role-permissions");
    var editRoleDescription = document.getElementById("edit-role-description");
    var editRoleError = document.getElementById("edit-role-error");
    var editRoleCancelBtn = document.getElementById("edit-role-cancel-btn");
    var editRoleSubmitBtn = document.getElementById("edit-role-submit-btn");

    var deleteRoleModal = document.getElementById("delete-role-modal");
    var deleteRoleName = document.getElementById("delete-role-name");
    var deleteRoleError = document.getElementById("delete-role-error");
    var deleteRoleCancelBtn = document.getElementById("delete-role-cancel-btn");
    var deleteRoleConfirmBtn = document.getElementById("delete-role-confirm-btn");

    var manageMembersModal = document.getElementById("manage-members-modal");
    var manageMembersTitle = document.getElementById("manage-members-title");
    var membersList = document.getElementById("members-list");
    var addMemberForm = document.getElementById("add-member-form");
    var addMemberUser = document.getElementById("add-member-user");
    var addMemberError = document.getElementById("add-member-error");
    var manageMembersCloseBtn = document.getElementById("manage-members-close-btn");

    // --- State ---

    var currentEditRoleId = null;
    var currentEditRoleName = null;
    var currentDeleteRoleId = null;
    var currentDeleteRoleName = null;
    var currentManageRoleId = null;
    var currentManageRoleName = null;
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

        if (!resp.ok) {
            var data = await resp.json().catch(function () { return {}; });
            throw new Error(data.detail || "API error " + resp.status);
        }

        return resp.json();
    }

    // --- Auth gate ---

    async function checkAuth() {
        try {
            var me = await apiFetch(API_BASE + "/auth/me");
            if (!me || !me.roles || me.roles.indexOf("admin") === -1) {
                window.location.href = "/dashboard";
                return false;
            }
            return true;
        } catch (err) {
            // Transient auth error — don't hard-redirect, let the page try to load
            // If not authenticated, API calls will fail and show errors
            return false;
        }
    }

    // --- Role loading ---

    function showLoading() {
        loadingState.hidden = false;
        rolesTable.hidden = true;
        emptyState.hidden = true;
    }

    function hideLoading() {
        loadingState.hidden = true;
        rolesTable.hidden = false;
    }

    async function loadRoles() {
        showLoading();
        try {
            var data = await apiFetch(API_BASE + "/roles");
            console.log("Roles loaded:", data);
            renderRoles(data.roles);
        } catch (err) {
            console.error("Failed to load roles:", err);
            showToast("Failed to load roles: " + err.message, "error");
        } finally {
            hideLoading();
        }
    }

    function renderRoles(roles) {
        console.log("renderRoles called with:", roles);
        console.log("rolesTbody exists:", !!rolesTbody);
        console.log("emptyState exists:", !!emptyState);
        rolesTbody.innerHTML = "";

        if (!roles || roles.length === 0) {
            console.log("No roles to display, showing empty state");
            emptyState.hidden = false;
            return;
        }

        console.log("Rendering", roles.length, "roles");
        emptyState.hidden = true;

        for (var i = 0; i < roles.length; i++) {
            var role = roles[i];
            var tr = document.createElement("tr");

            // Name
            var nameTd = document.createElement("td");
            nameTd.textContent = role.name;
            tr.appendChild(nameTd);

            // Permissions
            var permsTd = document.createElement("td");
            permsTd.textContent = role.permissions;
            tr.appendChild(permsTd);

            // Description
            var descTd = document.createElement("td");
            descTd.textContent = role.description || "\u2014";
            tr.appendChild(descTd);

            // Members
            var membersTd = document.createElement("td");
            membersTd.textContent = role.member_count || 0;
            tr.appendChild(membersTd);

            // Actions
            var actionsTd = document.createElement("td");

            // Manage Members button
            var membersBtn = document.createElement("button");
            membersBtn.className = "btn-secondary";
            membersBtn.textContent = "\u229E Members";
            membersBtn.title = "Manage members";
            membersBtn.dataset.roleId = role.id;
            membersBtn.dataset.roleName = role.name;
            membersBtn.addEventListener("click", function () {
                openManageMembersModal(parseInt(this.dataset.roleId), this.dataset.roleName);
            });
            actionsTd.appendChild(membersBtn);

            // Edit button
            var editBtn = document.createElement("button");
            editBtn.className = "btn-reveal";
            editBtn.textContent = "\u270E";
            editBtn.title = "Edit";
            editBtn.dataset.roleId = role.id;
            editBtn.dataset.roleName = role.name;
            editBtn.dataset.rolePermissions = role.permissions;
            editBtn.dataset.roleDescription = role.description || "";
            editBtn.addEventListener("click", function () {
                openEditModal(parseInt(this.dataset.roleId), this.dataset.roleName, this.dataset.rolePermissions, this.dataset.roleDescription);
            });
            actionsTd.appendChild(editBtn);

            // Delete button
            var deleteBtn = document.createElement("button");
            deleteBtn.className = "btn-delete";
            deleteBtn.textContent = "\u2716";
            deleteBtn.title = "Delete";
            deleteBtn.dataset.roleId = role.id;
            deleteBtn.dataset.roleName = role.name;
            deleteBtn.addEventListener("click", function () {
                openDeleteModal(parseInt(this.dataset.roleId), this.dataset.roleName);
            });
            actionsTd.appendChild(deleteBtn);

            tr.appendChild(actionsTd);
            rolesTbody.appendChild(tr);
        }
    }

    // --- Create Role ---

    function openCreateModal() {
        if (!createRoleModal) return;
        if (createRoleName) createRoleName.value = "";
        if (createRolePermissions) createRolePermissions.value = "read-write";
        if (createRoleDescription) createRoleDescription.value = "";
        if (createRoleError) createRoleError.hidden = true;
        createRoleModal.hidden = false;
        if (createRoleName) createRoleName.focus();
    }

    function closeCreateModal() {
        if (!createRoleModal) return;
        createRoleModal.hidden = true;
    }

    // --- Edit Role ---

    function openEditModal(roleId, roleName, rolePermissions, roleDescription) {
        if (!editRoleModal) return;
        currentEditRoleId = roleId;
        currentEditRoleName = roleName;
        if (editRoleName) editRoleName.value = roleName;
        if (editRolePermissions) editRolePermissions.value = rolePermissions;
        if (editRoleDescription) editRoleDescription.value = roleDescription;
        if (editRoleError) editRoleError.hidden = true;
        editRoleModal.hidden = false;
        if (editRoleName) editRoleName.focus();
    }

    function closeEditModal() {
        if (!editRoleModal) return;
        editRoleModal.hidden = true;
        currentEditRoleId = null;
        currentEditRoleName = null;
    }

    // --- Delete Role ---

    function openDeleteModal(roleId, roleName) {
        if (!deleteRoleModal) return;
        currentDeleteRoleId = roleId;
        currentDeleteRoleName = roleName;
        if (deleteRoleName) deleteRoleName.textContent = roleName;
        if (deleteRoleError) deleteRoleError.hidden = true;
        deleteRoleModal.hidden = false;
    }

    function closeDeleteModal() {
        if (!deleteRoleModal) return;
        deleteRoleModal.hidden = true;
        currentDeleteRoleId = null;
        currentDeleteRoleName = null;
    }

    // --- Manage Members ---

    async function openManageMembersModal(roleId, roleName) {
        if (!manageMembersModal) return;
        currentManageRoleId = roleId;
        currentManageRoleName = roleName;
        if (manageMembersTitle) manageMembersTitle.textContent = "Manage Members: " + roleName;
        if (membersList) membersList.innerHTML = "<p>Loading members...</p>";
        if (addMemberError) addMemberError.hidden = true;
        manageMembersModal.hidden = false;

        // Load members
        try {
            var data = await apiFetch(API_BASE + "/roles/" + roleId + "/members");
            renderMembers(data.members);
        } catch (err) {
            console.error("Failed to load members:", err);
            if (membersList) membersList.innerHTML = "<p class=\"message-error\">Failed to load members.</p>";
        }

        // Load users for dropdown
        try {
            var usersData = await apiFetch(API_BASE + "/admin/users");
            populateUserDropdown(usersData.users);
        } catch (err) {
            console.error("Failed to load users:", err);
        }
    }

    function closeManageMembersModal() {
        if (!manageMembersModal) return;
        manageMembersModal.hidden = true;
        currentManageRoleId = null;
        currentManageRoleName = null;
    }

    function renderMembers(members) {
        if (!membersList) return;
        membersList.innerHTML = "";

        if (!members || members.length === 0) {
            var emptyP = document.createElement("p");
            emptyP.className = "empty-state";
            emptyP.textContent = "No members in this role.";
            membersList.appendChild(emptyP);
            return;
        }

        var table = document.createElement("table");
        table.innerHTML = "<thead><tr><th>User ID</th><th>Actions</th></tr></thead>";
        var tbody = document.createElement("tbody");

        for (var i = 0; i < members.length; i++) {
            var member = members[i];
            var tr = document.createElement("tr");

            var userIdTd = document.createElement("td");
            userIdTd.textContent = member.user_id;
            tr.appendChild(userIdTd);

            var actionsTd = document.createElement("td");
            var removeBtn = document.createElement("button");
            removeBtn.className = "btn-delete";
            removeBtn.textContent = "\u2716";
            removeBtn.title = "Remove from role";
            removeBtn.addEventListener("click", function () {
                removeMember(member.user_id);
            });
            actionsTd.appendChild(removeBtn);

            tr.appendChild(actionsTd);
            tbody.appendChild(tr);
        }

        table.appendChild(tbody);
        membersList.appendChild(table);
    }

    function populateUserDropdown(users) {
        if (!addMemberUser) return;
        addMemberUser.innerHTML = '<option value="">Select a user...</option>';
        for (var i = 0; i < users.length; i++) {
            var user = users[i];
            var option = document.createElement("option");
            option.value = user.user_id;
            option.textContent = user.user_id + (user.display_name ? " (" + user.display_name + ")" : "");
            addMemberUser.appendChild(option);
        }
    }

    async function removeMember(userId) {
        try {
            await apiFetch(API_BASE + "/roles/" + currentManageRoleId + "/members/" + encodeURIComponent(userId), {
                method: "DELETE",
            });
            showToast("User removed from role.", "success");
            // Reload members
            var data = await apiFetch(API_BASE + "/roles/" + currentManageRoleId + "/members");
            renderMembers(data.members);
            // Update role list
            loadRoles();
        } catch (err) {
            console.error("Failed to remove member:", err);
            showToast("Failed to remove user from role.", "error");
        }
    }

    // --- Toast ---

    function showToast(message, type) {
        var toast = document.createElement("div");
        toast.className = "toast toast-" + type;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(function () {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 5000);
    }

    // --- Event Listeners ---

    // Create role
    if (createRoleBtn) {
        createRoleBtn.addEventListener("click", openCreateModal);
    }
    if (createRoleCancelBtn) {
        createRoleCancelBtn.addEventListener("click", closeCreateModal);
    }
    if (createRoleForm) {
        createRoleForm.addEventListener("submit", function (e) {
            e.preventDefault();
            if (!createRoleName) return;

            createRoleSubmitBtn.disabled = true;
            createRoleSubmitBtn.textContent = "Creating...";
            if (createRoleError) createRoleError.hidden = true;

            var body = {
                name: createRoleName.value.trim(),
                permissions: createRolePermissions ? createRolePermissions.value : "read-write",
                description: createRoleDescription ? createRoleDescription.value.trim() : "",
            };

            apiFetch(API_BASE + "/roles", {
                method: "POST",
                body: JSON.stringify(body),
            }).then(function () {
                closeCreateModal();
                showToast("Role created.", "success");
                loadRoles();
            }).catch(function (err) {
                if (createRoleError) {
                    createRoleError.textContent = err.message;
                    createRoleError.hidden = false;
                }
            }).finally(function () {
                if (createRoleSubmitBtn) {
                    createRoleSubmitBtn.disabled = false;
                    createRoleSubmitBtn.textContent = "Create";
                }
            });
        });
    }

    // Edit role
    if (editRoleCancelBtn) {
        editRoleCancelBtn.addEventListener("click", closeEditModal);
    }
    if (editRoleForm) {
        editRoleForm.addEventListener("submit", function (e) {
            e.preventDefault();
            if (!editRoleName || currentEditRoleId === null) return;

            editRoleSubmitBtn.disabled = true;
            editRoleSubmitBtn.textContent = "Saving...";
            if (editRoleError) editRoleError.hidden = true;

            var body = {
                name: editRoleName.value.trim(),
                permissions: editRolePermissions ? editRolePermissions.value : null,
                description: editRoleDescription ? editRoleDescription.value.trim() : null,
            };

            apiFetch(API_BASE + "/roles/" + currentEditRoleId, {
                method: "PUT",
                body: JSON.stringify(body),
            }).then(function () {
                closeEditModal();
                showToast("Role updated.", "success");
                loadRoles();
            }).catch(function (err) {
                if (editRoleError) {
                    editRoleError.textContent = err.message;
                    editRoleError.hidden = false;
                }
            }).finally(function () {
                if (editRoleSubmitBtn) {
                    editRoleSubmitBtn.disabled = false;
                    editRoleSubmitBtn.textContent = "Save";
                }
            });
        });
    }

    // Delete role
    if (deleteRoleCancelBtn) {
        deleteRoleCancelBtn.addEventListener("click", closeDeleteModal);
    }
    if (deleteRoleConfirmBtn) {
        deleteRoleConfirmBtn.addEventListener("click", function () {
            if (currentDeleteRoleId === null) return;

            deleteRoleConfirmBtn.disabled = true;
            deleteRoleConfirmBtn.textContent = "Deleting...";

            apiFetch(API_BASE + "/roles/" + currentDeleteRoleId, {
                method: "DELETE",
            }).then(function () {
                closeDeleteModal();
                showToast("Role deleted.", "success");
                loadRoles();
            }).catch(function (err) {
                if (deleteRoleError) {
                    deleteRoleError.textContent = err.message;
                    deleteRoleError.hidden = false;
                }
            }).finally(function () {
                if (deleteRoleConfirmBtn) {
                    deleteRoleConfirmBtn.disabled = false;
                    deleteRoleConfirmBtn.textContent = "Delete";
                }
            });
        });
    }

    // Manage members
    if (manageMembersCloseBtn) {
        manageMembersCloseBtn.addEventListener("click", closeManageMembersModal);
    }
    if (addMemberForm) {
        addMemberForm.addEventListener("submit", function (e) {
            e.preventDefault();
            if (!addMemberUser || currentManageRoleId === null) return;

            var userId = addMemberUser.value;
            if (!userId) {
                if (addMemberError) {
                    addMemberError.textContent = "Please select a user.";
                    addMemberError.hidden = false;
                }
                return;
            }

            addMemberForm.disabled = true;
            if (addMemberError) addMemberError.hidden = true;

            apiFetch(API_BASE + "/roles/" + currentManageRoleId + "/members", {
                method: "POST",
                body: JSON.stringify({ user_id: userId }),
            }).then(function () {
                showToast("User added to role.", "success");
                // Reload members
                return apiFetch(API_BASE + "/roles/" + currentManageRoleId + "/members");
            }).then(function (data) {
                renderMembers(data.members);
                addMemberUser.value = "";
                // Update role list
                return loadRoles();
            }).catch(function (err) {
                if (addMemberError) {
                    addMemberError.textContent = err.message;
                    addMemberError.hidden = false;
                }
            }).finally(function () {
                addMemberForm.disabled = false;
            });
        });
    }

    // --- Init ---

    checkAuth().then(function (authenticated) {
        if (authenticated) {
            loadRoles();
            window.startSessionRefresh();
        }
    });
})();
