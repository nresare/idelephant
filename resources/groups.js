(() => {
    const list = document.getElementById("groups-list");
    const detail = document.getElementById("group-detail");
    const status = document.getElementById("groups-status");
    const newButton = document.getElementById("group-new");
    let groups = [];
    let users = [];
    let selectedId = null;
    let mode = "view";

    function element(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    function button(label, handler, className = "") {
        const node = element("button", className, label);
        node.type = "button";
        node.addEventListener("click", handler);
        return node;
    }

    async function request(path, method = "GET", body) {
        const response = await fetch(path, {
            method,
            headers: body ? {"Content-Type": "application/json"} : {},
            body: body ? JSON.stringify(body) : undefined,
        });
        if (!response.ok) {
            if (response.status === 401) throw new Error("An admin login is required. Please sign in again.");
            if (response.status === 404) throw new Error("This group or user no longer exists. Reload the page to refresh the list.");
            throw new Error(await readErrorMessage(response, "Could not update groups."));
        }
        return response.headers.get("content-type")?.includes("application/json") ? response.json() : null;
    }

    async function refresh() {
        [groups, users] = await Promise.all([request("/api/groups"), request("/api/users")]);
        if (selectedId && !groups.some(group => group.id === selectedId)) selectedId = null;
        if (!selectedId && groups.length && mode === "view") selectedId = groups[0].id;
        render();
    }

    function showErrorMessage(error) {
        showError(error.message);
        status.textContent = "";
    }

    async function change(path, method, body, message) {
        hideError();
        try {
            const result = await request(path, method, body);
            mode = "view";
            if (method === "POST" && path === "/api/groups") selectedId = result.id;
            await refresh();
            status.textContent = message;
        } catch (error) {
            showErrorMessage(error);
        }
    }

    function renderList() {
        list.replaceChildren();
        if (!groups.length) {
            list.append(element("p", "muted", "No groups yet. Create your first group."));
            return;
        }
        for (const group of groups) {
            const row = element("article", "admin-row");
            const select = button("", () => {
                selectedId = group.id;
                mode = "view";
                render();
            }, "admin-row-select");
            select.setAttribute("aria-label", `View ${group.name}`);
            if (group.id === selectedId && mode === "view") select.setAttribute("aria-current", "true");
            select.append(element("h3", "", group.name), element("p", "", group.description));
            const count = element("span", "muted", `${group.members.length} ${group.members.length === 1 ? "member" : "members"}`);
            row.append(select, count);
            list.append(row);
        }
    }

    function renderForm(group) {
        const creating = !group;
        detail.replaceChildren(element("h2", "", creating ? "New group" : "Edit group"));
        detail.append(element("p", "muted", "A clear name and description help admins place people correctly."));
        const form = element("form");
        const nameLabel = element("label", "", "Group name");
        nameLabel.htmlFor = "group-name";
        const name = element("input");
        name.id = "group-name";
        name.required = true;
        name.maxLength = 80;
        name.value = group?.name ?? "";
        const descriptionLabel = element("label", "", "Description");
        descriptionLabel.htmlFor = "group-description";
        const description = element("textarea");
        description.id = "group-description";
        description.rows = 3;
        description.required = true;
        description.maxLength = 300;
        description.value = group?.description ?? "";
        const actions = element("div", "button-group");
        const save = element("button", "primary", creating ? "Create group" : "Save changes");
        save.type = "submit";
        actions.append(save, button("Cancel", () => { mode = "view"; render(); }));
        form.append(nameLabel, name, descriptionLabel, description, actions);
        form.addEventListener("submit", async event => {
            event.preventDefault();
            save.disabled = true;
            await change(
                creating ? "/api/groups" : `/api/groups/${encodeURIComponent(group.id)}`,
                creating ? "POST" : "PUT",
                {name: name.value.trim(), description: description.value.trim()},
                creating ? "Group created." : "Group updated.",
            );
            save.disabled = false;
        });
        detail.append(form);
        name.focus();
    }

    function renderDetail() {
        const group = groups.find(item => item.id === selectedId);
        if (mode === "create") return renderForm(null);
        if (mode === "edit" && group) return renderForm(group);
        detail.replaceChildren();
        if (!group) {
            detail.append(element("h2", "", "Select a group"), element("p", "muted", "Choose a group to view its members."));
            return;
        }
        detail.append(element("h2", "", group.name), element("p", "muted", group.description));
        const actions = element("div", "button-group");
        actions.append(
            button("Edit details", () => { mode = "edit"; render(); }),
            button("Delete group", () => { confirm.hidden = false; }, "danger"),
        );
        detail.append(actions);
        const confirm = element("div", "confirm-box");
        confirm.hidden = true;
        confirm.append(element("p", "", `Delete “${group.name}”? Members will keep their accounts.`));
        const confirmActions = element("div", "button-group");
        confirmActions.append(
            button("Delete group", async () => {
                await change(`/api/groups/${encodeURIComponent(group.id)}`, "DELETE", undefined, "Group deleted.");
            }, "danger"),
            button("Cancel", () => { confirm.hidden = true; }),
        );
        confirm.append(confirmActions);
        detail.append(confirm, element("hr"), element("h3", "", `Members (${group.members.length})`));
        const memberList = element("ul");
        if (!group.members.length) memberList.append(element("li", "muted", "No members yet."));
        for (const member of group.members) {
            const item = element("li");
            item.append(element("span", "", member.email), button("Remove", () => change(
                `/api/groups/${encodeURIComponent(group.id)}/members`, "DELETE",
                {subject_id: member.id}, `${member.email} removed from ${group.name}.`,
            )));
            memberList.append(item);
        }
        detail.append(memberList);
        const available = users.filter(user => !group.members.some(member => member.id === user.id));
        const label = element("label", "", "Add a user");
        label.htmlFor = "group-member";
        const select = element("select");
        select.id = "group-member";
        select.append(new Option("Select an existing user", ""));
        for (const user of available) select.append(new Option(user.email, user.id));
        const add = button("Add to group", () => {
            if (!select.value) return;
            change(`/api/groups/${encodeURIComponent(group.id)}/members`, "POST",
                {subject_id: select.value}, "User added to group.");
        });
        add.disabled = !available.length;
        detail.append(label, select, element("div", "button-group"));
        detail.lastChild.append(add);
    }

    function render() {
        renderList();
        renderDetail();
    }

    newButton.addEventListener("click", () => { mode = "create"; render(); });
    status.textContent = "Loading groups…";
    refresh().then(() => { status.textContent = ""; }).catch(showErrorMessage);
})();
