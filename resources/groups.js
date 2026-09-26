(() => {
    const list = document.getElementById("groups-list");
    const status = document.getElementById("groups-status");
    const form = document.getElementById("group-form");
    let users = [];
    const element = (tag, text) => {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        return node;
    };
    async function request(path, method = "GET", body) {
        const response = await fetch(path, {
            method, headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
        });
        if (!response.ok) {
            if (response.status === 401) throw new Error("An admin login is required. Please sign in again.");
            if (response.status === 404) throw new Error("This group no longer exists. Reload to refresh the list.");
            throw new Error(await readErrorMessage(response, "Could not update groups."));
        }
        return response;
    }
    async function mutate(button, action, message) {
        button.disabled = true;
        hideError();
        try {
            await action();
            status.textContent = message;
            await refresh();
        } catch (error) { showError(error.message); }
        finally { button.disabled = false; }
    }
    async function refresh() {
        const [groupsResponse, usersResponse] = await Promise.all([request("/groups"), request("/groups/users")]);
        const groups = await groupsResponse.json();
        users = await usersResponse.json();
        list.replaceChildren();
        if (!groups.length) list.append(element("p", "No groups yet."));
        for (const group of groups) {
            const card = element("article");
            card.className = "app-card";
            card.append(element("h3", group.name), element("p", `Group ID: ${group.group_id}`));
            if (!group.members.length) card.append(element("p", "No members yet."));
            for (const userId of group.members) {
                const email = users.find(user => user.user_id === userId)?.email || userId;
                const row = element("div");
                row.className = "group-member";
                const remove = element("button", "Remove");
                remove.setAttribute("aria-label", `Remove ${email} from ${group.name}`);
                remove.onclick = () => mutate(remove, () => request("/groups/members", "DELETE", {
                    group_id: group.group_id, user_id: userId,
                }), "Member removed. Existing ID tokens keep their claims until expiry.");
                row.append(element("span", email), remove);
                card.append(row);
            }
            const memberForm = element("form");
            memberForm.className = "management-form";
            const select = element("select");
            select.id = `member-${group.group_id}`;
            select.required = true;
            const label = element("label", "Add a member");
            label.htmlFor = select.id;
            const placeholder = element("option", "Select a user");
            placeholder.value = "";
            select.append(placeholder);
            for (const user of users.filter(user => !group.members.includes(user.user_id))) {
                const option = element("option", user.email);
                option.value = user.user_id;
                select.append(option);
            }
            const add = element("button", "Add member");
            add.type = "submit";
            add.disabled = select.options.length === 1;
            const actions = element("div");
            actions.className = "button-group";
            actions.append(add);
            memberForm.append(label, select, actions);
            memberForm.onsubmit = event => {
                event.preventDefault();
                mutate(add, () => request("/groups/members", "POST", {
                    group_id: group.group_id, user_id: select.value,
                }), "Member added.");
            };
            const removeGroup = element("button", "Delete group");
            removeGroup.onclick = () => {
                if (!confirm(`Delete “${group.name}” and all its memberships? Existing ID tokens keep their claims until expiry.`)) return;
                mutate(removeGroup, () => request("/groups", "DELETE", {group_id: group.group_id}), "Group deleted.");
            };
            const deleteActions = element("div");
            deleteActions.className = "button-group";
            deleteActions.append(removeGroup);
            card.append(memberForm, deleteActions);
            list.append(card);
        }
    }
    form.onsubmit = event => {
        event.preventDefault();
        mutate(form.querySelector("button"), async () => {
            await request("/groups", "POST", {
                group_id: document.getElementById("group-id").value.trim(),
                name: document.getElementById("group-name").value.trim(),
            });
            form.reset();
        }, "Group created.");
    };
    status.textContent = "Loading groups…";
    refresh().then(() => { status.textContent = ""; }).catch(error => {
        status.textContent = "Groups could not be loaded. Reload to try again.";
        showError(error.message);
    });
})();
