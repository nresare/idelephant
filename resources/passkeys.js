(() => {
    const panel = document.getElementById("passkeys");
    if (!panel) return;
    const list = document.getElementById("passkey-list");
    const form = document.getElementById("passkey-editor");
    const name = document.getElementById("passkey-name");
    const add = document.getElementById("passkey-add");
    const save = document.getElementById("passkey-save");
    const status = document.getElementById("passkey-status");
    let editing = null;
    let csrf = panel.dataset.csrfToken;

    async function request(path, method, body) {
        const response = await fetch(path, {
            method,
            headers: {"Content-Type": "application/json"},
            body: body ? JSON.stringify({...body, csrf_token: csrf}) : undefined,
        });
        if (!response.ok) throw new Error(await readErrorMessage(response, "The request failed. Please try again."));
        return response;
    }

    async function refresh() {
        const response = await request("/api/passkeys", "GET");
        const data = await response.json();
        csrf = data.csrf_token;
        list.replaceChildren();
        for (const key of data.passkeys) {
            const row = document.createElement("li");
            row.className = "passkey-row";
            row.dataset.id = key.id;
            const label = document.createElement("span");
            label.className = "passkey-name";
            label.textContent = key.name;
            const actions = document.createElement("div");
            actions.className = "button-group";
            for (const action of ["rename", "delete"]) {
                const button = document.createElement("button");
                button.type = "button";
                button.dataset.action = action;
                button.className = action === "delete" ? "danger" : "secondary";
                button.textContent = action === "delete" ? "Delete" : "Rename";
                actions.append(button);
            }
            row.append(label, actions);
            list.append(row);
        }
        if (!data.passkeys.length) {
            const empty = document.createElement("li");
            empty.className = "muted";
            empty.textContent = "You have no passkeys. Register one to sign in again after this session ends.";
            list.append(empty);
        }
    }

    function edit(id, value) {
        hideError();
        status.textContent = "";
        editing = id;
        name.value = value;
        save.textContent = id ? "Save name" : "Register passkey";
        form.hidden = false;
        add.hidden = true;
        name.focus();
    }
    function close() {
        form.hidden = true;
        add.hidden = false;
        editing = null;
    }
    async function perform(action) {
        hideError();
        panel.querySelectorAll("button, input").forEach(control => control.disabled = true);
        try { await action(); }
        catch (error) {
            showError(error.name === "NotAllowedError" ? "Passkey registration was cancelled or timed out. You can try again." : error.message);
        } finally {
            panel.querySelectorAll("button, input").forEach(control => control.disabled = false);
        }
    }

    add.addEventListener("click", () => edit(null, ""));
    document.getElementById("passkey-cancel").addEventListener("click", close);
    list.addEventListener("click", event => {
        const button = event.target.closest("button[data-action]");
        if (!button) return;
        const row = button.closest("li");
        const label = row.querySelector(".passkey-name").textContent;
        if (button.dataset.action === "rename") return edit(row.dataset.id, label);
        if (!confirm(`Delete passkey “${label}”?`)) return;
        perform(async () => {
            await request(`/api/passkeys/${encodeURIComponent(row.dataset.id)}`, "DELETE", {});
            close();
            await refresh();
            status.textContent = "Passkey deleted.";
        });
    });
    form.addEventListener("submit", event => {
        event.preventDefault();
        const keyName = name.value.trim();
        perform(async () => {
            if (editing) {
                await request(`/api/passkeys/${encodeURIComponent(editing)}`, "PUT", {name: keyName});
            } else {
                const data = await (await request("/api/passkeys/register-start", "POST", {name: keyName})).json();
                const options = make_register_options(base64ToBytes(data.challenge), base64ToBytes(data.user_id), data.email);
                options.rp.id = data.rp_id;
                options.excludeCredentials = data.exclude_credentials.map(key => ({type: "public-key", id: base64ToBytes(key.id)}));
                const credential = await navigator.credentials.create({publicKey: options});
                await request("/api/passkeys/register-finish", "POST", {credential: JSON.parse(register_response_as_json(credential))});
            }
            const message = editing ? "Passkey renamed." : "Passkey registered.";
            close();
            await refresh();
            status.textContent = message;
        });
    });
})();
