(() => {
    const form = document.getElementById("app-form");
    const clientId = document.getElementById("app-client-id");
    const name = document.getElementById("app-name");
    const redirects = document.getElementById("app-redirects");
    const save = document.getElementById("app-save");
    const cancel = document.getElementById("app-cancel");
    const title = document.getElementById("app-form-title");
    const status = document.getElementById("apps-status");
    const list = document.getElementById("apps-list");
    let editing = false;

    function reset() {
        form.reset();
        editing = false;
        clientId.readOnly = false;
        cancel.hidden = true;
        title.textContent = "Register an app";
        save.textContent = "Register app";
    }

    async function request(method, body) {
        const response = await fetch("/oauth-client", {
            method,
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(body),
        });
        if (!response.ok) {
            if (response.status === 401) throw new Error("An admin login is required. Please sign in again.");
            if (response.status === 404) throw new Error("This app no longer exists. Reload the page to refresh the list.");
            throw new Error(await readErrorMessage(response, "Could not save the app registration."));
        }
        return response;
    }

    async function refresh() {
        const response = await request("GET");
        const apps = await response.json();
        list.replaceChildren();
        if (!apps.length) list.textContent = "No apps registered yet.";
        for (const app of apps) {
            const card = document.createElement("article");
            card.className = "app-card";
            const heading = document.createElement("h3");
            heading.textContent = app.name;
            const id = document.createElement("p");
            id.textContent = `Client ID: ${app.client_id}`;
            const uris = document.createElement("ul");
            for (const uri of app.redirect_uris) {
                const item = document.createElement("li");
                item.textContent = uri;
                uris.append(item);
            }
            const actions = document.createElement("div");
            actions.className = "button-group";
            const edit = document.createElement("button");
            edit.textContent = "Edit";
            edit.onclick = () => {
                editing = true;
                clientId.value = app.client_id;
                clientId.readOnly = true;
                name.value = app.name;
                redirects.value = app.redirect_uris.join("\n");
                title.textContent = "Edit app";
                save.textContent = "Save changes";
                cancel.hidden = false;
                name.focus();
            };
            const remove = document.createElement("button");
            remove.textContent = "Delete";
            remove.onclick = async () => {
                if (!confirm(`Delete “${app.name}”? This also revokes its access tokens and saved consents.`)) return;
                remove.disabled = true;
                hideError();
                try {
                    await request("DELETE", {client_id: app.client_id});
                    if (editing && clientId.value === app.client_id) reset();
                    status.textContent = "App deleted.";
                    await refresh();
                } catch (error) { showError(error.message); }
                finally { remove.disabled = false; }
            };
            actions.append(edit, remove);
            card.append(heading, id, uris, actions);
            list.append(card);
        }
    }

    cancel.onclick = reset;
    form.onsubmit = async (event) => {
        event.preventDefault();
        hideError();
        save.disabled = true;
        try {
            await request(editing ? "PUT" : "POST", {
                client_id: clientId.value.trim(),
                name: name.value.trim(),
                redirect_uris: redirects.value.split(/\r?\n/).map(uri => uri.trim()).filter(Boolean),
            });
            status.textContent = editing ? "Changes saved." : "App registered.";
            reset();
            await refresh();
        } catch (error) { showError(error.message); }
        finally { save.disabled = false; }
    };
    status.textContent = "Loading app registrations…";
    refresh().then(() => { status.textContent = ""; }).catch(error => {
        status.textContent = "App registrations could not be loaded. Reload to try again.";
        showError(error.message);
    });
})();
