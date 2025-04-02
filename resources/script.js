
async function register() {
    const data = await get_challenge();
    const registrationResult = await navigator.credentials.create(
        {publicKey: make_register_options(data["challenge"], data["user_id"], data["email"])},
    ).then((publicKeyCredential) => {
        const options = {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: register_response_as_json(publicKeyCredential),
        }
        return fetch("/register-finish", options)
    })
    alert("response from registration: " + registrationResult.ok);
}

async function authenticate() {
    const auth_result = await navigator.credentials.get({publicKey: {challenge: await get_auth_challenge()}})
        .then((credential) => {
            const options = {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: auth_response_as_json(credential),
            }
            return fetch("/auth-finish", options)
        })
    if (auth_result.ok) {
        location.reload()
    } else {
        alert("something went wrong: " + auth_result.status);
    }
}

async function logout() {
    const result = await fetch("/logout", {method: "GET"})
    if (result.ok) {
        location.reload()
    }
}

async function get_auth_challenge() {
    const resp = await fetch("/auth-start", {method: "GET"}).then(resp => resp.json());
    return base64ToBytes(resp.challenge);
}

function register_response_as_json(publicKeyCredential) {
    const { id, rawId, response, type } = publicKeyCredential;
    return JSON.stringify({
        id,
        rawId: bytesToBase64(rawId),
        response: {
            attestationObject: bytesToBase64(response.attestationObject),
            // even though this value is json data presumably in text format, is ByteArray so base64 encode
            // it as well.
            clientDataJSON: bytesToBase64(response.clientDataJSON),
            publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
            publicKey: bytesToBase64(response.getPublicKey()),
            authenticatorData: bytesToBase64(response.getAuthenticatorData()),
        },
        type,
        clientExtensionResults: publicKeyCredential.clientExtensionResults,
    })
}

function auth_response_as_json(auth_response) {
    const { id, rawId, response, type, authenticatorAttachment } = auth_response;
    return JSON.stringify({
        id,
        rawId: bytesToBase64(rawId),
        response: {
            clientDataJSON: bytesToBase64(response.clientDataJSON),
            authenticatorData: bytesToBase64(response.authenticatorData),
            signature: bytesToBase64(response.signature),
            userHandle: bytesToBase64(response.userHandle),
        },
        type,
        authenticatorAttachment,
    })
}

function make_register_options(challenge, user_id, email) {
    // Docs: https://www.w3.org/TR/webauthn-2/#sctn-sample-registration
    return {
        challenge: challenge,
        rp: {
            name: "identityprovider",
        },
        user: {
            displayName: "identityprovider",
            id: user_id,
            name: email,
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    }

}

// Returns a Promise<UInt8Array>
async function get_challenge(){
    return await fetch("/register-start")
        .then((response) => response.json())
        .then(resp => {
            return {
                "challenge": base64ToBytes(resp.challenge),
                "user_id": base64ToBytes(resp.user_id),
                "email": resp.email,
            }
        });
}

//  Copied from https://developer.mozilla.org/en-US/docs/Web/API/Window/btoa
//  with some further snippets from  https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/browser/src/helpers/bufferToBase64URLString.ts
function bytesToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const binString = Array.from(bytes, (byte) =>
        String.fromCodePoint(byte),
    ).join("");
    return btoa(binString).replace(/=+$/, '');
}

function base64ToBytes(base64) {
    const binString = atob(base64);
    return Uint8Array.from(binString, (m) => m.codePointAt(0));
}
