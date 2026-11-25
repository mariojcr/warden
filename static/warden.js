// SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
// SPDX-License-Identifier: Apache-2.0

// The only script the CSP allows (`script-src 'self'`): inputs come from server-set data-* attributes
// and it only posts JSON back to warden. No dependencies.
'use strict';
(() => {
  const enc = buf => {
    const u = new Uint8Array(buf);
    let s = '';
    for (const b of u) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const dec = s => {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const b = atob(s);
    const u = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    return u;
  };
  const say = (el, text, bad) => {
    if (!el) return;
    el.textContent = text;
    el.className = bad ? 'bad' : 'muted';
  };
  const post = async (url, body) => {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), credentials: 'same-origin' });
    let v = {};
    try { v = await r.json(); } catch (_) { /* no JSON body */ }
    return { ok: r.ok, v };
  };
  const why = e => {
    if (e && e.name === 'NotAllowedError') return 'Cancelled, or this device does not have the warden passkey.';
    if (e && e.name === 'InvalidStateError') return 'This passkey was already registered in warden.';
    return (e && e.message) || String(e);
  };
  const supported = () => !!(window.PublicKeyCredential && navigator.credentials);

  const approve = document.getElementById('wa-approve');
  if (approve) {
    const status = document.getElementById('wa-status');
    if (!supported()) {
      approve.disabled = true;
      say(status, 'This browser cannot use passkeys: approve with Pocket ID.', true);
    }
    approve.addEventListener('click', async () => {
      const id = approve.dataset.request;
      const csrf = approve.dataset.csrf;
      const base = `/r/${encodeURIComponent(id)}/passkey`;
      approve.disabled = true;
      say(status, 'Asking warden for a challenge…');
      try {
        const c = await post(`${base}/challenge`, { csrf });
        if (!c.ok) throw new Error(c.v.error || 'warden gave no challenge.');
        say(status, 'Use your passkey…');
        const cred = await navigator.credentials.get({
          publicKey: {
            challenge: dec(c.v.challenge),
            rpId: c.v.rp_id,
            allowCredentials: (c.v.allow || []).map(x => ({ type: 'public-key', id: dec(x) })),
            userVerification: 'required',
            timeout: c.v.timeout_ms,
          },
        });
        const r = cred.response;
        const a = await post(`${base}/approve`, {
          csrf,
          credential_id: enc(cred.rawId),
          client_data: enc(r.clientDataJSON),
          authenticator_data: enc(r.authenticatorData),
          signature: enc(r.signature),
        });
        if (!a.ok) throw new Error(a.v.error || 'warden did not accept it.');
        location.reload();
      } catch (e) {
        say(status, why(e), true);
        approve.disabled = false;
      }
    });
  }

  const reg = document.getElementById('wa-register');
  if (reg) {
    const status = document.getElementById('wa-status');
    if (!supported()) {
      reg.disabled = true;
      say(status, 'This browser cannot create passkeys.', true);
    }
    reg.addEventListener('click', async () => {
      const d = reg.dataset;
      const name = (document.getElementById('wa-name') || {}).value || 'passkey';
      reg.disabled = true;
      say(status, 'Create the passkey on your device…');
      try {
        const cred = await navigator.credentials.create({
          publicKey: {
            challenge: dec(d.challenge),
            rp: { id: d.rp, name: 'warden' },
            user: { id: dec(d.user), name: 'warden', displayName: 'warden (approve access)' },
            pubKeyCredParams: [-7, -8, -257].map(alg => ({ type: 'public-key', alg })),
            authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
            excludeCredentials: (d.exclude ? d.exclude.split(',') : []).filter(Boolean).map(x => ({ type: 'public-key', id: dec(x) })),
            attestation: 'none',
            timeout: 240000,
          },
        });
        const r = cred.response;
        const v = await post('/passkeys/register', {
          csrf: d.csrf,
          name,
          credential_id: enc(cred.rawId),
          client_data: enc(r.clientDataJSON),
          attestation: enc(r.attestationObject),
        });
        if (!v.ok) throw new Error(v.v.error || 'warden did not accept it.');
        say(status, `Registered “${v.v.name}”. You can now approve from the heimdall card.`);
        setTimeout(() => { location.href = '/'; }, 1500);
      } catch (e) {
        say(status, why(e), true);
        reg.disabled = false;
      }
    });
  }
})();
