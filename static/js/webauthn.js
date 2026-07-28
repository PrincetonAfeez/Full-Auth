/* WebAuthn/passkey client glue. Talks to the session-authenticated JSON API and relays the
   browser ceremony to the server. Loaded as an external file so it satisfies the strict
   `script-src 'self'` CSP (no inline handlers). */
(function () {
  "use strict";

  var URLS = {
    registerOptions: "/api/v1/me/2fa/webauthn/register/options/",
    registerVerify: "/api/v1/me/2fa/webauthn/register/verify/",
    authRegisterOptions: "/api/v1/auth/2fa/webauthn/register/options/",
    authRegisterVerify: "/api/v1/auth/2fa/webauthn/register/verify/",
    assertOptions: "/api/v1/auth/2fa/webauthn/options/",
    assertVerify: "/api/v1/auth/2fa/webauthn/verify/",
    stepUpOptions: "/api/v1/me/step-up/webauthn/options/",
    stepUpVerify: "/api/v1/me/step-up/webauthn/verify/",
  };

  function b64urlToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    var pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
    var raw = atob(s + pad);
    var buf = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
    return buf.buffer;
  }

  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var str = "";
    for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function csrfToken() {
    var el = document.querySelector('meta[name="csrf-token"]');
    return el ? el.getAttribute("content") : "";
  }

  async function api(url, body) {
    var res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
      body: body ? JSON.stringify(body) : "{}",
    });
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok) {
      if (res.status === 403 && data.error && data.error.code === "recent_auth_required") {
        var fields = data.error.fields || {};
        var target = fields.step_up_url;
        if (!target) {
          var action = fields.action || "manage_mfa";
          target = "/step-up/?" + new URLSearchParams({ action: action, next: window.location.pathname }).toString();
        }
        window.location.href = target;
        throw new Error("Redirecting to step-up…");
      }
      throw new Error((data.error && data.error.message) || ("HTTP " + res.status));
    }
    return data;
  }

  function status(msg) {
    var el = document.getElementById("passkey-status");
    if (el) el.textContent = msg;
  }

  function prepCreateOptions(opts) {
    var challenge = opts.challenge;
    opts.challenge = b64urlToBuf(opts.challenge);
    opts.user.id = b64urlToBuf(opts.user.id);
    if (opts.excludeCredentials) {
      opts.excludeCredentials = opts.excludeCredentials.map(function (c) {
        return Object.assign({}, c, { id: b64urlToBuf(c.id) });
      });
    }
    return challenge;
  }

  function prepGetOptions(opts) {
    var challenge = opts.challenge;
    opts.challenge = b64urlToBuf(opts.challenge);
    if (opts.allowCredentials) {
      opts.allowCredentials = opts.allowCredentials.map(function (c) {
        return Object.assign({}, c, { id: b64urlToBuf(c.id) });
      });
    }
    return challenge;
  }

  function credentialPayload(cred, challenge) {
    return {
      challenge: challenge,
      credential: {
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        type: cred.type,
        response: cred.response.attestationObject
          ? {
              attestationObject: bufToB64url(cred.response.attestationObject),
              clientDataJSON: bufToB64url(cred.response.clientDataJSON),
            }
          : {
              authenticatorData: bufToB64url(cred.response.authenticatorData),
              clientDataJSON: bufToB64url(cred.response.clientDataJSON),
              signature: bufToB64url(cred.response.signature),
              userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
            },
        clientExtensionResults: {},
      },
    };
  }

  async function register(optionsUrl, verifyUrl, onSuccess, extraBody) {
    status("Requesting registration options…");
    var opts = await api(optionsUrl);
    var challenge = prepCreateOptions(opts);
    status("Waiting for your authenticator…");
    var cred = await navigator.credentials.create({ publicKey: opts });
    var payload = credentialPayload(cred, challenge);
    if (extraBody) Object.assign(payload, extraBody);
    await api(verifyUrl, payload);
    status("Passkey registered.");
    if (onSuccess) onSuccess();
    else window.location.reload();
  }

  async function authenticate(optionsUrl, verifyUrl, onSuccess, extraBody) {
    status("Requesting sign-in options…");
    var opts = await api(optionsUrl);
    var challenge = prepGetOptions(opts);
    status("Waiting for your authenticator…");
    var cred = await navigator.credentials.get({ publicKey: opts });
    var payload = credentialPayload(cred, challenge);
    if (extraBody) Object.assign(payload, extraBody);
    var result = await api(verifyUrl, payload);
    if (onSuccess) onSuccess(result);
    else if (result.authenticated) window.location.href = "/";
  }

  function stepUpContext() {
    var form = document.getElementById("step-up-form");
    if (!form) return {};
    var actionInput = form.querySelector('input[name="action"]');
    var nextInput = form.querySelector('input[name="next"]');
    var tokenInput = form.querySelector('input[name="token"]');
    return {
      action: actionInput ? actionInput.value : "default",
      next: nextInput ? nextInput.value : "/",
      token: tokenInput ? tokenInput.value : "",
    };
  }

  window.FullAuthWebAuthn = {
    bindRegister: function () {
      var reg = document.getElementById("passkey-register");
      if (reg) {
        reg.addEventListener("click", function () {
          register(URLS.registerOptions, URLS.registerVerify).catch(function (e) {
            status("Registration failed: " + e.message);
          });
        });
      }
    },
    bindAuthEnrollRegister: function () {
      var btn = document.getElementById("passkey-enroll-auth");
      if (btn) {
        btn.addEventListener("click", function () {
          register(URLS.authRegisterOptions, URLS.authRegisterVerify, function () {
            window.location.href = "/";
          }).catch(function (e) {
            status("Registration failed: " + e.message);
          });
        });
      }
    },
    bindAuthenticate: function () {
      var auth = document.getElementById("passkey-authenticate");
      if (auth) {
        auth.addEventListener("click", function () {
          authenticate(URLS.assertOptions, URLS.assertVerify).catch(function (e) {
            status("Sign-in failed: " + e.message);
          });
        });
      }
    },
    bindStepUp: function () {
      var btn = document.getElementById("passkey-step-up");
      if (!btn) return;
      btn.addEventListener("click", function () {
        var ctx = stepUpContext();
        authenticate(
          URLS.stepUpOptions,
          URLS.stepUpVerify,
          function (result) {
            window.location.href = (result && result.next) || ctx.next || "/";
          },
          { action: ctx.action, next: ctx.next, token: ctx.token }
        ).catch(function (e) {
          status("Passkey verification failed: " + e.message);
        });
      });
    },
  };

  document.addEventListener("DOMContentLoaded", function () {
    window.FullAuthWebAuthn.bindRegister();
    window.FullAuthWebAuthn.bindAuthenticate();
    window.FullAuthWebAuthn.bindAuthEnrollRegister();
    window.FullAuthWebAuthn.bindStepUp();
  });
})();
