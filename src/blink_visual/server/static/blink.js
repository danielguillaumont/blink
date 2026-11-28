// Blink dashboard glue. Adds the API token (kept in sessionStorage, never sent to other
// origins) and the CSRF token to every HTMX request, and shows request errors.
(function () {
  "use strict";
  var KEY = "blink.token";

  function readToken() {
    try { return window.sessionStorage.getItem(KEY) || ""; } catch (e) { return ""; }
  }
  function writeToken(value) {
    try {
      if (value) { window.sessionStorage.setItem(KEY, value); }
      else { window.sessionStorage.removeItem(KEY); }
    } catch (e) { /* storage unavailable: stay locked */ }
  }
  function csrf() {
    var meta = document.querySelector('meta[name="blink-csrf"]');
    return meta ? meta.getAttribute("content") : "";
  }
  function flash(message) {
    var box = document.getElementById("flash");
    if (!box) { return; }
    box.textContent = message;
    box.hidden = !message;
  }
  function updateLock() {
    var unlocked = !!readToken();
    document.documentElement.classList.toggle("unlocked", unlocked);
    var state = document.getElementById("lock-state");
    if (state) { state.textContent = unlocked ? "Unlocked" : "Locked"; }
  }

  document.addEventListener("htmx:configRequest", function (evt) {
    var token = readToken();
    if (token) { evt.detail.headers["Authorization"] = "Bearer " + token; }
    evt.detail.headers["X-CSRF-Token"] = csrf();
    flash("");
  });
  document.addEventListener("htmx:responseError", function (evt) {
    var xhr = evt.detail.xhr;
    var message = "Request failed (HTTP " + xhr.status + ")";
    try {
      var body = JSON.parse(xhr.responseText);
      if (body && body.detail) {
        message = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
      }
    } catch (e) { /* not JSON */ }
    if (xhr.status === 401) { message += ". Unlock with the API token first."; }
    flash(message);
  });
  document.addEventListener("submit", function (evt) {
    var form = evt.target;
    if (form.id === "unlock-form") {
      evt.preventDefault();
      var input = form.querySelector('input[name="token"]');
      writeToken(input ? input.value.trim() : "");
      form.reset();
      updateLock();
    } else if (form.id === "login-form") {
      var field = form.querySelector('input[name="token"]');
      writeToken(field ? field.value.trim() : "");
    }
  });
  document.addEventListener("click", function (evt) {
    if (evt.target && evt.target.id === "lock-button") {
      writeToken("");
      updateLock();
    }
  });
  document.addEventListener("DOMContentLoaded", updateLock);
})();
