// Blink lab: first-party checkout script.
// LAB FIXTURE - benign by design: it never reads form field values and never sends user input.
(function () {
  "use strict";
  document.addEventListener("DOMContentLoaded", function () {
    var total = document.getElementById("order-total");
    if (total) {
      total.setAttribute("data-ready", "true");
    }
    fetch("/api/config", { credentials: "same-origin" })
      .then(function (response) { return response.json(); })
      .then(function (config) {
        if (config.beacon_url) {
          // Constant payload to a localhost sink; exists only to create a network signal.
          navigator.sendBeacon(config.beacon_url, '{"ping":1}');
        }
      })
      .catch(function () {});
  });
  // LAB FIXTURE: an inert extra statement so the content hash of an approved script changes.
  window.__blinkLabBuild = "unexpected-change";
})();
