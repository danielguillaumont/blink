// Blink lab: simulated third-party trust badge served from a second local origin.
// LAB FIXTURE - inert: it only writes a static label.
(function () {
  "use strict";
  var badge = document.getElementById("trust-badge");
  if (badge) {
    badge.textContent = "Protected by LabTrust (demo badge)";
  }
})();
