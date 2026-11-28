// Kept out of the page so /docs needs no inline script under its CSP.
window.addEventListener("load", function () {
  "use strict";
  window.ui = window.SwaggerUIBundle({ url: "/openapi.json", dom_id: "#swagger-ui" });
});
