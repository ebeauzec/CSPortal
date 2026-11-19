/* CSPortal front-end helpers. No external libraries. Loaded with a strict CSP (no inline script). */
(function () {
  "use strict";
  // Confirm before destructive actions: <button data-confirm="Delete this bucket?">
  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-confirm]");
    if (t && !window.confirm(t.getAttribute("data-confirm"))) { e.preventDefault(); }
    var c = e.target.closest("[data-copy]");
    if (c) {
      var src = document.getElementById(c.getAttribute("data-copy"));
      if (src && navigator.clipboard) {
        navigator.clipboard.writeText(src.textContent.trim());
        c.textContent = "Copied";
        setTimeout(function () { c.textContent = "Copy"; }, 1500);
      }
    }
  });
  // Submit a filter form when a select with data-autosubmit changes.
  document.addEventListener("change", function (e) {
    if (e.target.matches("select[data-autosubmit]") && e.target.form) { e.target.form.submit(); }
  });
})();
