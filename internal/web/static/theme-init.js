/*
 * Applies the persisted theme to <html> before first paint.
 *
 * Loaded synchronously (no defer) from <head>: a deferred script would run
 * after the body paints and the page would flash in the wrong theme. It is an
 * external file rather than an inline script because the Content-Security-
 * Policy is `script-src 'self'` with no nonce, and a test enforces that the CSP
 * never permits inline execution.
 */
(function () {
  "use strict";

  var STORAGE_KEY = "pm-theme";
  var VALID = { light: true, dark: true, system: true };

  function stored() {
    try {
      var value = localStorage.getItem(STORAGE_KEY);
      return VALID[value] ? value : "system";
    } catch {
      // Private mode or blocked storage: fall back to the system preference.
      return "system";
    }
  }

  function apply(theme) {
    document.documentElement.setAttribute("data-pm-theme", theme);
  }

  function persist(theme) {
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Non-fatal: the theme still applies for this page view.
    }
  }

  function syncButtons(theme) {
    var buttons = document.querySelectorAll("[data-pm-theme-set]");
    for (var i = 0; i < buttons.length; i++) {
      var pressed = buttons[i].getAttribute("data-pm-theme-set") === theme;
      buttons[i].setAttribute("aria-pressed", String(pressed));
    }
  }

  apply(stored());

  // The switcher lives in the nav, which does not exist yet at this point.
  document.addEventListener("DOMContentLoaded", function () {
    var current = stored();
    syncButtons(current);

    document.addEventListener("click", function (event) {
      var target = event.target.closest("[data-pm-theme-set]");
      if (!target) {
        return;
      }
      var next = target.getAttribute("data-pm-theme-set");
      if (!VALID[next]) {
        return;
      }
      apply(next);
      persist(next);
      syncButtons(next);
    });
  });
})();
