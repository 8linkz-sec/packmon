(function () {
  function setupAutoRefresh(control) {
    if (control.dataset.autoRefreshReady === "true") {
      return;
    }

    var eventName = control.dataset.autoRefreshEvent;
    var intervalMs = Number.parseInt(control.dataset.autoRefreshIntervalMs || "", 10);
    var toggle = control.querySelector("[data-auto-refresh-toggle]");
    var status = control.querySelector("[data-auto-refresh-status]");
    if (!eventName || !Number.isFinite(intervalMs) || intervalMs <= 0 || !toggle) {
      return;
    }

    control.dataset.autoRefreshReady = "true";
    var paused = false;
    var runningLabel = control.dataset.autoRefreshRunningLabel || "Auto-refresh on";
    var pausedLabel = control.dataset.autoRefreshPausedLabel || "Auto-refresh paused";

    function renderState() {
      toggle.setAttribute("aria-pressed", paused ? "true" : "false");
      toggle.textContent = paused ? "Resume auto-refresh" : "Pause auto-refresh";
      if (status) {
        status.textContent = paused ? pausedLabel : runningLabel;
      }
    }

    toggle.addEventListener("click", function () {
      paused = !paused;
      renderState();
    });

    window.setInterval(function () {
      if (paused) {
        return;
      }
      document.body.dispatchEvent(new Event(eventName, { bubbles: true }));
    }, intervalMs);

    renderState();
  }

  function initAutoRefreshControls() {
    document.querySelectorAll("[data-auto-refresh-control]").forEach(setupAutoRefresh);
  }

  function setupSubmitLock(form) {
    if (form.dataset.submitLockReady === "true") {
      return;
    }

    var button = form.querySelector("[data-submit-lock-button]");
    if (!button) {
      return;
    }

    form.dataset.submitLockReady = "true";
    form.addEventListener("submit", function () {
      if (button.disabled) {
        return;
      }
      button.dataset.originalText = button.textContent;
      var label = form.dataset.submitLockLabel;
      if (label) {
        button.textContent = label;
      }
      button.disabled = true;
      button.setAttribute("aria-disabled", "true");
    });
  }

  function initSubmitLocks() {
    document.querySelectorAll("[data-submit-lock]").forEach(setupSubmitLock);
  }

  function setupSelectOnFocus(input) {
    if (input.dataset.selectOnFocusReady === "true") {
      return;
    }

    input.dataset.selectOnFocusReady = "true";
    input.addEventListener("focus", function () {
      if (typeof input.select === "function") {
        input.select();
      }
    });
  }

  function initSelectOnFocusInputs() {
    document.querySelectorAll("[data-select-on-focus]").forEach(setupSelectOnFocus);
  }

  function setupCopyButton(button) {
    if (button.dataset.copyReady === "true") {
      return;
    }

    var selector = button.dataset.copyTarget;
    if (!selector) {
      return;
    }

    button.dataset.copyReady = "true";
    button.addEventListener("click", function () {
      var target = document.querySelector(selector);
      if (!target) {
        return;
      }

      if (typeof target.focus === "function") {
        target.focus();
      }
      if (typeof target.select === "function") {
        target.select();
      }
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        navigator.clipboard.writeText(target.value || "");
      }
    });
  }

  function initCopyButtons() {
    document.querySelectorAll("[data-copy-target]").forEach(setupCopyButton);
  }

  function setupFeedSyncButton(button) {
    if (button.dataset.feedSyncReady === "true") {
      return;
    }

    button.dataset.feedSyncReady = "true";
    var defaultLabel = button.dataset.feedSyncLabel || button.textContent || "Sync now";
    var busyLabel = button.dataset.feedSyncBusyLabel || "Syncing...";
    var flashTarget = button.dataset.feedSyncFlashTarget || "";

    function resetLabel() {
      button.textContent = button.dataset.originalText || defaultLabel;
    }

    button.addEventListener("htmx:beforeRequest", function () {
      button.dataset.originalText = button.textContent || defaultLabel;
      button.textContent = busyLabel;
    });
    button.addEventListener("htmx:afterRequest", resetLabel);
    button.addEventListener("htmx:responseError", function (event) {
      var flash = flashTarget ? document.querySelector(flashTarget) : null;
      if (flash && event.detail && event.detail.xhr) {
        flash.innerHTML = event.detail.xhr.responseText;
      }
      resetLabel();
    });
  }

  function initFeedSyncButtons() {
    document.querySelectorAll("[data-feed-sync-now]").forEach(setupFeedSyncButton);
  }

  function scrollStateKey(container, scroller) {
    return container.id + ":" + (scroller.dataset.preserveScroll || "default");
  }

  function initScrollPreservation() {
    if (document.body.dataset.scrollPreservationReady === "true") {
      return;
    }

    document.body.dataset.scrollPreservationReady = "true";
    var scrollPositions = {};

    document.body.addEventListener("htmx:beforeSwap", function (event) {
      var target = event.detail && event.detail.target;
      if (!target || !target.id || !target.matches("[data-preserve-scroll-container]")) {
        return;
      }

      target.querySelectorAll("[data-preserve-scroll]").forEach(function (scroller) {
        scrollPositions[scrollStateKey(target, scroller)] = scroller.scrollLeft;
      });
    });

    document.body.addEventListener("htmx:afterSwap", function (event) {
      var target = event.detail && event.detail.target;
      if (!target || !target.id || !target.matches("[data-preserve-scroll-container]")) {
        return;
      }

      var restore = function () {
        target.querySelectorAll("[data-preserve-scroll]").forEach(function (scroller) {
          var key = scrollStateKey(target, scroller);
          if (Object.prototype.hasOwnProperty.call(scrollPositions, key)) {
            scroller.scrollLeft = scrollPositions[key];
          }
        });
      };

      if (window.requestAnimationFrame) {
        window.requestAnimationFrame(restore);
      } else {
        restore();
      }
    });
  }

  function setHTMXBusy(target, busy) {
    if (!target || !target.setAttribute || !target.hasAttribute("aria-busy")) {
      return;
    }
    target.setAttribute("aria-busy", busy ? "true" : "false");
  }

  function initHTMXBusyState() {
    if (document.body.dataset.htmxBusyReady === "true") {
      return;
    }

    document.body.dataset.htmxBusyReady = "true";
    document.body.addEventListener("htmx:beforeRequest", function (event) {
      setHTMXBusy(event.detail && event.detail.target, true);
    });
    document.body.addEventListener("htmx:afterRequest", function (event) {
      setHTMXBusy(event.detail && event.detail.target, false);
    });
    document.body.addEventListener("htmx:responseError", function (event) {
      setHTMXBusy(event.detail && event.detail.target, false);
    });
  }

  function initControls() {
    initAutoRefreshControls();
    initSubmitLocks();
    initSelectOnFocusInputs();
    initCopyButtons();
    initFeedSyncButtons();
    initScrollPreservation();
    initHTMXBusyState();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initControls);
  } else {
    initControls();
  }
})();
