(function () {
  function splitClassList(value) {
    return (value || "").split(/\s+/).filter(Boolean);
  }

  function setClassList(element, classes, enabled) {
    if (!element || !classes.length) {
      return;
    }
    classes.forEach(function (className) {
      element.classList.toggle(className, enabled);
    });
  }

  function readStoredAutoRefreshPaused(storageKey) {
    if (!storageKey) {
      return false;
    }
    try {
      return window.localStorage.getItem(storageKey) === "true";
    } catch {
      return false;
    }
  }

  function writeStoredAutoRefreshPaused(storageKey, paused) {
    if (!storageKey) {
      return;
    }
    try {
      window.localStorage.setItem(storageKey, paused ? "true" : "false");
    } catch {
      return;
    }
  }

  function autoRefreshControlledTarget(toggle) {
    if (!toggle || typeof toggle.getAttribute !== "function") {
      return null;
    }
    var controls = toggle.getAttribute("aria-controls");
    if (!controls) {
      return null;
    }
    return document.getElementById(controls);
  }

  function autoRefreshTargetHasFocus(target) {
    return Boolean(target && document.activeElement && target.contains(document.activeElement));
  }

  function autoRefreshTargetHasOpenDetails(target) {
    return Boolean(target && target.querySelector("details[open]"));
  }

  function autoRefreshTargetIsBusy(target) {
    return Boolean(target && target.getAttribute && target.getAttribute("aria-busy") === "true");
  }

  function setupAutoRefresh(control) {
    if (control.dataset.autoRefreshReady === "true") {
      return;
    }

    var eventName = control.dataset.autoRefreshEvent;
    var intervalMs = Number.parseInt(control.dataset.autoRefreshIntervalMs || "", 10);
    var toggle = control.querySelector("[data-auto-refresh-toggle]");
    var refreshNow = control.querySelector("[data-auto-refresh-now]");
    var status = control.querySelector("[data-auto-refresh-status]");
    if (!eventName || !Number.isFinite(intervalMs) || intervalMs <= 0 || !toggle) {
      return;
    }

    control.dataset.autoRefreshReady = "true";
    var storageKey = control.dataset.autoRefreshStorageKey || "";
    var paused = readStoredAutoRefreshPaused(storageKey);
    var autoRefreshIntervalID = null;
    var toggleLabel = control.dataset.autoRefreshLabel || toggle.textContent || "";
    var runningLabel = control.dataset.autoRefreshRunningLabel || (status && status.textContent) || "";
    var pausedLabel = control.dataset.autoRefreshPausedLabel || "";
    var runningClasses = splitClassList(control.dataset.autoRefreshRunningClass);
    var pausedClasses = splitClassList(control.dataset.autoRefreshPausedClass);
    var controlledTarget = autoRefreshControlledTarget(toggle);

    function renderState() {
      toggle.setAttribute("aria-pressed", paused ? "false" : "true");
      toggle.textContent = toggleLabel;
      setClassList(toggle, runningClasses, !paused);
      setClassList(toggle, pausedClasses, paused);
      if (status) {
        status.textContent = paused ? pausedLabel : runningLabel;
      }
    }

    function isDocumentHidden() {
      return document.hidden || document.visibilityState === "hidden";
    }

    function canDispatchAutoRefresh() {
      return !autoRefreshTargetIsBusy(controlledTarget)
        && !autoRefreshTargetHasFocus(controlledTarget)
        && !autoRefreshTargetHasOpenDetails(controlledTarget);
    }

    function dispatchAutoRefresh() {
      if (!isAutoRefreshActive() || !canDispatchAutoRefresh()) {
        return;
      }
      document.body.dispatchEvent(new Event(eventName, { bubbles: true }));
    }

    function dispatchManualAutoRefresh() {
      if (!isAutoRefreshActive()) {
        return;
      }
      document.body.dispatchEvent(new Event(eventName, { bubbles: true }));
    }

    function isAutoRefreshActive() {
      return !paused && !isDocumentHidden();
    }

    function startAutoRefreshTimer() {
      if (autoRefreshIntervalID !== null || !isAutoRefreshActive()) {
        return;
      }
      autoRefreshIntervalID = window.setInterval(dispatchAutoRefresh, intervalMs);
    }

    function stopAutoRefreshTimer() {
      if (autoRefreshIntervalID === null) {
        return;
      }
      window.clearInterval(autoRefreshIntervalID);
      autoRefreshIntervalID = null;
    }

    function syncAutoRefreshTimer() {
      if (isAutoRefreshActive()) {
        startAutoRefreshTimer();
        return;
      }
      stopAutoRefreshTimer();
    }

    toggle.addEventListener("click", function () {
      paused = !paused;
      writeStoredAutoRefreshPaused(storageKey, paused);
      renderState();
      syncAutoRefreshTimer();
    });
    if (refreshNow) {
      refreshNow.addEventListener("click", dispatchManualAutoRefresh);
    }

    document.addEventListener("visibilitychange", syncAutoRefreshTimer);

    renderState();
    syncAutoRefreshTimer();
  }

  function initAutoRefreshControls() {
    document.querySelectorAll("[data-auto-refresh-control]").forEach(setupAutoRefresh);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAutoRefreshControls);
  } else {
    initAutoRefreshControls();
  }
})();
