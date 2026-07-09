(function () {
  function initDismissibleAlerts() {
    if (!document.body || document.body.dataset.alertDismissReady === "true") {
      return;
    }

    document.body.dataset.alertDismissReady = "true";
    document.body.addEventListener("click", function (event) {
      var target = event.target;
      if (!target || typeof target.closest !== "function") {
        return;
      }

      var button = target.closest("[data-alert-dismiss]");
      if (!button) {
        return;
      }

      var alert = button.closest("[data-alert-dismissible]");
      if (!alert) {
        return;
      }
      alert.hidden = true;
    });
  }

  function setupConditionalRequiredCheckbox(checkbox) {
    if (checkbox.dataset.requiredWhenReady === "true") {
      return;
    }

    var triggerName = checkbox.dataset.requiredWhenChecked;
    var form = checkbox.form;
    var trigger = form && triggerName ? form.elements[triggerName] : null;
    if (!trigger) {
      return;
    }

    checkbox.dataset.requiredWhenReady = "true";
    function syncRequired() {
      checkbox.required = trigger.checked;
      if (!trigger.checked) {
        checkbox.checked = false;
        checkbox.removeAttribute("required");
        checkbox.setCustomValidity("");
        return;
      }
      checkbox.setCustomValidity(checkbox.checked ? "" : checkbox.dataset.requiredMessage || "Confirm this action before saving.");
    }
    checkbox.addEventListener("change", function () {
      if (trigger.checked) {
        checkbox.setCustomValidity(checkbox.checked ? "" : checkbox.dataset.requiredMessage || "Confirm this action before saving.");
      }
    });
    trigger.addEventListener("change", syncRequired);
    syncRequired();
  }

  function initConditionalRequiredCheckboxes() {
    document.querySelectorAll("[data-required-when-checked]").forEach(setupConditionalRequiredCheckbox);
  }

  function setupSelectRequiredCheckbox(checkbox) {
    if (checkbox.dataset.requiredWhenSelectReady === "true") {
      return;
    }

    var selector = checkbox.dataset.requiredWhenSelect;
    var requiredValue = checkbox.dataset.requiredValue || "";
    var select = selector ? document.querySelector(selector) : null;
    if (!select) {
      return;
    }

    checkbox.dataset.requiredWhenSelectReady = "true";
    var message = checkbox.dataset.requiredMessage || "Confirm this setting before saving.";

    function syncRequired() {
      var required = select.value === requiredValue;
      checkbox.required = required;
      checkbox.setAttribute("aria-required", required ? "true" : "false");
      if (!required) {
        checkbox.checked = false;
        checkbox.removeAttribute("required");
        checkbox.setCustomValidity("");
        return;
      }
      checkbox.setCustomValidity(checkbox.checked ? "" : message);
    }

    checkbox.addEventListener("change", syncRequired);
    select.addEventListener("change", syncRequired);
    syncRequired();
  }

  function initSelectRequiredCheckboxes() {
    document.querySelectorAll("[data-required-when-select]").forEach(setupSelectRequiredCheckbox);
  }

  function setupPasswordConfirmation(form) {
    if (form.dataset.passwordConfirmReady === "true") {
      return;
    }

    var source = form.querySelector("[data-password-confirm-source]");
    var target = form.querySelector("[data-password-confirm-target]");
    if (!source || !target) {
      return;
    }

    form.dataset.passwordConfirmReady = "true";
    var message = target.dataset.passwordMismatchMessage || "New passwords do not match.";

    function syncPasswordConfirmation(showMismatch) {
      target.setCustomValidity(source.value && target.value && source.value !== target.value ? message : "");
      if (showMismatch && target.validationMessage) {
        target.reportValidity();
      }
    }

    source.addEventListener("input", function () {
      syncPasswordConfirmation(false);
    });
    source.addEventListener("change", function () {
      syncPasswordConfirmation(false);
    });
    target.addEventListener("input", function () {
      syncPasswordConfirmation(true);
    });
    target.addEventListener("change", function () {
      syncPasswordConfirmation(true);
    });
    form.addEventListener("submit", function (event) {
      syncPasswordConfirmation(true);
      if (!target.checkValidity()) {
        event.preventDefault();
      }
    });
    syncPasswordConfirmation(false);
  }

  function initPasswordConfirmations() {
    document.querySelectorAll("[data-password-confirm-form]").forEach(setupPasswordConfirmation);
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

  var unsavedChangesMessage = "You have unsaved changes. Leave this page?";

  function unsavedGuardFieldValue(field) {
    if (field.type === "checkbox" || field.type === "radio") {
      return field.checked ? "checked" : "unchecked";
    }
    if (field.tagName === "SELECT" && field.multiple) {
      return Array.from(field.options).filter(function (option) {
        return option.selected;
      }).map(function (option) {
        return option.value;
      }).join("\n");
    }
    return field.value || "";
  }

  function unsavedGuardSnapshot(form) {
    return JSON.stringify(Array.from(form.querySelectorAll("input, select, textarea")).map(function (field) {
      return [
        field.tagName,
        field.type || "",
        field.name || "",
        unsavedGuardFieldValue(field),
      ];
    }));
  }

  function setUnsavedGuardDirty(form, dirty) {
    form.dataset.unsavedDirty = dirty ? "true" : "false";
  }

  function clearUnsavedGuard(form) {
    form.dataset.unsavedGuardInitial = unsavedGuardSnapshot(form);
    setUnsavedGuardDirty(form, false);
  }

  function setupUnsavedGuard(form) {
    if (form.dataset.unsavedGuardReady === "true") {
      return;
    }

    form.dataset.unsavedGuardReady = "true";
    clearUnsavedGuard(form);

    function syncDirty() {
      setUnsavedGuardDirty(form, unsavedGuardSnapshot(form) !== form.dataset.unsavedGuardInitial);
    }

    form.addEventListener("input", syncDirty);
    form.addEventListener("change", syncDirty);
    form.addEventListener("submit", function () {
      clearUnsavedGuard(form);
    });
  }

  function hasDirtyUnsavedGuard() {
    return Boolean(document.querySelector('[data-unsaved-guard][data-unsaved-dirty="true"]'));
  }

  function isLocalNavigationLink(link) {
    if (!link || link.target || link.hasAttribute("download")) {
      return false;
    }
    try {
      var url = new URL(link.href, window.location.href);
      if (url.origin !== window.location.origin) {
        return false;
      }
      return !(url.pathname === window.location.pathname && url.search === window.location.search && url.hash);
    } catch {
      return false;
    }
  }

  function initUnsavedGuards() {
    document.querySelectorAll("[data-unsaved-guard]").forEach(setupUnsavedGuard);

    if (!document.body || document.body.dataset.unsavedGuardGlobalReady === "true") {
      return;
    }
    document.body.dataset.unsavedGuardGlobalReady = "true";

    window.addEventListener("beforeunload", function (event) {
      if (!hasDirtyUnsavedGuard()) {
        return;
      }
      event.preventDefault();
      event.returnValue = "";
      return "";
    });

    document.body.addEventListener("click", function (event) {
      var target = event.target;
      if (!target || typeof target.closest !== "function") {
        return;
      }

      var link = target.closest("a[href]");
      if (!link || !isLocalNavigationLink(link) || !hasDirtyUnsavedGuard()) {
        return;
      }
      if (!window.confirm(unsavedChangesMessage)) {
        event.preventDefault();
      }
    });
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

  function selectCopyTargetForManualCopy(target) {
    if (typeof target.focus === "function") {
      try {
        target.focus({ preventScroll: true });
      } catch {
        target.focus();
      }
    }
    if (typeof target.select === "function") {
      target.select();
    }
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
      var status = copyStatusElement(button);
      if (!target) {
        setCopyStatus(status, "Copy target is unavailable.");
        return;
      }

      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        setCopyStatus(status, "Copying API key.");
        try {
          var clipboardWrite = navigator.clipboard.writeText(target.value || "");
          void Promise.resolve(clipboardWrite).then(function () {
            setCopyStatus(status, "API key copied to clipboard.");
          }).catch(function () {
            handleCopyFailure(status, target);
          });
        } catch {
          handleCopyFailure(status, target);
        }
      } else {
        handleCopyFailure(status, target, "Clipboard unavailable. API key selected for manual copying.");
      }
    });
  }

  function copyStatusElement(button) {
    var selector = button.dataset.copyStatus;
    if (!selector) {
      return null;
    }
    return document.querySelector(selector);
  }

  function handleCopyFailure(status, target) {
    var message = arguments[2];
    selectCopyTargetForManualCopy(target);
    if (message) {
      setCopyStatus(status, message);
      return;
    }
    setCopyStatus(status, "Copy failed. API key selected for manual copying.");
  }

  function setCopyStatus(status, message) {
    if (status) {
      status.textContent = message;
    }
  }

  function initCopyButtons() {
    document.querySelectorAll("[data-copy-target]").forEach(setupCopyButton);
  }

  function setupFeedSyncButton(button) {
    if (button.dataset.feedSyncReady === "true") {
      return;
    }

    button.dataset.feedSyncReady = "true";
    var defaultLabel = button.dataset.feedSyncLabel || button.textContent || "";
    var busyLabel = button.dataset.feedSyncBusyLabel || defaultLabel;
    var runningLabel = button.dataset.feedSyncRunningLabel || busyLabel || defaultLabel;
    var flashTarget = button.dataset.feedSyncFlashTarget || "";

    function resetLabel() {
      button.dataset.feedSyncState = "idle";
      button.textContent = button.dataset.originalText || defaultLabel;
      button.removeAttribute("aria-disabled");
    }

    function markRunning() {
      button.dataset.feedSyncState = "running";
      button.textContent = runningLabel;
      button.disabled = true;
      button.setAttribute("aria-disabled", "true");
    }

    button.addEventListener("htmx:beforeRequest", function () {
      button.dataset.originalText = button.textContent || defaultLabel;
      button.dataset.feedSyncState = "queued";
      button.textContent = busyLabel;
    });
    button.addEventListener("htmx:afterRequest", function (event) {
      if (event.detail && event.detail.successful) {
        markRunning();
        return;
      }
      resetLabel();
    });
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

  function initFormActions() {
    initDismissibleAlerts();
    initConditionalRequiredCheckboxes();
    initSelectRequiredCheckboxes();
    initPasswordConfirmations();
    initSubmitLocks();
    initUnsavedGuards();
    initSelectOnFocusInputs();
    initCopyButtons();
    initFeedSyncButtons();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initFormActions);
  } else {
    initFormActions();
  }
})();
