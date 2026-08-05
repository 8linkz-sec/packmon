(function () {
  var rtlScrollType = "";

  function detectRTLScrollType() {
    if (rtlScrollType) {
      return rtlScrollType;
    }
    if (!document.body || !document.createElement) {
      rtlScrollType = "default";
      return rtlScrollType;
    }

    var outer = document.createElement("div");
    var inner = document.createElement("div");
    outer.dir = "rtl";
    outer.style.cssText = "position:absolute;top:-1000px;width:4px;height:1px;overflow:scroll;visibility:hidden;";
    inner.style.cssText = "width:8px;height:1px;";
    outer.appendChild(inner);
    document.body.appendChild(outer);

    if (outer.scrollLeft > 0) {
      rtlScrollType = "default";
    } else {
      outer.scrollLeft = 1;
      rtlScrollType = outer.scrollLeft === 0 ? "negative" : "reverse";
    }
    document.body.removeChild(outer);
    return rtlScrollType;
  }

  function maxHorizontalScroll(scroller) {
    return Math.max(0, scroller.scrollWidth - scroller.clientWidth);
  }

  function clampScrollLeft(value, max) {
    return Math.min(Math.max(value || 0, 0), max);
  }

  function getLogicalScrollLeft(scroller) {
    var raw = scroller.scrollLeft || 0;
    if (!window.getComputedStyle || window.getComputedStyle(scroller).direction !== "rtl") {
      return raw;
    }

    var max = maxHorizontalScroll(scroller);
    switch (detectRTLScrollType()) {
    case "negative":
      return clampScrollLeft(-raw, max);
    case "reverse":
      return clampScrollLeft(raw, max);
    default:
      return clampScrollLeft(max - raw, max);
    }
  }

  function setLogicalScrollLeft(scroller, value) {
    if (!window.getComputedStyle || window.getComputedStyle(scroller).direction !== "rtl") {
      scroller.scrollLeft = value;
      return;
    }

    var max = maxHorizontalScroll(scroller);
    var logical = clampScrollLeft(value, max);
    switch (detectRTLScrollType()) {
    case "negative":
      scroller.scrollLeft = -logical;
      break;
    case "reverse":
      scroller.scrollLeft = logical;
      break;
    default:
      scroller.scrollLeft = max - logical;
      break;
    }
  }

  function scrollStateKey(container, scroller) {
    return container.id + ":" + (scroller.dataset.preserveScroll || "default");
  }

  function initScrollPreservation() {
    if (!document.body || document.body.dataset.scrollPreservationReady === "true") {
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
        scrollPositions[scrollStateKey(target, scroller)] = getLogicalScrollLeft(scroller);
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
            setLogicalScrollLeft(scroller, scrollPositions[key]);
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

  function setHTMXStatusMessage(target, message) {
    if (!target || !target.dataset || !target.dataset.htmxStatusTarget || typeof message !== "string") {
      return;
    }
    var status = document.querySelector(target.dataset.htmxStatusTarget);
    if (!status) {
      return;
    }
    status.textContent = message;
  }

  function clearHTMXErrorState(target) {
    if (!target || !target.querySelectorAll || !target.removeAttribute) {
      return;
    }
    target.querySelectorAll("[data-htmx-error-state]").forEach(function (panel) {
      panel.remove();
    });
    target.removeAttribute("data-htmx-error-visible");
  }

  function firstHTMXTriggerName(element) {
    if (!element || !element.getAttribute) {
      return "";
    }
    var trigger = element.getAttribute("hx-trigger") || "";
    var fallback = "";
    var preferred = "";
    trigger.split(",").some(function (triggerPart) {
      var match = triggerPart.match(/^\s*([^\s,]+)/);
      if (!match) {
        return false;
      }
      if (!fallback) {
        fallback = match[1];
      }
      if (triggerPart.indexOf("changed") === -1) {
        preferred = match[1];
        return true;
      }
      return false;
    });
    return preferred || fallback;
  }

  function triggerHTMXRetry(target, retrySource) {
    var source = retrySource || target;
    var triggerName = firstHTMXTriggerName(source) || firstHTMXTriggerName(target);
    if (triggerName) {
      var triggerConfig = (source && source.getAttribute && source.getAttribute("hx-trigger"))
        || (target && target.getAttribute && target.getAttribute("hx-trigger"))
        || "";
      var dispatchTarget = /\bfrom:body\b/.test(triggerConfig) ? document.body : source;
      if (dispatchTarget && dispatchTarget.dispatchEvent) {
        dispatchTarget.dispatchEvent(new Event(triggerName, { bubbles: true }));
        return;
      }
    }
    if (window.htmx && typeof window.htmx.trigger === "function" && source) {
      window.htmx.trigger(source, "click");
    }
  }

  function showHTMXErrorState(target, message, retrySource) {
    if (!target || !target.insertBefore || !target.querySelector) {
      return;
    }
    var panel = target.querySelector("[data-htmx-error-state]");
    if (!panel) {
      panel = document.createElement("div");
      panel.setAttribute("data-htmx-error-state", "true");
      panel.setAttribute("role", "alert");
      panel.setAttribute("aria-live", "assertive");
      panel.setAttribute("aria-atomic", "true");
      panel.className = "mb-3 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800";
      target.insertBefore(panel, target.firstChild);
    }
    target.setAttribute("data-htmx-error-visible", "true");
    panel.replaceChildren();

    var text = document.createElement("p");
    text.className = "font-medium";
    text.textContent = message;
    panel.appendChild(text);

    var staleMessage = target.dataset.htmxStaleMessage || "";
    if (staleMessage) {
      var hint = document.createElement("p");
      hint.className = "mt-1";
      hint.textContent = staleMessage;
      panel.appendChild(hint);
    }

    var retryLabel = target.dataset.htmxRetryLabel || "";
    if (retryLabel) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "mt-2 inline-flex min-h-11 items-center justify-center rounded-md border border-red-700 bg-white px-3 py-1.5 font-medium text-red-700";
      button.textContent = retryLabel;
      button.addEventListener("click", function () {
        triggerHTMXRetry(target, retrySource);
      });
      panel.appendChild(button);
    }
  }

  function handleHTMXError(event, messageName) {
    var target = event.detail && event.detail.target;
    var retrySource = (event.detail && event.detail.elt) || target;
    var message = "";
    if (target && target.dataset) {
      if (messageName === "htmxTimeoutMessage") {
        message = target.dataset.htmxTimeoutMessage || "";
      } else if (messageName === "htmxSwapErrorMessage") {
        message = target.dataset.htmxSwapErrorMessage || "";
      } else {
        message = target.dataset.htmxErrorMessage || "";
      }
    }
    setHTMXBusy(target, false);
    setHTMXStatusMessage(target, message);
    if (message) {
      showHTMXErrorState(target, message, retrySource);
    }
  }

  function initHTMXBusyState() {
    if (!document.body || document.body.dataset.htmxBusyReady === "true") {
      return;
    }

    document.body.dataset.htmxBusyReady = "true";
    document.body.addEventListener("htmx:beforeRequest", function (event) {
      var target = event.detail && event.detail.target;
      setHTMXBusy(target, true);
      setHTMXStatusMessage(target, target && target.dataset && target.dataset.htmxLoadingMessage);
    });
    document.body.addEventListener("htmx:afterRequest", function (event) {
      var target = event.detail && event.detail.target;
      setHTMXBusy(target, false);
      if (event.detail && event.detail.successful) {
        clearHTMXErrorState(target);
        setHTMXStatusMessage(target, target && target.dataset && target.dataset.htmxSuccessMessage);
      }
    });
    document.body.addEventListener("htmx:responseError", function (event) {
      handleHTMXError(event, "htmxErrorMessage");
    });
    document.body.addEventListener("htmx:sendError", function (event) {
      handleHTMXError(event, "htmxErrorMessage");
    });
    document.body.addEventListener("htmx:timeout", function (event) {
      handleHTMXError(event, "htmxTimeoutMessage");
    });
    document.body.addEventListener("htmx:timeoutError", function (event) {
      handleHTMXError(event, "htmxTimeoutMessage");
    });
    document.body.addEventListener("htmx:swapError", function (event) {
      handleHTMXError(event, "htmxSwapErrorMessage");
    });
  }

  function initHTMXRegions() {
    initScrollPreservation();
    initHTMXBusyState();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initHTMXRegions);
  } else {
    initHTMXRegions();
  }
})();
