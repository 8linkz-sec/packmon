(function () {
  var absoluteFormatter = null;
  var relativeFormatter = null;
  var numberFormatter = null;
  var percentFormatter = null;

  function absoluteFormatterForLocale() {
    if (absoluteFormatter !== null) {
      return absoluteFormatter;
    }
    if (typeof Intl === "undefined" || !Intl.DateTimeFormat) {
      absoluteFormatter = false;
      return null;
    }
    try {
      absoluteFormatter = new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      });
    } catch {
      absoluteFormatter = false;
    }
    return absoluteFormatter || null;
  }

  function relativeFormatterForLocale() {
    if (relativeFormatter !== null) {
      return relativeFormatter;
    }
    if (typeof Intl === "undefined" || !Intl.RelativeTimeFormat) {
      relativeFormatter = false;
      return null;
    }
    try {
      relativeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
    } catch {
      relativeFormatter = false;
    }
    return relativeFormatter || null;
  }

  function numberFormatterForLocale() {
    if (numberFormatter !== null) {
      return numberFormatter;
    }
    if (typeof Intl === "undefined" || !Intl.NumberFormat) {
      numberFormatter = false;
      return null;
    }
    try {
      numberFormatter = new Intl.NumberFormat(undefined);
    } catch {
      numberFormatter = false;
    }
    return numberFormatter || null;
  }

  function percentFormatterForLocale() {
    if (percentFormatter !== null) {
      return percentFormatter;
    }
    if (typeof Intl === "undefined" || !Intl.NumberFormat) {
      percentFormatter = false;
      return null;
    }
    try {
      percentFormatter = new Intl.NumberFormat(undefined, {
        maximumFractionDigits: 1,
        style: "percent",
      });
    } catch {
      percentFormatter = false;
    }
    return percentFormatter || null;
  }

  function parseDate(element) {
    var raw = element.getAttribute("datetime") || "";
    var time = Date.parse(raw);
    if (!Number.isFinite(time)) {
      return null;
    }
    return new Date(time);
  }

  function absoluteLabelFor(date) {
    var formatter = absoluteFormatterForLocale();
    if (formatter) {
      return formatter.format(date);
    }
    if (typeof date.toLocaleString === "function") {
      return date.toLocaleString();
    }
    return date.toISOString();
  }

  function relativePartsFor(date, now) {
    var seconds = Math.round((date.getTime() - now.getTime()) / 1000);
    var absoluteSeconds = Math.abs(seconds);
    if (absoluteSeconds < 60) {
      return { value: 0, unit: "second" };
    }
    if (absoluteSeconds < 60 * 60) {
      return { value: Math.round(seconds / 60), unit: "minute" };
    }
    if (absoluteSeconds < 24 * 60 * 60) {
      return { value: Math.round(seconds / (60 * 60)), unit: "hour" };
    }
    return { value: Math.round(seconds / (24 * 60 * 60)), unit: "day" };
  }

  function relativeLabelFor(date) {
    var formatter = relativeFormatterForLocale();
    if (!formatter) {
      return "";
    }
    var parts = relativePartsFor(date, new Date());
    return formatter.format(parts.value, parts.unit);
  }

  function numberLabelFor(value) {
    var formatter = numberFormatterForLocale();
    if (formatter) {
      return formatter.format(value);
    }
    return String(value);
  }

  function percentLabelFor(value) {
    var formatter = percentFormatterForLocale();
    if (formatter) {
      return formatter.format(value / 100);
    }
    return String(value) + "%";
  }

  function durationLabelFor(milliseconds) {
    if (milliseconds < 1000) {
      return numberLabelFor(milliseconds) + " ms";
    }
    if (milliseconds < 60 * 1000) {
      return numberLabelFor(Math.round(milliseconds / 100) / 10) + " s";
    }
    if (milliseconds < 60 * 60 * 1000) {
      return numberLabelFor(Math.round(milliseconds / (60 * 100)) / 10) + " min";
    }
    return numberLabelFor(Math.round(milliseconds / (60 * 60 * 100)) / 10) + " h";
  }

  function localizeTimeElement(element) {
    var date = parseDate(element);
    if (!date) {
      return;
    }
    var absoluteLabel = absoluteLabelFor(date);
    element.setAttribute("aria-label", absoluteLabel);
    element.setAttribute("title", absoluteLabel);

    if (element.dataset.localTime === "absolute") {
      element.textContent = absoluteLabel;
      return;
    }
    if (element.dataset.localTime === "relative") {
      var relativeLabel = relativeLabelFor(date);
      if (relativeLabel) {
        element.textContent = relativeLabel;
      }
    }
  }

  function initLocaleFormatting() {
    document.querySelectorAll("time[datetime][data-local-time]").forEach(localizeTimeElement);
    document.querySelectorAll("[data-local-number]").forEach(function (element) {
      var value = Number.parseFloat(element.dataset.localNumber || "");
      if (Number.isFinite(value)) {
        element.textContent = numberLabelFor(value);
      }
    });
    document.querySelectorAll("[data-local-percent]").forEach(function (element) {
      var value = Number.parseFloat(element.dataset.localPercent || "");
      if (!Number.isFinite(value)) {
        return;
      }
      var label = percentLabelFor(value);
      element.textContent = label;
      if (element.dataset.localPercentLabel) {
        element.setAttribute("aria-label", element.dataset.localPercentLabel.replace("%s", label));
      }
    });
    document.querySelectorAll("[data-local-duration-ms]").forEach(function (element) {
      var value = Number.parseFloat(element.dataset.localDurationMs || "");
      if (Number.isFinite(value)) {
        element.textContent = durationLabelFor(value);
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initLocaleFormatting);
  } else {
    initLocaleFormatting();
  }
})();
