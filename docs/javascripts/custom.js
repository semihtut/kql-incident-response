/**
 * KQL Incident Response Playbooks - Custom JS
 * Designed by Defne (UX/Content Designer)
 * Implemented by Emre (Web Architect)
 */

document.addEventListener("DOMContentLoaded", function () {
  initGalleryFilters();
  initCopyAnimation();
  enhanceKqlSyntax();
  initProgressBar();
  initVariableBanner();
});

/* ===== 1. Gallery Filtering (existing) ===== */

function initGalleryFilters() {
  var buttons = document.querySelectorAll(".filter-btn");
  var cards = document.querySelectorAll(".runbook-card");
  if (!buttons.length) return;

  buttons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var filter = btn.getAttribute("data-filter");
      var group = btn.getAttribute("data-group");

      document.querySelectorAll('.filter-btn[data-group="' + group + '"]').forEach(function (b) {
        b.classList.remove("active");
      });
      btn.classList.add("active");

      applyFilters();
    });
  });

  function applyFilters() {
    var activeSeverity = document.querySelector('.filter-btn[data-group="severity"].active');
    var activeTactic = document.querySelector('.filter-btn[data-group="tactic"].active');

    var sevFilter = activeSeverity ? activeSeverity.getAttribute("data-filter") : "all";
    var tacFilter = activeTactic ? activeTactic.getAttribute("data-filter") : "all";

    cards.forEach(function (card) {
      var matchSev = sevFilter === "all" || card.getAttribute("data-severity") === sevFilter;
      var matchTac = tacFilter === "all" || (card.getAttribute("data-tactics") || "").indexOf(tacFilter) !== -1;

      if (matchSev && matchTac) {
        card.style.display = "";
      } else {
        card.style.display = "none";
      }
    });
  }
}

/* ===== 2. Copy Button Animation ===== */

function initCopyAnimation() {
  document.addEventListener("click", function (e) {
    var btn = e.target.closest(".md-clipboard");
    if (!btn) return;
    var highlight = btn.closest(".highlight");
    if (!highlight) return;
    highlight.classList.add("kql-copied");
    setTimeout(function () {
      highlight.classList.remove("kql-copied");
    }, 800);
  });
}

/* ===== 3. KQL Syntax Enhancement ===== */

var KQL_FUNCTIONS = [
  "ago", "bin", "count", "countif", "dcount", "dcountif", "sum", "sumif",
  "avg", "avgif", "min", "max", "percentile", "percentiles", "stdev",
  "variance", "make_list", "make_set", "arg_max", "arg_min",
  "tostring", "toint", "tolong", "todouble", "todecimal", "tobool",
  "todatetime", "totimespan", "toreal", "toguid",
  "iff", "iif", "case", "coalesce",
  "isempty", "isnotempty", "isnull", "isnotnull",
  "strlen", "strcat", "strcat_delim", "substring", "indexof",
  "split", "parse_json", "todynamic", "extract", "extract_all",
  "replace_string", "trim", "trim_start", "trim_end",
  "tolower", "toupper", "has", "has_any", "has_all", "contains",
  "startswith", "endswith", "matches_regex",
  "format_datetime", "format_timespan", "datetime_diff",
  "now", "ingestion_time",
  "pack", "pack_all", "bag_keys", "bag_merge",
  "array_length", "array_sort_asc", "array_sort_desc",
  "geo_point_to_s2cell", "ipv4_is_private",
  "url_decode", "base64_decode_tostring",
  "dynamic", "print", "range", "datatable",
  "series_stats", "series_decompose", "series_outliers",
  "prev", "next", "row_number", "row_cumsum"
];

var KQL_TABLES = [
  "SigninLogs", "AADNonInteractiveUserSignInLogs", "AADUserRiskEvents",
  "AADRiskyUsers", "AuditLogs", "IdentityInfo", "OfficeActivity",
  "CloudAppEvents", "SecurityAlert", "ThreatIntelligenceIndicator",
  "BehaviorAnalytics", "DeviceEvents", "DeviceProcessEvents",
  "DeviceNetworkEvents", "DeviceFileEvents", "DeviceLogonEvents",
  "EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo",
  "AlertEvidence", "AlertInfo", "AzureActivity", "AzureDiagnostics",
  "CommonSecurityLog", "Syslog", "SecurityEvent",
  "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs",
  "AADProvisioningLogs", "IntuneDeviceComplianceOrg",
  "MicrosoftGraphActivityLogs", "NetworkAccessTraffic",
  "IdentityDirectoryEvents", "IdentityLogonEvents",
  "EmailPostDeliveryEvents", "UrlClickEvents",
  "AADRiskyServicePrincipals", "MicrosoftPurviewInformationProtection"
];

var KQL_OPERATORS = [
  "where", "summarize", "project", "extend", "join", "on", "by",
  "order", "sort", "take", "limit", "top", "union", "render",
  "evaluate", "parse", "lookup", "distinct", "getschema",
  "invoke", "search", "find", "externaldata", "materialize",
  "toscalar", "as", "asc", "desc", "and", "or", "not", "in",
  "between", "kind", "inner", "outer", "leftouter", "rightouter",
  "leftanti", "rightanti", "leftsemi", "rightsemi", "fullouter",
  "anti", "mv-expand", "mv-apply"
];

function enhanceKqlSyntax() {
  var funcSet = {};
  KQL_FUNCTIONS.forEach(function (f) { funcSet[f] = true; });
  var tableSet = {};
  KQL_TABLES.forEach(function (t) { tableSet[t] = true; });
  var opSet = {};
  KQL_OPERATORS.forEach(function (o) { opSet[o] = true; });

  var codeBlocks = document.querySelectorAll(
    "code.language-kql, code.language-kusto"
  );

  codeBlocks.forEach(function (block) {
    var spans = block.querySelectorAll("span.n, span.nb, span.ni, span.no");
    spans.forEach(function (span) {
      var text = span.textContent.trim();
      if (text === "let") {
        span.classList.add("kql-let");
      } else if (funcSet[text]) {
        span.classList.add("kql-func");
      } else if (tableSet[text]) {
        span.classList.add("kql-table");
      } else if (opSet[text]) {
        span.classList.add("kql-op");
      }
    });
  });
}

/* ===== 4. Runbook Progress Bar ===== */

function initProgressBar() {
  var progressBar = document.getElementById("kql-progress-bar");
  if (!progressBar) return;

  var fill = document.getElementById("kql-progress-fill");
  var phases = progressBar.querySelectorAll(".kql-progress-phase");
  var phaseOrder = ["triage", "investigation", "containment", "evidence"];

  var PHASE_MAP = {
    triage: [1, 2, 3, 4],
    investigation: [5],
    containment: [6],
    evidence: [7, 8, 9, 10, 11]
  };

  /* Collect all numbered H2 section elements */
  var sectionElements = {};
  document.querySelectorAll("h2").forEach(function (h2) {
    var match = h2.textContent.match(/^(\d+)\./);
    if (match) {
      sectionElements[parseInt(match[1])] = h2;
    }
  });

  /* Click handlers — navigate to phase */
  phases.forEach(function (phaseBtn) {
    phaseBtn.addEventListener("click", function () {
      var phaseName = phaseBtn.getAttribute("data-phase");
      var sections = PHASE_MAP[phaseName];
      if (sections && sectionElements[sections[0]]) {
        sectionElements[sections[0]].scrollIntoView({
          behavior: "smooth",
          block: "start"
        });
      }
    });
  });

  /* Scroll handler — update active phase */
  function updateProgress() {
    var scrollPos = window.scrollY + 200;
    var activePhaseIdx = 0;

    for (var i = phaseOrder.length - 1; i >= 0; i--) {
      var sections = PHASE_MAP[phaseOrder[i]];
      var firstSection = sectionElements[sections[0]];
      if (firstSection && firstSection.getBoundingClientRect().top + window.scrollY <= scrollPos) {
        activePhaseIdx = i;
        break;
      }
    }

    phases.forEach(function (btn, idx) {
      btn.classList.remove("active", "completed");
      if (idx < activePhaseIdx) {
        btn.classList.add("completed");
      } else if (idx === activePhaseIdx) {
        btn.classList.add("active");
      }
    });

    var fillPercent = (activePhaseIdx / (phaseOrder.length - 1)) * 100;
    fill.style.width = fillPercent + "%";
  }

  var ticking = false;
  window.addEventListener("scroll", function () {
    if (!ticking) {
      window.requestAnimationFrame(function () {
        updateProgress();
        ticking = false;
      });
      ticking = true;
    }
  });

  updateProgress();
}

/* ===== 5. Dynamic Variable Injection Banner ===== */

function initVariableBanner() {
  /* Only run on runbook pages that have KQL code blocks */
  var kqlBlocks = document.querySelectorAll("code.language-kql, code.language-kusto");
  if (!kqlBlocks.length) return;

  /* Find the "Input Parameters" section */
  var paramBlock = findParameterBlock();
  if (!paramBlock) return;

  /* Extract variables from the parameter block */
  var variables = extractParameterVariables(paramBlock);
  if (!variables.length) return;

  /* Store original textContent for every code block (for reset) */
  kqlBlocks.forEach(function (block) {
    block.setAttribute("data-original-text", block.textContent);
    block.setAttribute("data-original-html", block.innerHTML);
  });

  /* Build and inject the banner */
  var banner = buildBannerDOM(variables);

  /* Insert after the first H1, or at the start of the content */
  var h1 = document.querySelector(".md-content h1");
  if (h1) {
    h1.parentNode.insertBefore(banner, h1.nextSibling);
  }

  /* Wire up events */
  initBannerEvents(banner, variables, kqlBlocks);
}

function findParameterBlock() {
  var headings = document.querySelectorAll("h2");
  var paramHeading = null;
  for (var i = 0; i < headings.length; i++) {
    if (/3\.\s*Input Parameters/.test(headings[i].textContent)) {
      paramHeading = headings[i];
      break;
    }
  }
  if (!paramHeading) return null;

  var el = paramHeading.nextElementSibling;
  while (el) {
    if (el.tagName === "H2") return null;
    var code = el.querySelector ? el.querySelector("code.language-kql, code.language-kusto") : null;
    if (code) return code;
    if (el.classList && el.classList.contains("highlight")) {
      code = el.querySelector("code");
      if (code) return code;
    }
    el = el.nextElementSibling;
  }
  return null;
}

function extractParameterVariables(paramBlock) {
  var text = paramBlock.textContent;
  var lines = text.split("\n");
  var variables = [];
  var seen = {};

  lines.forEach(function (line) {
    var match = line.match(/^let\s+([A-Z]\w+)\s*=\s*(.+);/);
    if (!match) return;

    var name = match[1];
    var rawValue = match[2].trim();

    /* Skip if we already have this variable */
    if (seen[name]) return;
    seen[name] = true;

    /* Determine type from value */
    var type = "raw";
    var displayValue = rawValue;

    if (/^".*"$/.test(rawValue)) {
      type = "string";
      displayValue = rawValue.slice(1, -1); /* Remove quotes for display */
    } else if (/^datetime\(/.test(rawValue)) {
      type = "datetime";
      displayValue = rawValue; /* Keep full datetime() wrapper */
    } else if (/^\d+[hdms]$/.test(rawValue)) {
      type = "timespan";
      displayValue = rawValue;
    } else if (/^\d+$/.test(rawValue)) {
      type = "int";
      displayValue = rawValue;
    }

    variables.push({
      name: name,
      rawValue: rawValue,
      displayValue: displayValue,
      type: type
    });
  });

  return variables;
}

function buildBannerDOM(variables) {
  var banner = document.createElement("div");
  banner.className = "kql-var-banner";
  banner.id = "kql-var-banner";

  /* Header */
  var header = document.createElement("div");
  header.className = "kql-var-banner-header";
  header.innerHTML =
    '<span class="kql-var-banner-title">' +
    '<svg class="kql-var-banner-icon" viewBox="0 0 24 24" width="16" height="16" fill="currentColor">' +
    '<path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.49.49 0 00-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1115.6 12 3.611 3.611 0 0112 15.6z"/>' +
    '</svg>' +
    'Investigation Parameters' +
    '</span>' +
    '<button class="kql-var-banner-toggle" aria-label="Toggle parameter banner">' +
    '<svg class="kql-var-banner-chevron" viewBox="0 0 24 24" width="14" height="14" fill="currentColor">' +
    '<path d="M7.41 15.41L12 10.83l4.59 4.58L18 14l-6-6-6 6z"/>' +
    '</svg>' +
    '</button>';
  banner.appendChild(header);

  /* Body */
  var body = document.createElement("div");
  body.className = "kql-var-banner-body";

  variables.forEach(function (v) {
    var field = document.createElement("div");
    field.className = "kql-var-field";
    field.innerHTML =
      '<label class="kql-var-label" for="kql-var-' + v.name + '">' + v.name + '</label>' +
      '<input class="kql-var-input" type="text" id="kql-var-' + v.name + '" ' +
      'value="' + escapeAttr(v.displayValue) + '" ' +
      'data-var="' + v.name + '" ' +
      'data-type="' + v.type + '" ' +
      'data-default="' + escapeAttr(v.displayValue) + '">';
    body.appendChild(field);
  });

  /* Action buttons */
  var actions = document.createElement("div");
  actions.className = "kql-var-actions";
  actions.innerHTML =
    '<button class="kql-var-apply" id="kql-var-apply">Apply to All Queries</button>' +
    '<button class="kql-var-reset" id="kql-var-reset">Reset Defaults</button>';
  body.appendChild(actions);

  banner.appendChild(body);
  return banner;
}

function initBannerEvents(banner, variables, kqlBlocks) {
  /* Collapse/expand toggle */
  var header = banner.querySelector(".kql-var-banner-header");
  header.addEventListener("click", function () {
    banner.classList.toggle("collapsed");
  });

  /* Track modified inputs */
  var inputs = banner.querySelectorAll(".kql-var-input");
  inputs.forEach(function (input) {
    input.addEventListener("input", function () {
      if (input.value !== input.getAttribute("data-default")) {
        input.classList.add("modified");
      } else {
        input.classList.remove("modified");
      }
    });
  });

  /* Apply button */
  var applyBtn = document.getElementById("kql-var-apply");
  applyBtn.addEventListener("click", function () {
    applyVariableChanges(variables, kqlBlocks, banner);
  });

  /* Reset button */
  var resetBtn = document.getElementById("kql-var-reset");
  resetBtn.addEventListener("click", function () {
    resetVariables(variables, kqlBlocks, banner);
  });
}

function applyVariableChanges(variables, kqlBlocks, banner) {
  kqlBlocks.forEach(function (block) {
    /* Start from the original text to avoid cascading replacements */
    var text = block.getAttribute("data-original-text");
    var changed = false;

    variables.forEach(function (v) {
      var input = document.getElementById("kql-var-" + v.name);
      if (!input) return;

      var newDisplayValue = input.value;
      var newRawValue;

      /* Reconstruct the full raw value based on type */
      if (v.type === "string") {
        newRawValue = '"' + newDisplayValue + '"';
      } else {
        newRawValue = newDisplayValue;
      }

      if (newRawValue === v.rawValue) return;

      /* Build regex to find let VarName = oldValue; */
      var pattern = new RegExp(
        "(let\\s+" + escapeRegex(v.name) + "\\s*=\\s*)" +
        escapeRegex(v.rawValue) +
        "(\\s*;)",
        "g"
      );

      var newText = text.replace(pattern, "$1" + newRawValue + "$2");
      if (newText !== text) {
        text = newText;
        changed = true;
      }
    });

    if (changed) {
      /* Replace the block content and re-apply syntax highlighting */
      block.textContent = text;
      reHighlightBlock(block);
    }
  });

  /* Flash the apply button to confirm */
  var applyBtn = document.getElementById("kql-var-apply");
  applyBtn.textContent = "Applied!";
  applyBtn.classList.add("applied");
  setTimeout(function () {
    applyBtn.textContent = "Apply to All Queries";
    applyBtn.classList.remove("applied");
  }, 1500);
}

function resetVariables(variables, kqlBlocks, banner) {
  /* Restore inputs to defaults */
  variables.forEach(function (v) {
    var input = document.getElementById("kql-var-" + v.name);
    if (input) {
      input.value = v.displayValue;
      input.classList.remove("modified");
    }
  });

  /* Restore all code blocks to original HTML */
  kqlBlocks.forEach(function (block) {
    var originalHtml = block.getAttribute("data-original-html");
    if (originalHtml) {
      block.innerHTML = originalHtml;
    }
  });
}

/**
 * Re-applies KQL syntax highlighting after text replacement.
 * Uses a lightweight client-side tokenizer that produces Pygments-compatible spans.
 */
function reHighlightBlock(codeElement) {
  var text = codeElement.textContent;
  var html = highlightKql(text);
  codeElement.innerHTML = html;
}

function highlightKql(text) {
  var lines = text.split("\n");
  var result = [];

  var funcSet = {};
  KQL_FUNCTIONS.forEach(function (f) { funcSet[f] = true; });
  var tableSet = {};
  KQL_TABLES.forEach(function (t) { tableSet[t] = true; });
  var opSet = {};
  KQL_OPERATORS.forEach(function (o) { opSet[o] = true; });

  lines.forEach(function (line, lineIdx) {
    if (lineIdx > 0) result.push("\n");

    /* Check for full-line comments first */
    var trimmed = line.trimStart();
    if (trimmed.startsWith("//")) {
      var leadingSpace = line.substring(0, line.length - trimmed.length);
      result.push(esc(leadingSpace) + '<span class="c1">' + esc(trimmed) + '</span>');
      return;
    }

    /* Tokenize the line character by character */
    var i = 0;
    while (i < line.length) {
      /* Inline comment */
      if (line[i] === "/" && line[i + 1] === "/") {
        result.push('<span class="c1">' + esc(line.substring(i)) + '</span>');
        i = line.length;
        continue;
      }

      /* String literal */
      if (line[i] === '"') {
        var end = line.indexOf('"', i + 1);
        if (end === -1) end = line.length - 1;
        var str = line.substring(i, end + 1);
        result.push('<span class="s">' + esc(str) + '</span>');
        i = end + 1;
        continue;
      }

      /* Single-quoted string */
      if (line[i] === "'") {
        var end2 = line.indexOf("'", i + 1);
        if (end2 === -1) end2 = line.length - 1;
        var str2 = line.substring(i, end2 + 1);
        result.push('<span class="s">' + esc(str2) + '</span>');
        i = end2 + 1;
        continue;
      }

      /* Word token (identifier or keyword) */
      if (/[a-zA-Z_]/.test(line[i])) {
        var wordStart = i;
        while (i < line.length && /[a-zA-Z0-9_\-]/.test(line[i])) i++;
        var word = line.substring(wordStart, i);

        if (word === "let") {
          result.push('<span class="n kql-let">' + esc(word) + '</span>');
        } else if (opSet[word]) {
          result.push('<span class="n kql-op">' + esc(word) + '</span>');
        } else if (funcSet[word]) {
          result.push('<span class="n kql-func">' + esc(word) + '</span>');
        } else if (tableSet[word]) {
          result.push('<span class="n kql-table">' + esc(word) + '</span>');
        } else {
          result.push('<span class="n">' + esc(word) + '</span>');
        }
        continue;
      }

      /* Number */
      if (/[0-9]/.test(line[i])) {
        var numStart = i;
        while (i < line.length && /[0-9.]/.test(line[i])) i++;
        /* Time suffix (h, d, m, s) */
        if (i < line.length && /[hdms]/.test(line[i])) i++;
        result.push('<span class="mi">' + esc(line.substring(numStart, i)) + '</span>');
        continue;
      }

      /* Whitespace */
      if (/\s/.test(line[i])) {
        var wsStart = i;
        while (i < line.length && /\s/.test(line[i])) i++;
        result.push(esc(line.substring(wsStart, i)));
        continue;
      }

      /* Operators and punctuation */
      result.push('<span class="p">' + esc(line[i]) + '</span>');
      i++;
    }
  });

  return result.join("");
}

/* ===== Utility Functions ===== */

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeAttr(str) {
  return str.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function esc(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
