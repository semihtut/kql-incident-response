/**
 * KQL Incident Response Playbooks - Custom JS
 * Implemented by Emre (Web Architect)
 */

document.addEventListener("DOMContentLoaded", function () {
  initGalleryFilters();
});

/* Runbook Gallery Filtering */
function initGalleryFilters() {
  const buttons = document.querySelectorAll(".filter-btn");
  const cards = document.querySelectorAll(".runbook-card");
  if (!buttons.length) return;

  buttons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var filter = btn.getAttribute("data-filter");
      var group = btn.getAttribute("data-group");

      /* Toggle active state within same group */
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
