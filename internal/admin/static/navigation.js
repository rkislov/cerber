// SPDX-License-Identifier: Apache-2.0
"use strict";
const adminNavigation = (() => {
  const app = document.getElementById("app");
  const sidebar = document.getElementById("app-sidebar");
  const main = document.getElementById("workspace-main");
  const toggle = document.getElementById("nav-toggle");
  const backdrop = document.getElementById("nav-backdrop");
  const compact = window.matchMedia("(max-width: 760px)");
  let opened = false;
  function setOpen(value, returnFocus = true) {
    const wasOpen = opened;
    opened = !!value && compact.matches && !app.classList.contains("hidden");
    app.classList.toggle("navigation-open", opened);
    document.body.classList.toggle("navigation-open", opened);
    toggle.setAttribute("aria-expanded", String(opened));
    toggle.setAttribute("aria-label", opened ? "Закрыть меню" : "Открыть меню");
    sidebar.inert = compact.matches && !opened;
    if (sidebar.inert) sidebar.setAttribute("aria-hidden", "true");
    else sidebar.removeAttribute("aria-hidden");
    main.inert = opened;
    if (wasOpen && !opened && returnFocus && compact.matches) toggle.focus({preventScroll:true});
  }
  toggle.addEventListener("click", () => setOpen(!opened));
  backdrop.addEventListener("click", () => setOpen(false));
  document.addEventListener("keydown", event => {
    if (!opened) return;
    if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
    } else if (event.key === "Tab") {
      const buttons = [toggle, ...sidebar.querySelectorAll("button:not(:disabled), a[href]")]
        .filter(node => node.getClientRects().length > 0);
      const index = buttons.indexOf(document.activeElement);
      if (index < 0 || (!event.shiftKey && index === buttons.length - 1) || (event.shiftKey && index === 0)) {
        event.preventDefault();
        (event.shiftKey ? buttons.at(-1) : buttons[0]).focus();
      }
    }
  });
  compact.addEventListener("change", () => {
    const active = document.activeElement;
    setOpen(false, false);
    if (app.classList.contains("hidden")) return;
    if (compact.matches && sidebar.contains(active)) toggle.focus({preventScroll:true});
    else if (!compact.matches && toggle.contains(active)) sidebar.querySelector(".nav-item.selected")?.focus({preventScroll:true});
  });
  setOpen(false, false);
  return { close: returnFocus => setOpen(false, returnFocus) };
})();
function closeAdminNavigation(returnFocus = true) { adminNavigation.close(returnFocus); }
