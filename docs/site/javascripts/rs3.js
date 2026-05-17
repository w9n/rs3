(() => {
  let overlay;
  let image;
  let title;
  let closeButton;
  let lastFocus;
  let inertElements = [];

  const focusableSelector = [
    "a[href]",
    "button:not([disabled])",
    "input:not([disabled])",
    "select:not([disabled])",
    "textarea:not([disabled])",
    "[tabindex]:not([tabindex='-1'])",
  ].join(",");

  function ensureOverlay() {
    if (overlay) {
      return;
    }

    overlay = document.createElement("div");
    overlay.className = "rv-lightbox-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.hidden = true;

    const frame = document.createElement("div");
    frame.className = "rv-lightbox-frame";

    closeButton = document.createElement("button");
    closeButton.className = "rv-lightbox-close";
    closeButton.type = "button";
    closeButton.setAttribute("aria-label", "Close diagram preview");
    closeButton.textContent = "Close";

    title = document.createElement("div");
    title.className = "rv-lightbox-title";
    title.id = "rv-lightbox-title";
    overlay.setAttribute("aria-labelledby", title.id);

    image = document.createElement("img");
    image.className = "rv-lightbox-image";
    image.alt = "";

    frame.append(closeButton, title, image);
    overlay.append(frame);
    document.body.append(overlay);

    closeButton.addEventListener("click", closeOverlay);
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) {
        closeOverlay();
      }
    });
    document.addEventListener("keydown", (event) => {
      if (!overlay || overlay.hidden) {
        return;
      }
      if (event.key === "Escape") {
        closeOverlay();
        return;
      }
      if (event.key === "Tab") {
        trapFocus(event);
      }
    });
  }

  function openOverlay(link) {
    ensureOverlay();
    lastFocus = document.activeElement;
    const img = link.querySelector("img");
    image.src = img && img.currentSrc ? img.currentSrc : link.href;
    image.alt = img ? img.alt : "";
    title.textContent = link.dataset.rvTitle || (img ? img.alt : "Diagram preview");
    overlay.hidden = false;
    document.documentElement.classList.add("rv-lightbox-open");
    setBackgroundInert(true);
    closeButton.focus();
  }

  function closeOverlay() {
    if (!overlay || overlay.hidden) {
      return;
    }
    overlay.hidden = true;
    image.removeAttribute("src");
    document.documentElement.classList.remove("rv-lightbox-open");
    setBackgroundInert(false);
    if (lastFocus && typeof lastFocus.focus === "function") {
      lastFocus.focus();
    }
  }

  function setBackgroundInert(isInert) {
    if (isInert) {
      inertElements = Array.from(document.body.children).filter((element) => element !== overlay);
      inertElements.forEach((element) => {
        element.inert = true;
      });
      return;
    }

    inertElements.forEach((element) => {
      element.inert = false;
    });
    inertElements = [];
  }

  function trapFocus(event) {
    const focusable = Array.from(overlay.querySelectorAll(focusableSelector)).filter(
      (element) => element.offsetParent !== null,
    );
    if (focusable.length === 0) {
      event.preventDefault();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  document.addEventListener("click", (event) => {
    const link = event.target.closest("a.rv-lightbox");
    if (!link) {
      return;
    }
    event.preventDefault();
    openOverlay(link);
  });
})();
